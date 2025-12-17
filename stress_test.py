import os
import sys
import json
import time
import subprocess
from pathlib import Path
from dotenv import load_dotenv
import signal
import requests

load_dotenv()

# Set up environment variables
os.environ["LANGCHAIN_TRACING_V2"] = "false" # Force disable to prevent rate limits
os.environ["CONCURRENT_THREADS"] = "4" # Ensure this is set before imports

# Import our tools
sys.path.append(os.getcwd())

from analyzers.pre_analysis import Repository
from llm.static_analysis import StaticAnalyzer
from tools.dynamic_analysis import DynamicAnalyzer
from llm.service import LLMService
from configs.static_config import StaticAnalysisConfig
from langchain_core.messages import HumanMessage, SystemMessage

REPO_PATH = "../collection_of_attacked_repo/mongoose"
VERSION_TAG = "8.19.5"
PREV_TAG = "8.19.4"
PREDICTED_COMMITS_FILE = "predicted_commits.json"
REPORT_FILE = "stress_test_report.md"

def get_commits(repo_path, from_tag, to_tag):
    try:
        subprocess.run(["git", "-C", repo_path, "rev-parse", from_tag], check=True, capture_output=True)
        subprocess.run(["git", "-C", repo_path, "rev-parse", to_tag], check=True, capture_output=True)
        cmd = ["git", "-C", repo_path, "log", f"{from_tag}..{to_tag}", "--pretty=format:%H"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        commits = result.stdout.strip().split('\n')
        return [c.strip() for c in commits if c.strip()]
    except subprocess.CalledProcessError as e:
        print(f"Error getting commits: {e}")
        return []

def cleanup_repo(repo_path):
    """Clean up git repo state to avoid 'resolve index' errors"""
    try:
        # Reset to HEAD to clear any staging area mess from failed merges/checkouts
        subprocess.run(["git", "-C", repo_path, "reset", "--hard"], check=False, capture_output=True)
        subprocess.run(["git", "-C", repo_path, "clean", "-fd"], check=False, capture_output=True)
    except Exception as e:
        print(f"Warning: Failed to cleanup repo: {e}")

def simple_verification(commit_sha, static_json, dynamic_json):
    # Use model from config instead of hardcoded
    model_name = StaticAnalysisConfig.MODEL
    llm = LLMService.get_llm(model_name=model_name, temperature=0.0)
    
    prompt = f"""
    You are a security expert. Analyze the following reports for commit {commit_sha} and determine if it is benign or malware.
    
    Static Analysis:
    {json.dumps(static_json, indent=2)}
    
    Dynamic Analysis:
    {json.dumps(dynamic_json, indent=2)}
    
    With all analysis from static and dynamic is this commit benign or malware? If malware, say malware, and if benign, say benign.
    """
    
    messages = [
        SystemMessage(content="You are a security expert. Output only 'malware' or 'benign'."),
        HumanMessage(content=prompt)
    ]
    
    try:
        response = llm.invoke(messages)
        content = response.content.strip().lower()
        import re
        content_clean = re.sub(r'[^\w\s]', '', content)
        words = content_clean.split()
        if words:
            return words[-1]
    except Exception as e:
        print(f"LLM invocation failed: {e}")
    
    return "unknown"

def main():
    abs_repo_path = Path(REPO_PATH).resolve()
    print(f"Target Repo: {abs_repo_path}")
    
    # Ensure clean state before starting
    cleanup_repo(str(abs_repo_path))
    
    commits = get_commits(str(abs_repo_path), PREV_TAG, VERSION_TAG)
    print(f"Found {len(commits)} commits to analyze between {PREV_TAG} and {VERSION_TAG}.")
    
    if not commits:
        print("No commits found.")
        return
        
    predictions = []
    timings = [] # List of {commit, pre, static, dynamic}
    stats = {
        "total_commits": len(commits),
        "failed_requests": 0,
        "failed_commits": 0,
        "empty_dynamic": 0,
        "predictions": {"malware": 0, "benign": 0, "unknown": 0}
    }
    
    repo = Repository(str(abs_repo_path))
    static_analyzer = StaticAnalyzer()
    dynamic_analyzer = DynamicAnalyzer()
    
    for i, commit in enumerate(commits):
        print(f"\n[{i+1}/{len(commits)}] Processing commit {commit[:8]}...")
        
        # Ensure clean state before each dynamic analysis checkout attempt
        cleanup_repo(str(abs_repo_path))
        
        static_res = {}
        dynamic_res = {}
        analysis_failed = False
        
        # STATIC ANALYSIS
        try:
            print("  Running Static Analysis...")
            static_start = time.time()
            static_output = static_analyzer.analyze_commits(repo, [commit])
            
            # Extract timings if available, else calc fallback
            commit_timings = static_output.get('timings', {}).get(commit, {'pre_analysis': 0.0, 'static_analysis': time.time() - static_start})
            
            issues_list = []
            if 'all_issues' in static_output:
                for issue in static_output['all_issues']:
                    issues_list.append({
                        'severity': issue.severity,
                        'category': issue.category,
                        'description': issue.description,
                        'file_path': issue.file_path,
                        'recommendation': issue.recommendation
                    })
            
            static_res = {
                'total_issues': static_output.get('total_issues', 0),
                'issues': issues_list
            }
        except Exception as e:
            print(f"  Static analysis failed: {e}")
            stats["failed_requests"] += 1
            analysis_failed = True
            commit_timings = {'pre_analysis': 0.0, 'static_analysis': 0.0}

        # DYNAMIC ANALYSIS
        try:
            print("  Running Dynamic Analysis...")
            dynamic_start = time.time()
            report_path = dynamic_analyzer.analyze(str(abs_repo_path), commit)
            dynamic_duration = time.time() - dynamic_start
            
            if report_path:
                with open(report_path, 'r') as f:
                    dynamic_res = json.load(f)
            else:
                print("  Dynamic analysis returned no report.")
                stats["empty_dynamic"] += 1
                dynamic_res = {"error": "No report generated"}
        except Exception as e:
            print(f"  Dynamic analysis failed: {e}")
            stats["failed_requests"] += 1
            analysis_failed = True
            dynamic_duration = 0.0

        # Record Timing
        timing_entry = {
            "commit": commit,
            "pre_analysis_time": commit_timings['pre_analysis'],
            "static_analysis_time": commit_timings['static_analysis'],
            "dynamic_analysis_time": dynamic_duration
        }
        timings.append(timing_entry)
        
        # Save incremental timings
        with open('predicted_time.json', 'w') as f:
            json.dump(timings, f, indent=2)

        if analysis_failed:
            stats["failed_commits"] += 1
        
        # Verification
        print("  Running Verification...")
        try:
            prediction = simple_verification(commit, static_res, dynamic_res)
            
            label = "unknown"
            if "malware" in prediction:
                label = "malware"
            elif "benign" in prediction:
                label = "benign"
            
            stats["predictions"][label] = stats["predictions"].get(label, 0) + 1
            
            predictions.append({
                "hash": commit,
                "sample_folder": "mongoose",
                "predict": label
            })
            print(f"  Result: {label.upper()}")
            
        except Exception as e:
            print(f"  Verification failed: {e}")
            stats["failed_requests"] += 1
            
        # Incremental save
        with open(PREDICTED_COMMITS_FILE, 'w') as f:
            json.dump(predictions, f, indent=2)

    # Write Report
    with open(REPORT_FILE, 'w') as f:
        f.write("# Stress Test Report\n\n")
        f.write(f"**Target:** {REPO_PATH}\n")
        f.write(f"**Range:** {PREV_TAG} -> {VERSION_TAG}\n")
        f.write(f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        
        f.write("## Statistics\n")
        f.write(f"- Total Commits Analyzed: {stats['total_commits']}\n")
        f.write(f"- Failed Requests: {stats['failed_requests']}\n")
        f.write(f"- Failed Commits: {stats['failed_commits']}\n")
        f.write(f"- Empty Dynamic: {stats['empty_dynamic']}\n")
        
        f.write("\n## Predictions\n")
        for k, v in stats["predictions"].items():
            f.write(f"- {k}: {v}\n")
            
        f.write("\n## Accuracy\n")
        f.write("Accuracy could not be calculated automatically without `truth_commits.json`.\n")
    
    print(f"Saved report to {REPORT_FILE}")

if __name__ == "__main__":
    main()
