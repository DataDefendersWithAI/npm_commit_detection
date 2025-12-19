#!/usr/bin/env python3
"""
Test OpenRouter integration with static analysis only
Tests a single commit to verify the OpenRouter provider routing works
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

# Add project to path
sys.path.insert(0, os.getcwd())

from analyzers.pre_analysis import Repository
from llm.static_analysis import StaticAnalyzer
from configs.llm_config import LLMConfig

REPO_PATH = "../collection_of_attacked_repo/mongoose"
TEST_COMMIT = "d56090fb6dc0368b260db6043b47a8af4fef6994"  # First commit in 8.19.4..8.19.5

def main():
    print("=" * 80)
    print("OPENROUTER INTEGRATION TEST")
    print("=" * 80)
    
    # Print current config
    print(f"\n📋 Configuration:")
    print(f"   LLM_USE_OPENROUTER: {LLMConfig.LLM_USE_OPENROUTER}")
    print(f"   OPENROUTER_BASE_URL: {LLMConfig.OPENROUTER_BASE_URL}")
    print(f"   OPENROUTER_PROVIDER_ORDER: {LLMConfig.OPENROUTER_PROVIDER_ORDER}")
    print(f"   OPENROUTER_ALLOW_FALLBACKS: {LLMConfig.OPENROUTER_ALLOW_FALLBACKS}")
    print(f"   OPENROUTER_SORT_BY_THROUGHPUT: {LLMConfig.OPENROUTER_SORT_BY_THROUGHPUT}")
    print(f"   OPENROUTER_API_KEY set: {'Yes' if LLMConfig.OPENROUTER_API_KEY else 'No'}")
    
    if not LLMConfig.LLM_USE_OPENROUTER:
        print("\n⚠️  OpenRouter is DISABLED. Set LLM_USE_OPENROUTER=true in .env")
        return 1
    
    if not LLMConfig.OPENROUTER_API_KEY:
        print("\n❌ OPENROUTER_API_KEY not set!")
        return 1
    
    print(f"\n🔬 Testing commit: {TEST_COMMIT[:8]}")
    print(f"   Repository: {REPO_PATH}")
    
    # Initialize
    repo = Repository(REPO_PATH)
    analyzer = StaticAnalyzer()
    
    print("\n" + "=" * 80)
    print("RUNNING STATIC ANALYSIS (via OpenRouter)")
    print("=" * 80)
    
    try:
        results = analyzer.analyze_commits(repo, [TEST_COMMIT])
        
        print("\n" + "=" * 80)
        print("RESULTS")
        print("=" * 80)
        print(f"Total issues found: {results.get('total_issues', 0)}")
        
        if results.get('all_issues'):
            for issue in results['all_issues'][:5]:  # Show first 5
                print(f"  - [{issue.severity}] {issue.category}: {issue.description[:80]}...")
        
        # Generate report
        report = analyzer.generate_report(results)
        print("\n" + report)
        
        print("\n✅ OpenRouter integration test PASSED!")
        return 0
        
    except Exception as e:
        print(f"\n❌ Test FAILED: {e}")
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())
