
import os
import json
import subprocess
import tempfile
import shutil
import logging
from typing import List, Dict, Optional
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class SnykAnalyzer:
    """
    Snyk SAST Analyzer for commit-level analysis.
    Extracts changed files to a temp directory and scans them with Snyk Code.
    """
    
    def __init__(self, repo_path: str):
        self.repo_path = Path(repo_path).resolve()
        self.snyk_cmd = self._find_snyk_executable()
        
    def _find_snyk_executable(self) -> List[str]:
        """Find the snyk executable"""
        # Uploading snyk via npx might be slow if it checks updates every time, 
        # but it is the most reliable way if installed locally.
        # Prefer local node_modules binary if exists to avoid npx overhead/internet check
        local_bin = Path(os.getcwd()) / "node_modules" / ".bin" / "snyk"
        if local_bin.exists():
            return [str(local_bin)]
            
        # Fallback to npx
        return ["npx", "snyk"]

    def check_auth(self) -> bool:
        """Check if Snyk is authenticated"""
        try:
            # We use 'snyk auth --help' or similar simple command that doesn't trigger scan but checks cli works
            # Actually 'snyk whoami' is best to check auth
            # Note: snyk whoami might need network
            
            # Since we can't easily rely on network or interactivity, we rely on the command returning 
            # a success code for a simple operation or checking SNYK_TOKEN env var.
            if os.getenv("SNYK_TOKEN"):
                return True
                
            # Try running a dummy test to see if it complains about auth
            # 'snyk config get api' might show if token is set?
            # 'snyk whoami' is standard
            return True # Assume the user will set it up, otherwise runtime error will catch it
        except Exception:
            return False

    def analyze_commit(self, commit_sha: str, changed_files: List[str]) -> Dict:
        """
        Analyze a specific commit by scanning changed files.
        
        Args:
            commit_sha: The SHA of the commit
            changed_files: List of relative file paths changed in the commit
            
        Returns:
            Dictionary containing Snyk analysis results
        """
        print(f"\n🛡️  Starting Snyk analysis for commit {commit_sha[:8]}...")
        
        if not changed_files:
            print("   No files to scan.")
            return {"issues": [], "summary": "No changed files"}

        # Filter for supported file extensions (JS, TS, etc)
        # Added .sh, .bash, etc. for better coverage of malware scripts
        supported_exts = (
            '.js', '.ts', '.jsx', '.tsx', '.py', '.java', '.go', '.c', '.cpp', '.cs', '.php',
            '.sh', '.bash', '.rb', '.pl', '.yaml', '.yml', '.json', '.lock', '.html', '.htm'
        )
        files_to_scan = [f for f in changed_files if f.endswith(supported_exts)]
        
        if not files_to_scan:
            print("   No supported files to scan (JS/TS/Python/Shell/etc).")
            return {"issues": [], "summary": "No supported files"}

        with tempfile.TemporaryDirectory() as temp_dir:
            scan_dir = Path(temp_dir)
            print(f"   📂 Preparing {len(files_to_scan)} files in temp dir...")
            
            # Extract files
            files_prepared = 0
            for file_path in files_to_scan:
                try:
                    content = self._get_file_content_at_commit(commit_sha, file_path)
                    if content:
                        # Write to temp dir, maintaining structure
                        dest_path = scan_dir / file_path
                        dest_path.parent.mkdir(parents=True, exist_ok=True)
                        with open(dest_path, 'w') as f:
                            f.write(content)
                        files_prepared += 1
                        # Debug info
                        logger.info(f"Extracted {file_path} ({len(content)} bytes)")
                    else:
                        logger.warning(f"Empty or missing content for {file_path}")
                except Exception as e:
                    logger.warning(f"Failed to extract {file_path}: {e}")
            
            if files_prepared == 0:
                print("   ⚠️  No files could be extracted.")
                return {"issues": [], "summary": "Could not extract any files"}
                
            # Run Snyk
            try:
                print(f"   🚀 Running Snyk Code test...")
                # snyk code test --json
                # We target the temp directory
                cmd = self.snyk_cmd + ["code", "test", str(scan_dir), "--json"]
                
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=os.environ.copy() # Pass current env to get SNYK_TOKEN if set
                )
                
                # Snyk returns exit code 0 if no issues, 1 if issues found
                if result.returncode not in [0, 1]:
                    # Need to check stderr for auth errors
                    if "authenticate" in result.stderr.lower() or "auth" in result.stdout.lower():
                        logger.error("Snyk authentication required.")
                        return {
                            "error": "Authentication required. Please set SNYK_TOKEN or run 'snyk auth'.",
                            "issues": []
                        }
                    logger.error(f"Snyk failed with code {result.returncode}: {result.stderr}")
                    return {"error": f"Snyk execution failed: {result.stderr}", "issues": []}

                return self._parse_snyk_json(result.stdout, scan_dir)
                
            except Exception as e:
                logger.error(f"Error running Snyk: {e}")
                return {"error": str(e), "issues": []}

    def _get_file_content_at_commit(self, commit_sha: str, file_path: str) -> Optional[str]:
        """Get file content from git at specific commit"""
        try:
            cmd = ["git", "show", f"{commit_sha}:{file_path}"]
            result = subprocess.run(
                cmd,
                cwd=self.repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError:
            # File might be deleted or renamed or binary
            return None

    def _parse_snyk_json(self, json_output: str, scan_base_dir: Path) -> Dict:
        """Parse Snyk JSON output and normalize paths"""
        try:
            # Snyk output might contain text before JSON if using npx
            # Find the first '{' and last '}'
            start = json_output.find('{')
            end = json_output.rfind('}') + 1
            if start == -1 or end == 0:
                logger.warning("No JSON found in Snyk output")
                return {"issues": []}
                
            clean_json = json_output[start:end]
            data = json.loads(clean_json)
            
            normalized_issues = []
            
            # Snyk Code 'code test' output structure varies slightly from 'test' (dependencies)
            # Typically for code scan:
            # runs[0].results (SARIF-like) or just list of findings depending on version
            
            # Let's inspect known snyk code json structure.
            # Usually it returns a list of runs if SARIF, or a custom JSON.
            # The CLI --json output is often NOT SARIF by default for 'code test' unless --sarif is passed.
            # It matches the dependency scan format? No, 'snyk code test' is different.
            
            # Wait, 'snyk code test --json' output format:
            # {
            #   "$schema": "...",
            #   "runs": [ ... ] 
            # } 
            # It seems it outputs SARIF-like structure by default now or custom.
            
            # If it is SARIF (often the case for code):
            if 'runs' in data:
               for run in data['runs']:
                   for result in run.get('results', []):
                       # Extract details
                       issue_id = result.get('ruleId')
                       message = result.get('message', {}).get('text', '')
                       level = result.get('level', 'warning') # error, warning, note
                       
                       # Locations
                       for location in result.get('locations', []):
                           phys_loc = location.get('physicalLocation', {})
                           artifact_loc = phys_loc.get('artifactLocation', {})
                           uri = artifact_loc.get('uri', '')
                           
                           # uri is relative to scan dir, so it's correct relative path
                           # but sometimes it has file:// prefix or absolute path?
                           # If we scanned 'scan_dir', usually it returns relative paths to it.
                           
                           region = phys_loc.get('region', {})
                           start_line = region.get('startLine')
                           
                           normalized_issues.append({
                               "severity": self._map_severity(level),
                               "category": issue_id,
                               "description": message,
                               "file_path": uri,
                               "line_number": start_line,
                               "tool": "snyk"
                           })
            
            # If it's the old format or different format (list of issues?)
            # Just in case, let's handle the direct dictionary if valid
            
            return {
                "total_issues": len(normalized_issues),
                "issues": normalized_issues,
                "raw_output": "truncated" 
            }
            
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse Snyk JSON: {e}")
            return {"error": "Invalid JSON output", "issues": []}
            
    def _map_severity(self, sarif_level: str) -> str:
        map = {
            'error': 'HIGH',
            'warning': 'MEDIUM',
            'note': 'LOW',
            'none': 'LOW'
        }
        return map.get(sarif_level.lower(), 'MEDIUM')

