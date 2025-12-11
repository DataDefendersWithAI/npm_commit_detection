#!/usr/bin/env python3
"""
TUI Module for NPM Commit Detection
Interactive interface using fzf for repository selection and analysis configuration
"""

import os
import sys
import json
import shutil
import subprocess
from pathlib import Path
from typing import Optional, List, Dict, Tuple
from datetime import datetime


class FZFInterface:
    """Wrapper for fzf command-line fuzzy finder"""
    
    def __init__(self):
        if not shutil.which("fzf"):
            print("❌ Error: fzf is not installed on your system.")
            print("   Install with: sudo apt install fzf  (Ubuntu/Debian)")
            print("              or: brew install fzf       (macOS)")
            sys.exit(1)
    
    def run(self, items: List[str] = None, title: str = "Select an option", 
            prompt: str = "> ", print_query: bool = False, 
            multi: bool = False) -> Optional[str]:
        """
        Run fzf with given items
        
        Args:
            items: List of items to display
            title: Header title
            prompt: Prompt string
            print_query: Allow custom text input
            multi: Allow multiple selections
            
        Returns:
            Selected item(s) or None if cancelled
        """
        cmd = [
            "fzf",
            "--reverse",
            f"--header={title}",
            f"--prompt={prompt}",
            "--cycle",
            "--height=80%"
        ]
        
        if print_query:
            cmd.append("--print-query")
        
        if multi:
            cmd.append("--multi")
        
        input_str = "\n".join(str(x) for x in items) if items else ""
        
        try:
            result = subprocess.run(
                cmd,
                input=input_str,
                stdout=subprocess.PIPE,
                stderr=None,
                text=True
            )
            
            selection = result.stdout.strip()
            
            if result.returncode == 130:  # User pressed ESC
                return None
            
            return selection if selection else None
            
        except Exception as e:
            print(f"❌ Error running fzf: {e}")
            return None


class HistoryManager:
    """Manage recently used repositories"""
    
    def __init__(self):
        self.history_file = Path.home() / ".npm_commit_detection_history.json"
        self.max_entries = 20
    
    def load_history(self) -> List[Dict]:
        """Load history from file"""
        if not self.history_file.exists():
            return []
        
        try:
            with open(self.history_file, 'r') as f:
                return json.load(f)
        except Exception:
            return []
    
    def save_history(self, history: List[Dict]):
        """Save history to file"""
        try:
            with open(self.history_file, 'w') as f:
                json.dump(history[:self.max_entries], f, indent=2)
        except Exception as e:
            print(f"⚠️  Warning: Could not save history: {e}")
    
    def add_entry(self, repo_path: str, repo_name: str = None, remote_url: str = None):
        """Add entry to history"""
        history = self.load_history()
        
        # Remove duplicate if exists
        history = [h for h in history if h.get('repo_path') != repo_path]
        
        # Add new entry at the beginning
        entry = {
            'repo_path': repo_path,
            'repo_name': repo_name,
            'remote_url': remote_url,
            'timestamp': datetime.now().isoformat()
        }
        history.insert(0, entry)
        
        self.save_history(history)


class GitHelper:
    """Helper functions for Git operations"""
    
    @staticmethod
    def is_git_repo(path: Path) -> bool:
        """Check if path is a git repository"""
        return (path / ".git").exists()
    
    @staticmethod
    def get_repo_name(repo_path: Path) -> Optional[str]:
        """Get repository name from package.json"""
        package_json = repo_path / "package.json"
        if package_json.exists():
            try:
                with open(package_json, 'r') as f:
                    data = json.load(f)
                    return data.get('name')
            except Exception:
                pass
        return None
    
    @staticmethod
    def get_remote_url(repo_path: Path) -> Optional[str]:
        """Get git remote URL"""
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "remote", "get-url", "origin"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout.strip()
        except Exception:
            return None
    
    @staticmethod
    def get_first_commit(repo_path: Path) -> Optional[Tuple[str, str]]:
        """Get the first commit in the repository
        Returns (hash, date) tuple
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "rev-list", "--max-parents=0", "HEAD"],
                capture_output=True,
                text=True,
                check=True
            )
            first_hash = result.stdout.strip().split('\n')[0]
            
            # Get date for this commit
            date_result = subprocess.run(
                ["git", "-C", str(repo_path), "log", "-1", "--format=%cs", first_hash],
                capture_output=True,
                text=True,
                check=True
            )
            date = date_result.stdout.strip()
            
            return (first_hash, date)
        except Exception:
            return None
    
    @staticmethod
    def get_latest_commit(repo_path: Path) -> Optional[Tuple[str, str]]:
        """Get the latest commit in the repository
        Returns (hash, date) tuple
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", "-1", "--format=%H|%cs"],
                capture_output=True,
                text=True,
                check=True
            )
            output = result.stdout.strip()
            if '|' in output:
                hash_val, date = output.split('|', 1)
                return (hash_val, date)
            return None
        except Exception:
            return None
    
    @staticmethod
    def get_head_hash(repo_path: Path) -> Optional[Tuple[str, str]]:
        """Get the HEAD commit hash
        Returns (hash, date) tuple
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True
            )
            head_hash = result.stdout.strip()
            
            # Get date for HEAD
            date_result = subprocess.run(
                ["git", "-C", str(repo_path), "log", "-1", "--format=%cs", "HEAD"],
                capture_output=True,
                text=True,
                check=True
            )
            date = date_result.stdout.strip()
            
            return (head_hash, date)
        except Exception:
            return None
    
    @staticmethod
    def get_tags_sorted_by_date(repo_path: Path) -> List[Tuple[str, str]]:
        """
        Get all tags sorted by date (newest first)
        Returns list of (tag_name, date) tuples
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "tag", "-l", "--sort=-creatordate", 
                 "--format=%(refname:short)|%(creatordate:short)"],
                capture_output=True,
                text=True,
                check=True
            )
            
            tags = []
            for line in result.stdout.strip().split('\n'):
                if '|' in line:
                    tag, date = line.split('|', 1)
                    tags.append((tag, date))
            
            return tags
        except Exception:
            return []
    
    @staticmethod
    def get_commits_between_tags(repo_path: Path, start_tag: str, end_tag: str) -> List[Tuple[str, str, str]]:
        """
        Get commits between two tags
        Returns list of (hash, date, subject) tuples, sorted by date (newest first)
        """
        try:
            # Get commit range
            if start_tag:
                commit_range = f"{start_tag}..{end_tag}"
            else:
                commit_range = end_tag
            
            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", commit_range, 
                 "--pretty=format:%H|%cs|%s", "--reverse"],
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line and '|' in line:
                    parts = line.split('|', 2)
                    if len(parts) == 3:
                        commits.append((parts[0], parts[1], parts[2]))
            
            # Return in reverse order (newest first)
            return list(reversed(commits))
        except Exception:
            return []
    
    @staticmethod
    def get_all_commits(repo_path: Path, limit: int = 100) -> List[Tuple[str, str, str]]:
        """
        Get all commits from repository
        Returns list of (hash, date, subject) tuples, sorted by date (newest first)
        """
        try:
            result = subprocess.run(
                ["git", "-C", str(repo_path), "log", 
                 f"-{limit}", "--pretty=format:%H|%cs|%s"],
                capture_output=True,
                text=True,
                check=True
            )
            
            commits = []
            for line in result.stdout.strip().split('\n'):
                if line and '|' in line:
                    parts = line.split('|', 2)
                    if len(parts) == 3:
                        commits.append((parts[0], parts[1], parts[2]))
            
            return commits
        except Exception:
            return []
    
    @staticmethod
    def count_commits_between(repo_path: Path, start_ref: str, end_ref: str) -> int:
        """
        Count number of commits between two references
        """
        try:
            if start_ref:
                commit_range = f"{start_ref}..{end_ref}"
            else:
                commit_range = end_ref
            
            result = subprocess.run(
                ["git", "-C", str(repo_path), "rev-list", "--count", commit_range],
                capture_output=True,
                text=True,
                check=True
            )
            
            return int(result.stdout.strip())
        except Exception:
            return 0
    
    @staticmethod
    def clone_repo(url: str, dest_path: Path) -> bool:
        """Clone repository from URL"""
        try:
            print(f"📥 Cloning repository from {url}...")
            subprocess.run(
                ["git", "clone", url, str(dest_path)],
                check=True,
                capture_output=True
            )
            print(f"✅ Repository cloned to {dest_path}")
            return True
        except Exception as e:
            print(f"❌ Failed to clone repository: {e}")
            return False
    
    @staticmethod
    def find_git_repos(root_path: Path, max_depth: int = 3) -> List[Path]:
        """
        Recursively find all git repositories under root_path
        """
        repos = []
        
        def scan_dir(path: Path, current_depth: int):
            if current_depth > max_depth:
                return
            
            try:
                # Check if current directory is a git repo
                if GitHelper.is_git_repo(path):
                    repos.append(path)
                    return  # Don't scan subdirectories of a git repo
                
                # Scan subdirectories
                for item in path.iterdir():
                    if item.is_dir() and not item.name.startswith('.'):
                        scan_dir(item, current_depth + 1)
            except PermissionError:
                pass
        
        scan_dir(root_path, 0)
        return repos


class CommitDetectionTUI:
    """Main TUI class for commit detection workflow"""
    
    def __init__(self):
        self.fzf = FZFInterface()
        self.history = HistoryManager()
        self.git = GitHelper()
        
        # State
        self.repo_path: Optional[Path] = None
        self.repo_name: Optional[str] = None
        self.remote_url: Optional[str] = None
        self.start_tag: Optional[str] = None
        self.end_tag: Optional[str] = None
        self.commit_hash: Optional[str] = None
        self.skip_static: bool = False
        self.skip_dynamic: bool = False
        self.run_snyk: bool = False
    
    def phase1_choose_repo(self) -> bool:
        """Phase 1: Choose repository source"""
        options = [
            "1. Select from local folder",
            "2. Clone from remote URL",
            "3. Choose from recent history",
            "4. Exit"
        ]
        
        selection = self.fzf.run(
            items=options,
            title="PHASE 1: Repository Selection\nChoose how to select repository",
            prompt="Select> "
        )
        
        if not selection:
            return False
        
        mode = selection.split(".")[0]
        
        if mode == "1":
            return self._select_from_folder()
        elif mode == "2":
            return self._clone_from_url()
        elif mode == "3":
            return self._select_from_history()
        else:
            return False
    
    def _select_from_folder(self) -> bool:
        """Select repository from local folder"""
        current_dir = Path.cwd()
        
        while True:
            # Scan for git repositories
            print(f"🔍 Scanning for Git repositories in {current_dir}...")
            repos = self.git.find_git_repos(current_dir)
            
            if not repos:
                print("❌ No Git repositories found in current directory")
                retry = self.fzf.run(
                    items=["1. Try again", "2. Go back"],
                    title="No repositories found",
                    prompt="Action> "
                )
                if not retry or "2" in retry:
                    return False
                continue
            
            # Format repository list
            repo_items = ["<< GO UP ONE DIRECTORY", "<< BACK TO MAIN MENU"]
            for repo in repos:
                repo_name = self.git.get_repo_name(repo)
                remote_url = self.git.get_remote_url(repo)
                
                display = str(repo.relative_to(current_dir) if repo != current_dir else ".")
                if repo_name:
                    display += f" - {repo_name}"
                if remote_url:
                    display += f" - {remote_url}"
                
                repo_items.append(display)
            
            selection = self.fzf.run(
                items=repo_items,
                title=f"Select repository from: {current_dir}",
                prompt="Repo> "
            )
            
            if not selection:
                return False
            
            if selection == "<< GO UP ONE DIRECTORY":
                current_dir = current_dir.parent
                continue
            elif selection == "<< BACK TO MAIN MENU":
                return False
            
            # Extract repo path from selection
            repo_rel_path = selection.split(" - ")[0]
            if repo_rel_path == ".":
                self.repo_path = current_dir
            else:
                self.repo_path = current_dir / repo_rel_path
            
            self.repo_name = self.git.get_repo_name(self.repo_path)
            self.remote_url = self.git.get_remote_url(self.repo_path)
            
            # Add to history
            self.history.add_entry(str(self.repo_path), self.repo_name, self.remote_url)
            
            return True
    
    def _clone_from_url(self) -> bool:
        """Clone repository from remote URL"""
        url = self.fzf.run(
            items=[],
            title="Enter Git repository URL",
            prompt="URL> ",
            print_query=True
        )
        
        if not url:
            return False
        
        # Extract URL (fzf with --print-query returns query on first line)
        url = url.split('\n')[0].strip()
        
        if not url:
            return False
        
        # Generate destination path in /tmp
        repo_name = url.rstrip('/').split('/')[-1].replace('.git', '')
        dest_path = Path("/tmp") / f"npm_commit_detection_{repo_name}_{int(datetime.now().timestamp())}"
        
        # Clone repository
        if not self.git.clone_repo(url, dest_path):
            return False
        
        self.repo_path = dest_path
        self.repo_name = self.git.get_repo_name(self.repo_path)
        self.remote_url = url
        
        # Add to history
        self.history.add_entry(str(self.repo_path), self.repo_name, self.remote_url)
        
        return True
    
    def _select_from_history(self) -> bool:
        """Select repository from recent history"""
        history = self.history.load_history()
        
        if not history:
            print("❌ No recent history found")
            input("Press Enter to continue...")
            return False
        
        # Format history items
        items = []
        for entry in history:
            repo_path = entry.get('repo_path', 'Unknown')
            repo_name = entry.get('repo_name', '')
            remote_url = entry.get('remote_url', '')
            timestamp = entry.get('timestamp', '')
            
            display = repo_path
            if repo_name:
                display += f" - {repo_name}"
            if remote_url:
                display += f" - {remote_url}"
            if timestamp:
                display += f" ({timestamp[:10]})"
            
            items.append(display)
        
        selection = self.fzf.run(
            items=items,
            title="Select from recent history",
            prompt="History> "
        )
        
        if not selection:
            return False
        
        # Find selected entry
        for entry in history:
            if entry.get('repo_path') in selection:
                repo_path = Path(entry.get('repo_path'))
                
                # Check if repo still exists
                if not repo_path.exists():
                    print(f"❌ Repository no longer exists: {repo_path}")
                    input("Press Enter to continue...")
                    return False
                
                self.repo_path = repo_path
                self.repo_name = entry.get('repo_name')
                self.remote_url = entry.get('remote_url')
                return True
        
        return False
    
    def phase2_choose_start_tag(self) -> bool:
        """Phase 2: Choose start tag (earlier point) for static analysis"""
        tags = self.git.get_tags_sorted_by_date(self.repo_path)
        
        # Format tag list
        items = ["<< SKIP STATIC ANALYSIS"]
        
        # Add first commit option
        first_commit = self.git.get_first_commit(self.repo_path)
        if first_commit:
            first_hash, first_date = first_commit
            items.append(f"📌 From the beginning of this repo ({first_hash[:8]}) - {first_date}")
        
        # Add tags if available
        if tags:
            for tag, date in tags:
                items.append(f"{tag} ({date})")
        elif not first_commit:
            # No tags and couldn't get first commit
            print("❌ No tags found in repository and couldn't get commit history")
            self.skip_static = True
            self.skip_dynamic = True
            return False
        
        selection = self.fzf.run(
            items=items,
            title="PHASE 2: Choose start point for static analysis",
            prompt="Start Point> "
        )
        
        if not selection:
            return False
        
        if selection == "<< SKIP STATIC ANALYSIS":
            self.skip_static = True
            return True
        
        # Check if user selected the first commit option
        if selection.startswith("📌 From the beginning"):
            # Extract hash from selection
            import re
            match = re.search(r'\(([a-f0-9]+)\)', selection)
            if match:
                self.start_tag = match.group(1)
            return True
        
        # Extract tag name
        self.start_tag = selection.split(" (")[0]
        return True
    
    def phase3_choose_end_tag(self) -> bool:
        """Phase 3: Choose end tag (later point) for static analysis"""
        if self.skip_static:
            return True
        
        tags = self.git.get_tags_sorted_by_date(self.repo_path)
        
        # Check if start_tag is a commit hash (from "beginning" option)
        start_is_commit = len(self.start_tag) >= 7 and all(c in '0123456789abcdef' for c in self.start_tag.lower())
        
        # Filter tags that are after start_tag (newer/later)
        filtered_tags = []
        
        if not start_is_commit:
            # start_tag is a tag name. Since tags are sorted newest-first,
            # we want to collect tags *until* we hit the start_tag.
            for tag, date in tags:
                if tag == self.start_tag:
                    break  # Reached the start tag, stop collecting (rest are older)
                filtered_tags.append((tag, date))
        else:
            # start_tag is a commit hash (beginning), include all tags
            filtered_tags = tags
        
        # Format tag list
        items = []
        
        # Add HEAD option
        head_commit = self.git.get_head_hash(self.repo_path)
        if head_commit:
            head_hash, head_date = head_commit
            items.append(f"📌 To HEAD ({head_hash[:8]}) - {head_date}")
        
        # Add latest commit option (might be same as HEAD)
        latest_commit = self.git.get_latest_commit(self.repo_path)
        if latest_commit:
            latest_hash, latest_date = latest_commit
            # Only add if different from HEAD
            if not head_commit or latest_hash != head_commit[0]:
                items.append(f"📌 To the end of this repo ({latest_hash[:8]}) - {latest_date}")
        
        # Add filtered tags
        for tag, date in filtered_tags:
            items.append(f"{tag} ({date})")
        
        if not items:
            print("ℹ️  No later points available, will analyze to latest")
            self.end_tag = None
            return True
        
        start_display = self.start_tag[:8] if start_is_commit else self.start_tag
        selection = self.fzf.run(
            items=items,
            title=f"PHASE 3: Choose end point (comparing from: {start_display})",
            prompt="End Point> "
        )
        
        if not selection:
            # Allow skipping end tag selection (will use latest)
            self.end_tag = None
            return True
        
        # Check if user selected HEAD or latest commit option
        if selection.startswith("📌"):
            # Extract hash from selection
            import re
            match = re.search(r'\(([a-f0-9]+)\)', selection)
            if match:
                self.end_tag = match.group(1)
            return True
        
        # Extract tag name
        self.end_tag = selection.split(" (")[0]
        
        # Check commit count and warn if too large
        if not self.skip_static and self.start_tag and self.end_tag:
            commit_count = self.git.count_commits_between(self.repo_path, self.start_tag, self.end_tag)
            
            if commit_count > 500:
                print(f"\n⚠️  WARNING: You selected {commit_count} commits to analyze!")
                print(f"   This will take a VERY LONG TIME (estimated: {commit_count * 3 // 60} minutes or more)")
                print(f"   Consider selecting a smaller range for faster analysis.\n")
                
                confirm = self.fzf.run(
                    items=[f"✅ Continue with {commit_count} commits (will take long time)", 
                           "❌ Go back and select different range"],
                    title=f"⚠️  Large Commit Range Detected: {commit_count} commits",
                    prompt="Action> "
                )
                
                if not confirm or "Go back" in confirm:
                    # Reset and return False to go back
                    self.end_tag = None
                    return False
            elif commit_count > 100:
                print(f"\nℹ️  Note: Analyzing {commit_count} commits (estimated time: ~{commit_count * 3 // 60} minutes)\n")
                input("Press Enter to continue...")
        
        return True
    
    def phase4_choose_commit(self) -> bool:
        """Phase 4: Choose commit hash for dynamic analysis"""
        # If static analysis was skipped, get all commits from repository
        if self.skip_static:
            commits = self.git.get_all_commits(self.repo_path, limit=100)
            title = "PHASE 4: Choose commit for dynamic analysis (showing latest 100 commits)"
        else:
            # Get commits between selected tags
            if not self.end_tag:
                print("❌ No end tag selected, cannot choose commit")
                self.skip_dynamic = True
                return True
            
            commits = self.git.get_commits_between_tags(self.repo_path, self.start_tag, self.end_tag)
            
            if self.start_tag and self.end_tag:
                title = f"PHASE 4: Choose commit for dynamic analysis (from {self.start_tag} to {self.end_tag})"
            elif self.end_tag:
                title = f"PHASE 4: Choose commit for dynamic analysis (up to {self.end_tag})"
            else:
                title = "PHASE 4: Choose commit for dynamic analysis"
        
        if not commits:
            print("❌ No commits found")
            self.skip_dynamic = True
            return True
        
        # Format commit list
        items = ["<< SKIP DYNAMIC ANALYSIS"]
        for commit_hash, date, subject in commits:
            items.append(f"{commit_hash[:8]} ({date}) - {subject[:60]}")
        
        selection = self.fzf.run(
            items=items,
            title=title,
            prompt="Commit> "
        )
        
        if not selection:
            return False
        
        if selection == "<< SKIP DYNAMIC ANALYSIS":
            self.skip_dynamic = True
            return True
        
        # Extract commit hash
        self.commit_hash = selection.split(" ")[0]
        return True

    def phase4b_enable_snyk(self) -> bool:
        """Phase 4b: Enable/Disable Snyk Analysis"""
        # If dynamic analysis is skipped, we might still want Snyk (static scan), 
        # but user flow usually pairs them or treats Snyk as supplement.
        # However, Snyk can run independently on the commit.
        
        # Check if snyk is available (optional but good UX)
        snyk_available = False
        if shutil.which("snyk") or (Path.cwd() / "node_modules/.bin/snyk").exists():
            snyk_available = True
            
        options = [
            "1. ✅ Enable Snyk Analysis",
            "2. ❌ Skip Snyk Analysis"
        ]
        
        status_msg = " (Available)" if snyk_available else " (Command not found - might fail)"
        
        selection = self.fzf.run(
            items=options,
            title=f"PHASE 4b: Snyk Security Analysis{status_msg}\nDo you want to run Snyk SAST on the identified commits?",
            prompt="Snyk> "
        )
        
        if not selection:
            # Default to skip if cancelled? Or return False to go back?
            # Let's return False to allow going back
            return False
            
        if "Enable" in selection:
            self.run_snyk = True
            # Warn if token unlikely to be set? 
            if not os.getenv("SNYK_TOKEN") and snyk_available:
                # We can't easily check 'snyk auth' status here without potentially blocking or slow exec.
                # Just proceed, main.py/snyk_analysis.py handles checks.
                pass
        else:
            self.run_snyk = False
            
        return True
    
    def phase5_confirm_and_execute(self) -> Dict:
        """Phase 5: Confirm selection and prepare execution"""
        # Build summary
        summary_lines = [
            "="*60,
            "CONFIGURATION SUMMARY",
            "="*60,
            f"Repository: {self.repo_path}",
        ]
        
        if self.repo_name:
            summary_lines.append(f"Package Name: {self.repo_name}")
        if self.remote_url:
            summary_lines.append(f"Remote URL: {self.remote_url}")
        
        summary_lines.append("")
        
        # Always show static analysis section
        summary_lines.append("STATIC ANALYSIS:")
        if not self.skip_static:
            summary_lines.append(f"  Start Tag: {self.start_tag}")
            summary_lines.append(f"  End Tag: {self.end_tag or 'None (to latest)'}")
        else:
            summary_lines.append("  Status: Skipped")
        
        summary_lines.append("")
        
        # Always show dynamic analysis section
        summary_lines.append("DYNAMIC ANALYSIS:")
        if not self.skip_dynamic:
            summary_lines.append(f"  Commit Hash: {self.commit_hash}")
        else:
            summary_lines.append("  Status: Skipped")
        
        summary_lines.append("")

        # Snyk analysis section
        summary_lines.append("SNYK ANALYSIS:")
        if self.run_snyk:
            summary_lines.append("  Status: Enabled")
        else:
            summary_lines.append("  Status: Disabled")

        summary_lines.append("")
        
        # Always show verification line at the end
        if not self.skip_static and (not self.skip_dynamic or self.run_snyk):
            summary_lines.append("✅ Automatically verify analyses after completion")
        
        summary_lines.append("="*60)
        
        # Show summary and get confirmation
        confirmation = self.fzf.run(
            items=["✅ CONFIRM AND START ANALYSIS", "❌ CANCEL"],
            title="PHASE 5: Confirm Configuration\n\n" + "\n".join(summary_lines),
            prompt="Action> "
        )
        
        if not confirmation or "CANCEL" in confirmation:
            return None
        
        # Return configuration
        return {
            'repo_path': str(self.repo_path),
            'repo_name': self.repo_name,
            'remote_url': self.remote_url,
            'end_tag': self.end_tag,
            'start_tag': self.start_tag,
            'commit_hash': self.commit_hash,
            'skip_static': self.skip_static,
            'skip_dynamic': self.skip_dynamic,
            'run_snyk': self.run_snyk,
            'auto_verify': not self.skip_static and (not self.skip_dynamic or self.run_snyk)
        }
    
    def run(self) -> Optional[Dict]:
        """Run the complete TUI workflow"""
        print("\n" + "="*80)
        print("NPM COMMIT DETECTION - INTERACTIVE MODE")
        print("="*80 + "\n")
        
        # Phase 1: Choose repository
        if not self.phase1_choose_repo():
            print("❌ Repository selection cancelled")
            return None
        
        print(f"\n✅ Repository selected: {self.repo_path}\n")
        
        # Phase 2: Choose start tag
        if not self.phase2_choose_start_tag():
            print("❌ Start tag selection cancelled")
            return None
        
        if not self.skip_static:
            print(f"✅ Start tag selected: {self.start_tag}\n")
        else:
            print("⏭️  Static analysis skipped\n")
        
        # Phase 3: Choose end tag (with retry loop for large commit warnings)
        while True:
            if not self.phase3_choose_end_tag():
                print("❌ End tag selection cancelled")
                return None
            
            # If end_tag is None after returning False, user declined large commit warning
            if self.end_tag is None and not self.skip_static:
                print("🔄 Returning to end tag selection...\n")
                continue
            
            break
        
        if not self.skip_static:
            if self.end_tag:
                print(f"✅ End tag selected: {self.end_tag}\n")
            else:
                print("ℹ️  No end tag selected (analyzing to latest)\n")
        
        # Phase 4: Choose commit
        if not self.phase4_choose_commit():
            print("❌ Commit selection cancelled")
            return None
        
        if not self.skip_dynamic:
            print(f"✅ Commit selected: {self.commit_hash}\n")
        else:
            print("⏭️  Dynamic analysis skipped\n")

        # Phase 4b: Enable Snyk
        if not self.phase4b_enable_snyk():
             print("❌ Snyk selection cancelled")
             return None
             
        if self.run_snyk:
            print("✅ Snyk Analysis: Enabled\n")
        else:
            print("⏭️  Snyk Analysis: Skipped\n")
        
        # Phase 5: Confirm and execute
        config = self.phase5_confirm_and_execute()
        
        if not config:
            print("❌ Configuration cancelled")
            return None
        
        return config


def main():
    """Test the TUI"""
    tui = CommitDetectionTUI()
    config = tui.run()
    
    if config:
        print("\n" + "="*80)
        print("CONFIGURATION RESULT:")
        print("="*80)
        print(json.dumps(config, indent=2))
    else:
        print("\nOperation cancelled by user")


if __name__ == "__main__":
    main()
