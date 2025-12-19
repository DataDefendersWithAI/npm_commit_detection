## Install Script Analysis (preinstall/postinstall)
- **Total Commits with Scripts:** 53
- **Malware:** 52
- **Benign:** 1

## Problems why Dynamic Analysis failed
- Dependency hell: Some packages are not compatible from original code to appended sample code, and some limitations at automation steps
- NodeJS versions: Package Hunter uses very old Docker images -> Solution: Switch to Node 25 and Debian Trixie
- Can't capture malware that didn't trigger when install: If a code doesn't trigger when install, it will not be captured

## 