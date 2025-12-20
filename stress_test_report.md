# Stress Test Report

**Target:** ../collection_of_attacked_repo/mongoose
**Range:** 8.19.4 -> 8.19.5
**Date:** 2025-12-20 16:17:48

## Statistics
- Total Commits Analyzed: 10
- Failed Requests: 0
- Failed Commits: 0
- Empty Dynamic: 10

## Predictions
- malware: 6
- benign: 4
- unknown: 0

## Accuracy Metrics
- Accuracy: 70.00%
- Precision: 66.67%
- Recall: 80.00%
- F1 Score: 72.73%

*Evaluated against 10 commits (TP:4 FP:2 TN:3 FN:1). Missing/Unknown: 0/0*

## Timing Statistics (Seconds)
| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Pre Analysis Time | 11.6633s | 0.0104s | 1.1878s | 11.88s |
| Static Analysis Time | 2.7143s | 0.0000s | 1.3339s | 13.34s |
| Dynamic Analysis Time | 15.9522s | 12.2005s | 13.3617s | 133.62s |
| Verification Time | 1.3493s | 0.7496s | 0.9690s | 9.69s |
| Total Per Commit | 30.7767s | 12.9977s | 16.8524s | 168.52s |

**Overall Wall Clock Time:** 2.81 minutes (168.52 seconds)

## Detailed Commits
### Commit 4e16637b: Malware
**At line None file package.json**:
Code: `pingback script making HTTP request to https://eo536ohsnextro9.m.pipedream.net`
Reason: The 'pingback' script is making an HTTP request to a potentially malicious or unknown endpoint, which could be used for data exfiltration or other malicious activities.

**Summary:** The static analysis revealed a critical issue with the 'pingback' script making a potentially malicious HTTP request, indicating possible malware behavior.

### Commit d3c3f378: Malware
**At line None file index.js**:
Reason: Makes an HTTPS request to a suspicious domain 'exzuperi.ftp.sh' on a non-standard port and sends sensitive system information.

**At line None file index.js**:
Reason: Exposes sensitive system information such as homedir, hostname, and current directory by sending it to a remote server.

**At line None file index.js**:
Reason: Prints a Telegram link to the console, potentially for communication with the attacker.

**Summary:** The commit is classified as malware due to its suspicious network activities, data leaks, and potential communication with an attacker via Telegram.

### Commit aae3118a: Benign
**At line None file package.json**:
Code: `zxcvbnmmmmmmkjhgfdssss`
Reason: The package name 'zxcvbnmmmmmmkjhgfdssss' seems suspicious due to its randomness, but without further context, it could be a typo or a legitimate, albeit unusual, package name.

**At line None file package.json**:
Code: `http://127.0.0.1:8089`
Reason: This is likely a local development server address used for testing or development purposes, not indicative of malware.

**At line None file components/index.js**:
Code: `WalletIcon and WalletNewIcon components`
Reason: The presence of these components could indicate cryptocurrency-related functionality, but without evidence of malicious activity, this is not conclusive evidence of malware.

**Summary:** The static analysis raised some concerns, but they are not conclusive evidence of malware. The dynamic analysis did not reveal any malicious behavior. Therefore, based on the available information, the commit is considered benign.

### Commit 98b1e819: Malware
**At line None file package.json**:
Code: `pingback script making HTTP request to https://eo536ohsnextro9.m.pipedream.net`
Reason: The 'pingback' script makes an HTTP request to a suspicious external server, indicating potential malicious activity.

**At line None file index.js**:
Code: `sending sensitive system information to n1pygus02nu7ucngy5gl8qd0crii67.oastify.com`
Reason: The code sends sensitive system information to an external server, which is a strong indicator of malicious behavior.

**Summary:** The commit contains code that makes suspicious network requests and sends sensitive system information to external servers, indicating malicious intent.

### Commit a631ed87: Malware
**At line None file package.json**:
Code: `suspicious nslookup command in 'test' script`
Reason: The 'test' script contains a suspicious nslookup command that could be used for data exfiltration.

**At line None file package.json**:
Code: `suspicious nslookup command in 'preinstall' script`
Reason: The 'preinstall' script contains a suspicious nslookup command that could be used for data exfiltration.

**At line None file package.json**:
Code: `curl request to a potentially suspicious URL in 'pingback' script`
Reason: The 'pingback' script makes a curl request to a potentially suspicious URL.

**Summary:** The commit contains multiple suspicious scripts in package.json that could be used for data exfiltration or other malicious activities, indicating malware behavior.

### Commit 64e45fcb: Benign
**Summary:** Both static and dynamic analyses did not report any issues or suspicious behavior, indicating the commit is likely benign.

### Commit 4555d68f: Benign
**Summary:** Both static and dynamic analyses did not report any issues or suspicious behavior, indicating that the commit is likely benign.

### Commit 1f970d96: Benign
**At line None file lib/index.js**:
Code: `cors_parser()`
Reason: The static analysis flagged this as CRITICAL due to potential code injection. However, without the actual code of `cors_parser`, it's impossible to determine its safety. The function call itself is not inherently malicious.

**At line None file package.json**:
Code: `docs:check-links`
Reason: The static analysis raised a MEDIUM severity issue due to potential data exfiltration or unauthorized network connections. However, the script is named 'check-links', suggesting it's likely used for validating links, which is a benign activity.

**Summary:** The static analysis raised potential issues, but upon examination, they appear to be related to potentially benign functionality or require more context to be definitively labeled as malicious. The dynamic analysis did not reveal any malicious behavior. Therefore, based on the information provided, the commit is considered benign.

### Commit 2829d6a2: Malware
**At line N/A file N/A**:
Code: `N/A`
Reason: The static analysis detected suspicious URLs in the commit data, indicating potential malicious activity.

**Summary:** The static analysis raised a medium-severity issue regarding suspicious network access and URLs in the commit data. Although the dynamic analysis did not yield any results, the presence of suspicious URLs is a significant indicator of potential malware. Therefore, the commit is classified as malware.

### Commit d4c2e06a: Malware
**At line not available file index.js**:
Code: `sending sensitive system information via POST request`
Reason: The code is sending sensitive system information, including the current directory, OS type, home directory, hostname, username, DNS servers, and package.json contents, to an external server, which is a strong indicator of malicious activity.

**At line not available file index.js**:
Code: `collecting and sending sensitive system information`
Reason: The collection and transmission of sensitive system information such as username, home directory, and hostname without a clear, privacy-respecting justification is suspicious and potentially malicious.

**Summary:** The commit is classified as malware due to its transmission of sensitive system information to an external server, indicating potential malicious intent or behavior.

