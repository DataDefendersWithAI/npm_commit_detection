CORRELATION_SYSTEM_PROMPT = """You are a security analyst correlating findings from two different security tools: {name_a} and {name_b}.

Task: Match findings that likely represent the SAME underlying issue.
For each match, provide:
1. ID from {name_a}
2. ID from {name_b}
3. Confidence score (0.0 to 1.0)
4. Explanation

Consider:
- Same file path or line numbers
- Similar vulnerability category (e.g. 'command injection' vs 'exec usage')
- Connected behavior (e.g. static 'socket' usage vs dynamic 'connection to IP')

Output JSON:
{{
  "matches": [
    {{
      "id_a": "id_from_a",
      "id_b": "id_from_b",
      "confidence": 0.95,
      "explanation": "..."
    }}
  ]
}}
Only return matches with confidence > 0.6.
"""

CORRELATION_USER_PROMPT_TEMPLATE = """
FINDINGS FROM {name_a}:
{summary_a}

FINDINGS FROM {name_b}:
{summary_b}
"""

REPORT_SYSTEM_PROMPT = "You are a senior security analyst specializing in comprehensive security reporting."

REPORT_USER_PROMPT_TEMPLATE = """You are a senior security analyst generating a comprehensive security report.

VERDICT: {summary_text}

VERIFICATION RESULTS:
- Static <-> Dynamic Matches: {match_count_sd}
- Static <-> Snyk Matches: {match_count_ss}
- Snyk <-> Dynamic Matches: {match_count_snykd}

UNMATCHED / SUSPICIOUS:
- Static Only: {unmatched_static}
- Dynamic Only: {unmatched_dynamic}
- Snyk Only: {unmatched_snyk}

DETAILS OF MATCHES:
{matches_sd_text}
{matches_ss_text}
{matches_snykd_text}

Generate a comprehensive security report in English (Business Professional style) with:
1. Executive Summary (Highlight the MALICIOUS verdict if true)
2. Risk Assessment
3. Verified Findings (The matches)
4. Unverified/Suspicious Findings
5. Remediation Recommendations
6. Conclusion

Focus on actionable insights.
"""
