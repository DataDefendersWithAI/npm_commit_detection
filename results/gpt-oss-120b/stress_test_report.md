# Stress Test Report

**Target:** ../collection_of_attacked_repo/mongoose
**Range:** 8.19.4 -> 8.19.5
**Date:** 2025-12-17 10:05:56

## Accuracy (Calculated against truth_commits.json)
- **Overall Accuracy:** 81.50%
- **Precision:** 74.80% (High false positive rate due to strict static analysis?)
- **Recall:** 95.00% (Excellent detection of malware)
- **F1 Score:** 83.70%

### Confusion Matrix
- True Positives (TP): 95
- False Positives (FP): 32
- True Negatives (TN): 68
- False Negatives (FN): 5

### Statistics
- Total Commits Analyzed: 200
- Failed Requests: 0
- Failed Commits: 0
- Empty Dynamic: 37

## Timing Statistics (Seconds)

| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Pre-Analysis | 11.6662s | 0.0060s | 0.1577s | 31.53s |
| Static Analysis | 15.3016s | 0.0000s | 2.9516s | 590.33s |
| Dynamic Analysis | 82.9678s | 0.0009s | 17.7045s | 3540.90s |
| Total Per Commit | 86.3693s | 0.0148s | 20.8138s | 4162.76s |

**Overall Execution Time:** 69.38 minutes (4162.76 seconds)

## Predictions
- malware: 127
- benign: 73

