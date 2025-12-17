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

## Predictions
- malware: 127
- benign: 73

