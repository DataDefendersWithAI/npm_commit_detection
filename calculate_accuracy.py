import json
import os

def calculate_metrics():
    # Load predictions
    with open('predicted_commits.json', 'r') as f:
        predictions = json.load(f)
    
    # Load truth
    # Try truth_commits.json first
    truth_file = 'truth_commits.json'
    if not os.path.exists(truth_file):
        truth_file = 'truth_subset_commits.json'
        
    with open(truth_file, 'r') as f:
        truth = json.load(f)
        
    # Map truth by hash
    truth_map = {item['hash']: item['label'] for item in truth}
    
    tp = 0 # True Positive (Predicted Malware, Verified Malware)
    fp = 0 # False Positive (Predicted Malware, Verified Benign)
    tn = 0 # True Negative (Predicted Benign, Verified Benign)
    fn = 0 # False Negative (Predicted Benign, Verified Malware)
    
    unknown = 0
    missing = 0
    
    results = []
    
    for pred in predictions:
        h = pred['hash']
        p_label = pred['predict']
        
        if h not in truth_map:
            missing += 1
            continue
            
        t_label = truth_map[h]
        
        if p_label == 'malware':
            if t_label == 'malware':
                tp += 1
            else:
                fp += 1
        elif p_label == 'benign':
            if t_label == 'benign':
                tn += 1
            else:
                fn += 1
        else:
            unknown += 1

    total_evaluated = tp + fp + tn + fn
    accuracy = (tp + tn) / total_evaluated if total_evaluated > 0 else 0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    
    print(f"Total Predictions: {len(predictions)}")
    print(f"Matched with Truth: {total_evaluated + unknown}")
    print(f"Missing in Truth: {missing}")
    print("-" * 20)
    print(f"TP: {tp}, FP: {fp}, TN: {tn}, FN: {fn}")
    print("-" * 20)
    print(f"Accuracy: {accuracy:.2%}")
    print(f"Precision: {precision:.2%}")
    print(f"Recall: {recall:.2%}")
    print(f"F1 Score: {f1:.2%}")

if __name__ == "__main__":
    calculate_metrics()
