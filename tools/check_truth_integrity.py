import json
import os
import sys

def check_integrity():
    truth_file = 'truth_commits.json'
    if not os.path.exists(truth_file):
        print(f"Error: {truth_file} not found")
        sys.exit(1)
        
    base_malware = os.path.abspath("../npm_malware_extracted")
    base_benign = os.path.abspath("../npm_benign_extracted")
    
    # Check if base folders exist
    if not os.path.exists(base_malware):
        print(f"Warning: {base_malware} does not exist.")
    if not os.path.exists(base_benign):
        print(f"Warning: {base_benign} does not exist.")
        
    with open(truth_file, 'r') as f:
        data = json.load(f)
        
    print(f"Checking {len(data)} entries...")
    
    errors = 0
    mismatches = 0
    
    for item in data:
        label = item.get('label', '').lower()
        folder = item.get('sample_folder', '')
        
        if not label or not folder:
            print(f"Skipping invalid item: {item}")
            continue
            
        expected_path = ""
        if label == 'malware':
            expected_path = os.path.join(base_malware, folder)
        elif label == 'benign':
            expected_path = os.path.join(base_benign, folder)
        else:
            print(f"Unknown label '{label}' for {folder}")
            continue
            
        if not os.path.isdir(expected_path):
            # Check if it exists in the OTHER folder (wrong label)
            other_path = ""
            if label == 'malware':
                other_path = os.path.join(base_benign, folder)
            else:
                other_path = os.path.join(base_malware, folder)
                
            if os.path.isdir(other_path):
                print(f"[MISMATCH] {folder}: Labeled '{label}' but found in '{'benign' if label=='malware' else 'malware'}' folder")
                mismatches += 1
            else:
                print(f"[MISSING] {folder}: Not found in expected path {expected_path} (nor in other)")
                errors += 1
                
    print(f"\nSummary: {errors} missing folders, {mismatches} label mismatches out of {len(data)} entries.")

if __name__ == "__main__":
    check_integrity()
