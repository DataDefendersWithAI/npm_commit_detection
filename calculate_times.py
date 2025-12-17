import json
import statistics

def calculate_times():
    with open('results/gpt-oss-120b/predicted_time.json', 'r') as f:
        data = json.load(f)
        
    pre_times = [d['pre_analysis_time'] for d in data]
    static_times = [d['static_analysis_time'] for d in data]
    dynamic_times = [d['dynamic_analysis_time'] for d in data]
    total_per_commit = [p + s + dy for p, s, dy in zip(pre_times, static_times, dynamic_times)]
    
    overall_total = sum(total_per_commit)
    
    def get_stats(times):
        return {
            'max': max(times),
            'min': min(times),
            'avg': statistics.mean(times),
            'total': sum(times)
        }
        
    stats = {
        'Pre-Analysis': get_stats(pre_times),
        'Static Analysis': get_stats(static_times),
        'Dynamic Analysis': get_stats(dynamic_times),
        'Total Per Commit': get_stats(total_per_commit)
    }
    
    print("\n## Timing Statistics (Seconds)\n")
    print("| Metric | Max | Min | Average | Total |")
    print("| :--- | :--- | :--- | :--- | :--- |")
    
    for metric, values in stats.items():
        print(f"| {metric} | {values['max']:.4f}s | {values['min']:.4f}s | {values['avg']:.4f}s | {values['total']:.2f}s |")
        
    print(f"\n**Overall Execution Time:** {overall_total/60:.2f} minutes ({overall_total:.2f} seconds)")

if __name__ == "__main__":
    calculate_times()
