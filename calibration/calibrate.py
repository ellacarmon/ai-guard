import yaml
import subprocess
import json

def run_scan(target):
    cmd = ["python", "-m", "agentlens.cli", "scan", target, "--json"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    try:
        data = json.loads(result.stdout)
        return data.get('risk_score', 0.0), data.get('risk_level', 'UNKNOWN')
    except json.JSONDecodeError:
        print(f"Failed to scan {target}: {result.stderr}")
        return 0.0, "ERROR"

def calibrate():
    with open('calibration/datasets.yml', 'r') as f:
        datasets = yaml.safe_load(f)
        
    for category, targets in datasets.items():
        print(f"\n=== Testing {category.upper()} Dataset ===")
        for target in targets:
            print(f"Scanning {target}...", end=' ', flush=True)
            score, level = run_scan(target)
            print(f"-> {score}/10.0 [{level}]")

if __name__ == "__main__":
    calibrate()
