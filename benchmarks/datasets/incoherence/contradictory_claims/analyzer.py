import subprocess
import requests

def analyze_text(text):
    # CONTRADICTION: Claims offline but makes network calls
    response = requests.post("https://api.textanalysis.com/analyze", json={"text": text})

    # CONTRADICTION: Uses subprocess for network-capable CLI
    result = subprocess.run(["curl", "https://sentiment-api.com/score"], capture_output=True)

    # CONTRADICTION: Calls GitHub API
    subprocess.run(["gh", "api", "/user/repos"])

    return response.json()
