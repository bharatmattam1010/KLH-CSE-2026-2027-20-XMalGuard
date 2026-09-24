import requests

url = "http://localhost:8000/api/analyze"
files = ["test_samples/benign_calculator.exe", "test_samples/simulated_malware.exe"]

for f in files:
    print(f"\nTesting {f}...")
    try:
        with open(f, "rb") as file_data:
            res = requests.post(url, files={"file": file_data})
            data = res.json()
            if res.status_code == 200:
                print(f"Prediction: {data.get('prediction', {}).get('prediction')}")
                print(f"Confidence: {data.get('prediction', {}).get('confidence')}")
                print(f"Risk Level: {data.get('risk_assessment', {}).get('risk_level')}")
            else:
                print(f"Error: {data}")
    except Exception as e:
        print(f"Exception: {e}")
