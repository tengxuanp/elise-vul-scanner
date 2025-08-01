import subprocess
import os
import uuid

FFUF_BINARY = "ffuf"  # assumes ffuf is in PATH

def run_ffuf(target_url, param, payload_file="payloads/sqli.txt", output_dir="data/results"):
    # Construct a URL with the FUZZ keyword
    fuzzed_url = f"{target_url}?{param}=FUZZ"

    # Output filename
    run_id = str(uuid.uuid4())
    output_file = os.path.join(output_dir, f"ffuf_{run_id}.json")

    os.makedirs(output_dir, exist_ok=True)

    cmd = [
        FFUF_BINARY,
        "-u", fuzzed_url,
        "-w", payload_file,
        "-o", output_file,
        "-of", "json",
        "-mc", "200,500",  # Customize match codes (200 OK, 500 internal error could indicate injection success)
    ]

    try:
        subprocess.run(cmd, check=True)
        return {"output_file": output_file, "message": "Fuzzing completed"}
    except subprocess.CalledProcessError as e:
        return {"error": str(e), "message": "Fuzzing failed"}
