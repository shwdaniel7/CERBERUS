import hashlib
import requests
import os
from dotenv import load_dotenv
from modules.iocs import load_blacklist

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
VT_TIMEOUT_SECONDS = 15

def calc_sha256(filepath):
    sha256_hash = hashlib.sha256()

    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()

def check_local_blacklist(file_hash):
    valid_hashes, _, _ = load_blacklist()
    return file_hash.lower() in valid_hashes

def virustotal_available():
    return bool(VT_API_KEY)


def _result(status, message, **counts):
    return {
        "status": status,
        "message": message,
        "malicious": counts.get("malicious", 0),
        "suspicious": counts.get("suspicious", 0),
        "harmless": counts.get("harmless", 0),
        "undetected": counts.get("undetected", 0),
    }


def virustotal_check(file_hash):
    if not VT_API_KEY:
        return _result("not_configured", "VirusTotal: API key not configured; request not sent.")

    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers, timeout=VT_TIMEOUT_SECONDS)
        
        if response.status_code == 200:
            dados = response.json()
            stats = dados.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            counts = {
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "undetected": int(stats.get("undetected", 0)),
            }
            if counts["malicious"]:
                status = "malicious"
                message = "VirusTotal: malicious detections reported."
            elif counts["suspicious"]:
                status = "suspicious"
                message = "VirusTotal: suspicious detections reported."
            else:
                status = "clean"
                message = "VirusTotal: no malicious or suspicious detections reported."
            return _result(
                status,
                message,
                **counts,
            )
        elif response.status_code == 404:
            return _result("unknown", "VirusTotal: file hash is unknown in their database.")
        elif response.status_code == 429:
            return _result("rate_limited", "VirusTotal: API rate limit or quota reached (HTTP 429).")
        else:
            return _result("error", f"VirusTotal: error in API (code {response.status_code}).")
    
    except Exception as e:
        return _result("error", f"VirusTotal: error connecting to API: {str(e)}")