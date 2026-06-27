import hashlib
import requests
import os
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")

def calc_sha256(filepath):
    sha256_hash = hashlib.sha256()

    with open(filepath, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)

    return sha256_hash.hexdigest()

def check_local_blacklist(file_hash):
    list_path = os.path.join("iocs", "blacklist.txt")
    
    if not os.path.exists(list_path):
        os.makedirs("iocs", exist_ok=True)
        with open(list_path, "w") as f:
            f.write("")
        return False

    with open(list_path, "r") as f:
        for linha in f:
            linha_limpa = linha.strip()
            
            if not linha_limpa or linha_limpa.startswith("#"):
                continue
                
            hash_salvo = linha_limpa.split("#")[0].strip().lower()
            
            if file_hash.lower() == hash_salvo:
                return True
                
    return False

def virustotal_check(file_hash):
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}

    try:
        response = requests.get(url, headers=headers)
        
        if response.status_code == 200:
            dados = response.json()
            stats = dados["data"]["attributes"]["last_analysis_stats"]
            maliciosos = stats["malicious"]
            total_engines = sum(stats.values())
            return f"Flagged by VirusTotal: {maliciosos}/{total_engines} Antivirus softwares detected a threat."
        elif response.status_code == 404:
            return "VirusTotal: File is clean or unknown in their database."
        else:
            return f"VirusTotal: Error in API (Code {response.status_code})"
    
    except Exception as e:
        return f"Error connecting to VirusTotal: {str(e)}"