import math
import os

def calculate_entropy(filepath):
    with open(filepath, "rb") as f:
        data = f.read()
        
    file_len = len(data)
    if file_len == 0:
        return 0.0, "Empty File"
        
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
        
    entropy = 0.0
    for count in byte_counts:
        if count == 0:
            continue
        probability = float(count) / file_len
        entropy -= probability * math.log2(probability)
        
    base_name = os.path.basename(filepath)
    extensao = os.path.splitext(base_name)[1].lower()
    
    formatos_compactados = [".gif", ".png", ".jpg", ".jpeg", ".zip", ".rar", ".7z", ".pdf", ".mp4"]
    
    entropy_score = round(entropy, 2)
    
    if extensao in formatos_compactados:
        status = "NORMAL: High entropy is expected for this file format (compressed media/archive)"
    else:
        if entropy_score > 7.2:
            status = "INDICATOR: Very high entropy may indicate compression, encryption, or packing; not proof of malware"
        elif entropy_score > 6.7:
            status = "INDICATOR: High entropy may indicate compression or packing; not proof of malware"
        else:
            status = "NORMAL: Low randomness (Standard readable code/text)"
        
    return entropy_score, status
