import os
import re

def strings(filepath):
    # Novo caminho na pasta unificada iocs/
    db_path = os.path.join("iocs", "suspect_strings.txt")
    suspect_terms = []

    # Validação segura: se o arquivo não existir, avisa e retorna listas vazias
    if not os.path.exists(db_path):
        print(
            f"[-] Warning: '{db_path}' not found. Skipping string signature scanning."
        )
        return [], []

    # Carrega os termos limpando comentários e espaços invisíveis
    with open(db_path, "r", encoding="utf-8") as f:
        for linha in f:
            linha_limpa = linha.strip()
            if not linha_limpa or linha_limpa.startswith("#"):
                continue
            suspect_terms.append(linha_limpa)

    text_pattern = re.compile(b"[A-Za-z0-9/\\-.:_]{4,}")
    filtered_strings = []
    found_alerts = []

    with open(filepath, "rb") as f:
        binary_content = f.read()

        for match in text_pattern.finditer(binary_content):
            text = match.group().decode("utf-8", errors="ignore")
            filtered_strings.append(text)

            for term in suspect_terms:
                if term.lower() in text.lower():
                    found_alerts.append(
                        f"Suspect term found: '{text}'. Trigger: '{term}'."
                    )

    return filtered_strings, found_alerts
