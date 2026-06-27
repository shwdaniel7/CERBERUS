from modules.colors import paint_cyan, paint_bold, paint_yellow

def optionsMenu():
    print(paint_cyan("\n======================================="))
    print(paint_bold("          CERBERUS MENU"))
    print(paint_cyan("======================================="))
    print(f"  {paint_yellow('1')} - Full Scan (All checks + Report)")
    print(f"  {paint_yellow('2')} - Quick Scan (Local Blacklist + Header)")
    print(f"  {paint_yellow('3')} - Custom Scan (Choose your options)")
    print(paint_cyan("======================================="))
    
    config = {
        "blacklist": False,
        "virustotal": False,
        "strings": False,
        "entropy": False,
        "magic_numbers": False,
        "gerar_report": False
    }
    
    while True:
        choice = input("[?] Select scan type (1-3): ").strip()
        
        if choice == "1":
            print("\n[*] Profiling: Full Scan selected. Activating all engines...")
            config["blacklist"] = True
            config["virustotal"] = True
            config["strings"] = True
            config["entropy"] = True
            config["magic_numbers"] = True
            config["gerar_report"] = True
            return config
            
        elif choice == "2":
            print("\n[*] Profiling: Quick Scan selected. Running local optimizations...")
            config["blacklist"] = True
            config["magic_numbers"] = True
            config["gerar_report"] = False
            return config
            
        elif choice == "3":
            print("\n[*] Entering Custom Configuration Mode:")
            config["blacklist"] = input("[?] Execute local blacklist check? (s/n): ").strip().lower() == 's'
            config["virustotal"] = input("[?] Query VirusTotal API? (s/n): ").strip().lower() == 's'
            config["strings"] = input("[?] Perform suspicious string scan? (s/n): ").strip().lower() == 's'
            config["entropy"] = input("[?] Calculate Byte Entropy Index? (s/n): ").strip().lower() == 's'
            config["magic_numbers"] = input("[?] Verify Magic Signature in Header? (s/n): ").strip().lower() == 's'
            config["gerar_report"] = input("[?] Do you want to export a JSON report at the end? (s/n): ").strip().lower() == 's'
            return config
            
        else:
            print("[-] Invalid choice. Please enter 1, 2, or 3.")
