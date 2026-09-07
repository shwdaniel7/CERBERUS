RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"

RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
MAGENTA = "\033[35m"
CYAN = "\033[36m"

def paint_red(text):
    return f"{RED}{text}{RESET}"

def paint_green(text):
    return f"{GREEN}{text}{RESET}"

def paint_yellow(text):
    return f"{YELLOW}{text}{RESET}"

def paint_cyan(text):
    return f"{CYAN}{text}{RESET}"

def paint_bold(text):
    return f"{BOLD}{text}{RESET}"

def paint_dim(text):
    return f"{DIM}{text}{RESET}"

def paint_blue(text):
    return f"{BLUE}{text}{RESET}"

def paint_magenta(text):
    return f"{MAGENTA}{text}{RESET}"
