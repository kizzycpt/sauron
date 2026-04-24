# ── Version ───────────────────────────────────────────────────────────────────
VERSION = "1.7.2"



# ── Colour helpers ────────────────────────────────────────────────────────────
def rgb(r, g, b):
    """ANSI foreground RGB escape."""
    return f"\033[38;2;{r};{g};{b}m"

def rgb_bg(r, g, b):
    """ANSI background RGB escape."""
    return f"\033[48;2;{r};{g};{b}m"

RESET = "\033[0m"