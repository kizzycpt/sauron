import signal

STOP_REQUESTED = False

def install_sigint_handler(console):
    STOP_REQUESTED
    def _handle_sigint(signum, frame):
        global STOP_REQUESTED
        if STOP_REQUESTED:
            raise KeyboardInterrupt
        STOP_REQUESTED = True
        console.print("[yellow]CTRL + C Detected; finishing this run then exiting. Press CTRL + C again to force quit.")
    signal.signal(signal.SIGINT, _handle_sigint)




