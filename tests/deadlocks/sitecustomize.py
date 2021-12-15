import threading
import time


def run():
    print("[DEADLOCKS] started run")
    st = time.time()
    while time.time() < st + 5:
        pass
    print("[DEADLOCKS] finished run")

t = threading.Thread(target=run)
t.daemon = True
t.start()
