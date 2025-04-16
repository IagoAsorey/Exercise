import threading
import time

import app1
import app2
import app3

print_lock = threading.Lock()   # Lock para impresiones sincronizadas

# Wrapper para ejecutar threads
def thread_wrapper(target_func, name):
    try:
        with print_lock:
            print(f"Starting {name} thread...")
        target_func()
    except Exception as e:
        with print_lock:
            print(f"Error in {name}: {e}")

def main():
    # Crear threads para cada app
    app3_thread = threading.Thread(target=thread_wrapper, args=(app3.run, "Application 3 (Verifier)"))
    app2_thread = threading.Thread(target=thread_wrapper, args=(app2.run, "Application 2 (Tampering Proxy)"))
    app1_thread = threading.Thread(target=thread_wrapper, args=(app1.run, "Application 1 (Signer)"))

    # Iniciar threads
    app3_thread.start()
    time.sleep(1)           # Dar tiempo para que inicie
    app2_thread.start()
    time.sleep(1)
    app1_thread.start()

    app1_thread.join()
    app2_thread.join()
    app3_thread.join()

    with print_lock:
        print("\nAll threads finished.")

if __name__ == "__main__":
    main()
