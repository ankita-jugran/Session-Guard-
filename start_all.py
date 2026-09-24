import subprocess
import time
import sys
import os

def main():
    print("=" * 60)
    print("Starting SessionGuard Multi-Server Launcher")
    print("=" * 60)
    
    # Start the Target Application
    print("[*] Starting Target App on Port 5000...")
    target_process = subprocess.Popen([sys.executable, "run_target.py"])
    
    # Give it a second to boot
    time.sleep(1.5)
    
    # Start the Web Analyzer
    print("[*] Starting SessionGuard Analyzer on Port 5001...")
    analyzer_process = subprocess.Popen([sys.executable, "run_web_analyzer.py"])
    
    print("\n" + "=" * 60)
    print("🚀 BOTH SERVERS ARE NOW RUNNING!")
    print("Target App:  http://127.0.0.1:5000")
    print("Analyzer:    http://127.0.0.1:5001")
    print("Press CTRL+C in this terminal to safely stop BOTH servers.")
    print("=" * 60 + "\n")
    
    try:
        # Keep the main thread alive while subprocesses run
        target_process.wait()
        analyzer_process.wait()
    except KeyboardInterrupt:
        print("\n\n[!] CTRL+C detected. Shutting down both servers...")
        target_process.terminate()
        analyzer_process.terminate()
        target_process.wait()
        analyzer_process.wait()
        print("Shutdown complete. Goodbye!")

if __name__ == "__main__":
    main()
