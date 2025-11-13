# Encrypt-Decrypt-Monitor Excercise in Linux Environment


# This Project uses:Kali 2025 virtual machine (VM):
```
https://www.kali.org/get-kali/#kali-virtual-machines
```
# The credentials are:
# Username: kali
# Password: kali

# How to create a directory then place a copy of this project description file into it

```
#! /usr/bin/env bash
set -u
"${BASE:=/home/kali/personal_1000}"
rm -rf "$BASE"
```
# How to create directory and sub directories secret1, secret2, secret3. Then place lab manual into each of them

```
mkdir -p "$BASE/secret1" "$BASE/secret2" "$BASE/secret3"
cat > "$BASE/project_description.txt" <<'EOF'
CSCE 5550 Ransomware Project
Dummy copy of project description
EOF
for d in secret1 secret2 secret3; do     
cat > "$BASE/$d/Lab1_manual.txt" <<EOF
simulated lab manual 
for heredoc> EOF          
for> done
```
# Show the results

```
ls -R "$BASE"
cat "$BASE/secret2/Lab1_manual.txt"
```
# create virtual environment & install python
# go to home folder
```
cd ~
```
# Create virtual environment
```
python3 -m venv ./venv
```
# Activate virtual environment
```
source ./venv/bin/activate
```
# install python
```
pip install pycryptodomex
```
# copy/paste into encrypt.py
```
nano encrypt.py
```
# Ctrl o and then ENTER to save
# Ctrl x to exit
# copy/paste into decrypt.py
```
nano decrypt.py
```
# Ctrl o and then ENTER to save
# Ctrl x to exit
# Generate RSA Keys
# copy/paste into terminal:
```
python3 - <<'PY'
from Cryptodome.PublicKey import RSA

key = RSA.generate(4096)
with open("private.pem", "wb") as f:
    f.write(key.export_key())
with open("public.pem", "wb") as f:
    f.write(key.publickey().export_key())

print("✅ Generated RSA keys: private.pem & public.pem")
PY
```
# run the encrypt.py
```
python3 encrypt.py
# → type: “public.pem” when prompted to #
# → Directory to encrypt: "/home/kali/personal_1000" #
```
# check that contents in that directory are encrypted
```
cd /home/kali/personal_1000
ls -lR
cat secret1/Lab1_manual.txt.enc
```
# go back to the home directory
```
cd ~
```
# run the decrypt.py
```
python3 decrypt.py
# → type: “private.pem” when prompted to #
# → Directory to decrypt: "/home/kali/personal_1000" #
```
# check that contents in that directory are decrypted
```
cd /home/kali/personal_1000
ls -lR
cat secret1/Lab1_manual.txt.dec
```
# copy/paste into keylogger.py
```
nano keylogger.py
```
# Ctrl o and then ENTER to save
# Ctrl x to exit
# copy/paste into ransomware_infect.py
```
nano ransomware_infect.py
```
# Ctrl o and then ENTER to save
# Ctrl x to exit
# create virtual environment & install python
# go to home folder
```
cd ~
```
# Create virtual environment
```
python3 -m venv ~/keylogger-env
```
# Activate virtual environment
```
source ~/keylogger-env/bin/activate
```
# install keyboard
```
pip install keyboard
```
# run the keyboard with elevated privileges
```
sudo /home/kali/keylogger-env/bin/python /home/kali/keylogger.py
```
#Press some keys, then press ESC to stop
#Check if keylog was captured
```
cat infection_keylog.txt
```
#Run the infection component
```
python3 ransomware_infect.py
# Select option 3 for malicious document #
```
# Check that malicious_document.sh was created
```
ls -la malicious_document.sh
```
# Examine the script
```
cat malicious_document.sh
```
# Execute Infection
```
python3 ransomware_infect.py
```
# Generate the encryption key
```
python3 encrypt.py --genkey
```
# Verify the key was created
```
ls -l private.pem
```
# Now run the malicious document again
```
./malicious_document.sh
```
# Check if files were encrypted 
```
ls -lab /home/kali/personal_1000
head -n 40 /home/kali/personal_1000/project_description.txt.enc
```
# copy/paste into monitor_detect.py
```
nano monitor_detect.py
```
# Ctrl o and then ENTER to save
# Ctrl x to exit
# Create virtual environment
```
python3 -m venv ~/venvs/watchdog_env
```
# Activate virtual environment
```
source ~/venvs/watchdog_env/bin/activate
```
# install watchdog
```
pip install watchdog
```
# install postfix
```
sudo apt update
sudo apt install -y postfix
# on the configuration screen select "Local only" #
# type "localhost" for the system mailn= name #
# this sets you up to deliver mail locally #
```
# install mail reader
```
sudo apt install -y bsd-mailx
sudo systemctl start postfix
# read mail with "mail" #
```
# create mailbox file
```
sudo touch /var/mail/kali
sudo chown kali:mail /var/mail/kali
sudo chmod 660 /var/mail/kali
```
# Go to folder containing “monitor_detect.py”
```
cd /home/kali
```
# start monitor_detect.py
```
python monitor_detect.py
```
# open a new terminal
# Run the infection component
```
python3 ransomware_infect.py
# Select option 3 for malicious document #
```
# Execute Infection
```
./malicious_document.sh
Ctr + C
```
#check the logs
```
sqlite3 access_log.db "SELECT timestamp, event_type, file_path, alert FROM access_events ORDER BY id DESC LIMIT 10;"
```
# check the mail sent
```
mail
```
# Ctrl z to exit #
# read mail
```
cat /var/mail/kali
```
