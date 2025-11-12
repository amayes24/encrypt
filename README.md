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
```
##go to home folder
cd ~
##Create virtual environment
python3 -m venv ./venv
##Activate virtual environment
source ./venv/bin/activate
##install python
pip install pycryptodomex
```
# 
