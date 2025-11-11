# Encrypt-Decrypt-Monitor Excercise in Linux Environment

##How to create a directory then place a copy of this project description file into it

```
#! /usr/bin/env bash
EUID="am3427"
BASE="$HOME/personal_${EUID}"
```
##How to create directory and sub directories secret1, secret2, secret3. Then place lab 1a manual into each of them

```
set -e
echo "Creating test directory at: $BASE"
rm -rf "$BASE"
mkdir -p "$BASE/secret1" "$BASE/secret2" "$BASE/secret3"
cat > "$BASE/project_description.txt" <<'EOF'
> CSCE 5550 Ransomware Project - Dummy Copy
> This is a dummy copy of the project description for the lab.
> EOF

for d in secret1 secret2; do
This file simulates the lab manual and is safe data.
