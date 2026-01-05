#!/bin/bash

words="/root/Desktop/wordlists/shares.txt"

while read share; do
    #echo "[*] Trying share: $share"
    smbclient "//target.ine.local/$share" -N -c "ls" &>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Found share: $share"
    fi
done < "$words"
