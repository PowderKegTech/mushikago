@echo off
chcp 437
.\arp-scan.exe -t 10.1.200.0/24 > arp-scan.log
