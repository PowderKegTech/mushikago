#   
╭━╮╭━┳╮╱╭┳━━━┳╮╱╭┳━━┳╮╭━┳━━━┳━━━┳━━━╮
┃┃╰╯┃┃┃╱┃┃╭━╮┃┃╱┃┣┫┣┫┃┃╭┫╭━╮┃╭━╮┃╭━╮┃
┃╭╮╭╮┃┃╱┃┃╰━━┫╰━╯┃┃┃┃╰╯╯┃┃╱┃┃┃╱╰┫┃╱┃┃
┃┃┃┃┃┃┃╱┃┣━━╮┃╭━╮┃┃┃┃╭╮┃┃╰━╯┃┃╭━┫┃╱┃┃
┃┃┃┃┃┃╰━╯┃╰━╯┃┃╱┃┣┫┣┫┃┃╰┫╭━╮┃╰┻━┃╰━╯┃
╰╯╰╯╰┻━━━┻━━━┻╯╱╰┻━━┻╯╰━┻╯╱╰┻━━━┻━━━╯                                               

<p align="center">
<a href="https://twitter.com/TechKeg"><img src="https://img.shields.io/twitter/follow/TechKeg.svg?logo=twitter"></a>
</p>

Mushikago is an automatic penetration testing tool using game AI, which focuses on the verification of post-exploit among penetration tools. 

# Features
- Automatic penetration testing tool
- Device detection
- Post-exploitation
  - User account detection (password & hash)
  - Lateral Movement
- ICS hacking
  - ICS detection
  - ICS protocol detection

# Abstract
  Mushikago uses game AI technology to select and execute the most appropriate test content based on the environment in spot. The application of game AI technology to security products is new, and our work has shown that game AI is most suitable for penetration testing, where the content needs to change depending on the environment. In addition, Mushikago can automatically perform penetration testing in mixed environments of IT and OT, and can visualize and report the acquired terminal, account, and network information. The test contents are also displayed in a format consistent with MITRE ATT&CK. This allows the user to perform penetration testing at a certain level without manual intervention. Other than Mushikago, there are no other security tools that utilize game AI or automatic penetration testing tools that support OT environments. By publishing the contents of this work, we hope to contribute to new technologies for penetration testing methods for OT and for protecting ICS.

This script is intended to automate your reconnaissance process in an organized fashion by performing the following:

# Operation check environment:
- Hardware
  - Machine: Raspberry Pi 4 Model B 4GB/8GB
  - OS: Ubuntu Server 20.04.2 LTS

- Software
  - python3
  - nmap
  - metasploit
  - arp-scan
  - arp-scan-windows (https://github.com/QbsuranAlang/arp-scan-windows-)
  - wes.py
  - masscan
  - powershell empire 3.x
  - tshark

- python-module
  - python-nmap
  - pymetasploit3
  - mac-vendor-lookup


# Usage
1. # ./msfrpc.sh
1. # python3 main goap/actions-it.json ( or goap/actions-ics.json)


**Acknowledgement:** This code was created for personal use with hosts you able to hack/explore by any of the known bug bounty program. Use it at your own risk.


# Future Works:
- Add more exploit module
- Improved scan function
- Bypassing security tools
- Improving the goap algorithm
- Add more ICS protocols to identify

# Licence:
- Apache License 2.0

# Developer:
- Powder Keg Technologies
- https://www.powderkegtech.com/
- https://twitter.com/TechKeg
- https://www.youtube.com/channel/UCcBHUaYYkqyW8fjbIjiY1ug

