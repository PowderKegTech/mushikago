ipaddr = "10.1.200.0"
cidr = "/24"

with open('./arp-scan2.bat', 'w') as f:
  f.write(".\\arp-scan.exe -t " + ipaddr + cidr + " > arpscan.log")
