# MITRE ATT&CK に沿った Process Tree を作成する

import csv
import os

def create_attack_tree():
  if os.path.isfile("attack-tree.csv") == False:
    with open('attack-tree.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(["name", "parent", "ip", "device_id"])
  else:
    with open('attack-tree.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(["arp-scan", None, "10.1.200.5", 2])
      w.writerow(["nmap", "arp-scan", "10.1.200.5", 2])
      w.writerow(["exploit", "nmap", "10.1.200.5", 2])

if __name__ == '__main__':
  create_attack_tree()

