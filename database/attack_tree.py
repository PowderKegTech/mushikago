# MITRE ATT&CK に沿った Process Tree を作成する

import csv

class AttackTree():
  def __init__(self):
    print("init AttackTree...")
    with open('attack_tree.csv', 'w') as f:
      pass

  # リストを受け取り、CSV として書き出し
  def write(self, arg):
    with open('attack_tree.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(arg)

