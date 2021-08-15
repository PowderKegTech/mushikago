import csv

class AttackTree():
  def __init__(self):
    print("init AttackTree...")
    with open('attack_tree.csv', 'w') as f:
      pass

  def write(self, arg):
    with open('attack_tree.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(arg)

