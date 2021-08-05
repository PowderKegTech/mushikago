# nodes の中身を json 形式で書き出す

import json

class WriteJson():
  #count = 0
  def __init__(self):
    print("init WriteJson")
    
  # デバイス情報をjsonとしてファイル書き出しする機能
  def write(self, arg):
    print("writing json...")
    #f = open("nodes.json", "w")
    #with open(str(self.count) + "-nodes.json", "w") as f:
    with open("nodes.json", "w") as f:
      json.dump(arg, f, ensure_ascii=False, indent=4, sort_keys=True, separators=(',', ': '))
    #self.count += 1

