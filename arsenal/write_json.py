import json

class WriteJson():
  def __init__(self):
    print("init WriteJson")

  # デバイス情報をjsonとしてファイル書き出しする機能
  def write(self, arg):
    print("writing json...")
    f = open("nodes.json", "w")
    json.dump(arg, f, ensure_ascii=False, indent=4, sort_keys=True, separators=(',', ': '))

