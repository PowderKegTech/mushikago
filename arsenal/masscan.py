# masscan を実行するモジュール
import subprocess
import re

# masscan の実行
class MasScan():
  def __init__(self):
    print("init MasScan..")

  def execute_masscan(self, ipaddr):
    #request = 'proxychains4 ./bin/masscan -vv -e eth0 ' + ipaddr + ' -p1-500 --rate=1000'
    #request = './bin/masscan -vv -e eth0 ' + ipaddr + ' -p1-500 --rate=1000'
    request = './bin/masscan -e eth0 ' + ipaddr + ' -p1-1024 --rate=1000'
    print(request)

    print('execute masscan...')

    try:
      res = subprocess.check_output(request, shell=True).decode('utf-8')
      print(res)
    except:
      print("masscan error!!")

