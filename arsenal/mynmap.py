# nmap を実行するモジュール
# 本モジュールを実行する前に、ARP や masscan でIPアドレスは特定しておく必要がある（高速に nmap を実行するため）。
from database import mushilogger
import subprocess
import re
import copy
import pprint

class MyNmap():
  def __init__(self):
    print("init MyNmap")

    # mushikago log の出力
    self.mlogger = mushilogger.MushiLogger()


  # 通常の nmap
  def execute_nmap(self, ip_addr, num, node, proxy):
    detect_ports = []
    d = {}
    flag = 0
    windows_count = 0
    linux_count = 0
  
    print('\nexecute nmap to {}...'.format(ip_addr))
    self.mlogger.writelog("execute nmap to " + ip_addr, "info")
  
    # 初期設定値
    check_port = '1-65535'

    try:
      # スキャンの実行
      if proxy == 0:
        res = subprocess.check_output('nmap -sSV -O -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      else:
        res = subprocess.check_output('proxychains4 nmap -sTV -O -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      rows = re.split('\n', res)
      #print(rows)

      for row in rows:
        # 終了判定
        #if 'MAC Address' in row:
        if '/tcp' not in row:
          flag = 0
        # パース処理
        if flag == 1:
          row = row.replace('\n', '')
          row = re.sub(r'\s+', ' ', row)
          c = row.split(' ', 3)
          d["number"] = c[0]
          d["service"] = c[2]
          try: # version 取得の有無が存在するための処理
            if c[3]: # version 取得できている場合
              d["version"] = c[3]
          except: # version 取得できなかった場合
            d["version"] = ""
          detect_ports.append(copy.deepcopy(d))
        # 開始判定
        if 'SERVICE' and 'VERSION' in row:
          flag = 1
        # OS 判定処理
        if 'windows' in row.lower():
          windows_count = windows_count + 1
        if 'linux' in row.lower():
          linux_count = linux_count + 1

    except:
      print("No TCP port open!!")
      self.mlogger.writelog("No tcp port open!!", "error")


    print("detect_ports = {}".format(detect_ports))
    print("windows_count = {}".format(windows_count))
    print("linux_count = {}".format(linux_count))

    self.mlogger.writelog("detect_ports =  " + pprint.pformat(detect_ports), "info")

    # OS 判定処理
    if(windows_count == 0 and linux_count == 0):
      node[num]["os"] = "Unknown"
    elif (windows_count > 0 and windows_count >= linux_count):
      node[num]["os"] = "Windows"
    elif (windows_count < linux_count):
      node[num]["os"] = "Linux"
    
    # デバイス情報と連結
    node[num]["ports"] = copy.deepcopy(detect_ports)

    # 現在値の更新
    #node[num]["goap"]["Symbol_GetLanNodes"] = True
    node[num]["goap"]["Symbol_TcpScan"] = True
    node[num]["goap"]["Symbol_IdentOs"] = True

    detect_ports.clear()


  # masscan からの nmap
  def execute_mas2nmap(self, ip_addr, node, num, proxy, check_port):
  #def execute_mas2nmap(self, ip_addr, proxy, check_port):
    detect_ports = []
    d = {}
    flag = 0
    windows_count = 0
    linux_count = 0
  
    print('\nexecute nmap to {}...'.format(ip_addr))
    self.mlogger.writelog("execute nmap to " + ip_addr, "info")
    print("deep masscan node_id = {}".format(num))
  
    # 初期設定値
    #check_port = '1-65535'
    #check_port = '1-200'

    try:
      # スキャンの実行
      if proxy == 0:
        res = subprocess.check_output('nmap -sSV -O -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      else:
        res = subprocess.check_output('proxychains4 nmap -sTV -O -p' + check_port + ' ' + ip_addr, shell=True).decode('utf-8')
      rows = re.split('\n', res)
      #print(rows)

      for row in rows:
        # 終了判定
        if '/tcp' not in row:
          flag = 0
        # パース処理
        if flag == 1:
          row = row.replace('\n', '')
          row = re.sub(r'\s+', ' ', row)
          c = row.split(' ', 3)
          d["number"] = c[0]
          d["service"] = c[2]
          try: # version 取得の有無が存在するための処理
            if c[3]: # version 取得できている場合
              d["version"] = c[3]
          except: # version 取得できなかった場合
            d["version"] = ""
          detect_ports.append(copy.deepcopy(d))
        # 開始判定
        if 'SERVICE' and 'VERSION' in row:
          flag = 1
        # OS 判定処理
        if 'windows' in row.lower():
          windows_count = windows_count + 1
        if 'linux' in row.lower():
          linux_count = linux_count + 1

    except:
      print("No TCP port open!!")
      self.mlogger.writelog("No tcp port open!!", "error")

    # 重複削除
    print("detect_ports = {}".format(detect_ports))
    print("windows_count = {}".format(windows_count))
    print("linux_count = {}".format(linux_count))

    self.mlogger.writelog("detect_ports =  " + pprint.pformat(detect_ports), "info")

    # OS 判定処理
    if (windows_count >= linux_count):
      node[num]["os"] = "Windows"
    elif (windows_count < linux_count):
      node[num]["os"] = "Linux"
    elif(windows_count == 0 and linux_count == 0):
      node[num]["os"] = "Unknown"
    
    # デバイス情報と連結
    node[num]["ports"] = copy.deepcopy(detect_ports)

    # 現在値の更新
    #node[num]["goap"]["Symbol_GetLanNodes"] = True
    #node[num]["goap"]["Symbol_TcpScan"] = True
    #node[num]["goap"]["Symbol_IdentOs"] = True

    detect_ports.clear()
