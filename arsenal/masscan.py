# masscan を実行するモジュール
from database import mushilogger
import subprocess
import re
from arsenal import mynmap

# masscan の実行
class MasScan():
  def __init__(self):
    print("init MasScan..")

    # mushikago log の出力
    self.mlogger = mushilogger.MushiLogger()


  # 全ポートを高速スキャン
  def execute_deep_masscan(self, ipaddr_list, node, node_id):
    print('execute deep masscan...')
    self.mlogger.writelog("execute deep masscan...", "info")

    pattern = '(.*)port (.*)/tcp(.*)'
    #pattern2 = '(.*)port (.*) on (.*)'
    port_list = []

    # 特定IPアドレスのみを全ポートスキャン
    #count = 0 
    for ipaddr in ipaddr_list:
      print("deep scanning to {}...".format(ipaddr))
      self.mlogger.writelog("deep scanning to " + ipaddr, "info")
      request = 'proxychains4 ./bin/masscan -e eth0 ' + ipaddr + ' -p1-65535 --rate=1000'
      #request = 'proxychains4 ./bin/masscan -e eth0 ' + ipaddr + ' -p1-65535 --rate=10000' # test 
      print(request)

      try:
        res = subprocess.check_output(request, shell=True).decode('utf-8')
        #print("result = {}".format(res))
        rows = re.split('\t|\n', res)
        rows.pop(-1)

        for row in rows:
          print(row)
          result = re.match(pattern, row)
          port_list.append(result.group(2).replace('\n', ''))

        # 重複削除
        port_list = list(set(port_list))

        #print("IP address = {}".format(ipaddr))
        print("port list = {}\n".format(port_list))
        self.mlogger.writelog("port list =  " + ','.join(port_list), "info")

        # list to str and separate comma
        check_port = ','.join(port_list)
        print("check_port = {}".format(check_port))

        proxy = 1

        # execute nmap
        #print("deep masscan count = {}".format(count))
        print("deep masscan node_id = {}".format(node_id))

        if len(check_port) != 0:
          mynmapInstance = mynmap.MyNmap()
          mynmapInstance.execute_mas2nmap(ipaddr, node, node_id, proxy, check_port)

        port_list.clear()

      except:
        print("deep masscan error!!")
        self.mlogger.writelog("deep masscan error!!", "error")

      #count = count + 1
      #node_id = node_id + count
      node_id = node_id + 1


  # 高速スキャンの実施
  def execute_masscan(self, nwaddr, src_ip, node, link, node_id):
    print('execute masscan...')
    self.mlogger.writelog("execute masscan...", "info")

    pattern = '(.*) on (.*)'
    #pattern2 = '(.*)port (.*)/tcp(.*)'
    #pattern2 = '(.*)port (.*) on (.*)'
    ipaddr_list = []
    #port_list = []

    # 特定ポートのみを高速スキャン
    #request = 'proxychains4 ./bin/masscan -e eth0 ' + nwaddr + ' -p21,22,23,25,80,110,135,139,143,443,445,465,587,993,995,3389 --rate=10000' # test
    request = 'proxychains4 ./bin/masscan -e eth0 ' + nwaddr + ' -p21,22,23,25,80,110,135,139,143,443,445,465,587,993,995,3389 --rate=1500'
    print(request)

    try:
      res = subprocess.check_output(request, shell=True).decode('utf-8')
      #print("result = {}".format(res))
      rows = re.split('\t|\n', res)
      rows.pop(-1)

      for row in rows:
        print(row)
        result = re.match(pattern, row)
        ipaddr_list.append(result.group(2).replace(' ', ''))

        #result = re.match(pattern2, row)
        #port_list.append(result.group(2).replace('\n', ''))

      # 重複削除
      ipaddr_list = list(set(ipaddr_list))
      #port_list = list(set(port_list))

      print("IP address list = {}\n".format(ipaddr_list))
      self.mlogger.writelog("ip address list =  " + ','.join(ipaddr_list), "info")
      #print("port list = {}\n".format(port_list))

      # チェック済みな IP アドレスでないか確認
      check_iplist = []
      for ipaddr in ipaddr_list:
        for num in range(0, len(node)): 
          if ipaddr == node[num]["id"]:
            print("{} is checked. remove..".format(ipaddr))
            check_iplist.append(ipaddr)

      # チェック済みな IP アドレスを削除
      for ipaddr in check_iplist:
        ipaddr_list.remove(ipaddr)

      # node への追加
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['id'] = ipaddr
        d['mac'] = ""
        d['vendor'] = ""
        d['group'] = node_id
        d['ports'] = []
        d['os'] = ""
        d['node_id'] = node_id + count
        d['session'] = ""
        d['ics_protocol'] = {}
        d['ics_device'] = 0
        d['secret_data'] = 0
        d['goap'] = {
          # 同一LANの端末を探索したか T1120
          "Symbol_GetLanNodes": None,
          # TCP ポートスキャンを実行したか T1046 T1018
          "Symbol_TcpScan": True,
          # UDP ポートスキャンを実行したか T1046 T1018
          "Symbol_UdpScan": None,
          # 端末のOSを特定したか T1003, T1059
          "Symbol_IdentOs": True,
          # 横展開を実行したか TA0008
          "Symbol_LateralMovement": None,
          # ブルートフォースアタックを実行したか T1110
          #"Symbol_BruteForce": None,
          # ARP Cache Poisoning をしたか T1557 T1112(registry modify)
          "Symbol_ArpPoisoning": None,
          # ネットワーク情報を取得したか T1016, T1049
          "Symbol_GetNetworkInfo": None,
          # DC を探索したか T1482
          "Symbol_DCCheck": None,
          # ログオンユーザ情報を収集したか T1059
          "Symbol_LogonUserInfo": None,
          # ドメインユーザの探索 T1087
          "Symbol_DomainUser": None,
          # ローカルユーザの探索 T1087
          "Symbol_LocalUser": None,
          # 有効なアカウントを利用したか T1078
          "Symbol_ValidUser": None,
          # 不正なアカウントを作成したか T1136
          "Symbol_CreateUser": None,
          # 端末のOSのパッチ情報などを取得したか T1003, T1059, T1082
          "Symbol_GetOsPatch": None,
          # 権限昇格しているか TA0004
          "Symbol_PrivilegeEscalation": None,
          # プロセス情報を収集したか(セキュリティ製品の探索も行う) T1057, T1059 
          "Symbol_ProcessInfo": None,
          # 別のプロセスに移動したか T1055
          "Symbol_ProcessMigrate": None,
          # 主要なディレクトリを調査したか T1083(File and Directory Discovery), TA0009, TA0010
          "Symbol_MainDriveInfo": None,
          "Symbol_SearchMainDrive": None,
          # ネットワークドライブを確認したか T1083, T1135
          "Symbol_NwDriveInfo": None,
          "Symbol_SearchNwDrive": None,
          # ローカルの機密情報を発見したか TA0009
          "GoalSymbol_GetLocalSecretInfo": None,
          # ネットワーク上の機密情報を発見したか TA0009
          "GoalSymbol_GetNwSecretInfo": None,
          # 別のネットワークセグメントを特定したか
          #"Symbol_NetworkSegmentCheck": None,
          # パケットを収集したか T1040
          "Symbol_PacketInfo": None,
          # ICS プロトコルを特定したか T1046
          "Symbol_GetIcsProtocol": None,
          # ICS 機器を探索したか T1120
          "Symbol_GetIcsDevice": None,
          # ICS 機器を攻撃したか TA0040
          "GoalSymbol_AttackIcs": None
        }
        d['local_account_list'] = []
        d['local_account_pass'] = []
        d['local_account_hash'] = []
        d['domain_account_list'] = []
        d['domain_account_pass'] = []
        d['domain_account_hash'] = []
        d['dc'] = []
        d['domain_info'] = []
        d['process_list'] = []
        d['security_process'] = []
        d['ipconfig_info'] = []
        d['netstat_info'] = []
        d['network_drive'] = []
        d['local_drive'] = []
        d['pcap_list'] = []
        d['os_patches'] = []
        d['local_vuln_list'] = []
        node.append(d)
        count = count + 1

      # links への追加
      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['target'] = ipaddr
        d['source'] = src_ip
        d['node_id'] = node_id + count
        d['value'] = 1
        link.append(d)
        count = count + 1

      # 全ポートスキャンと nmap の実行
      if len(ipaddr_list) > 0:
        self.execute_deep_masscan(ipaddr_list, node, node_id)

      # node_id の更新
      node_id = node_id + count
      
      ipaddr_list.clear()
      #port_list.clear()

      return node_id

    except:
      print("masscan error!!")
      self.mlogger.writelog("masscan error!!", "error")

