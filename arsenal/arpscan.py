# arpscan を実行するモジュール
# 本モジュールは基本的にはムシカゴからしか行わない（というよりも L2 の通信なのでできない）
from database import mushilogger
from mac_vendor_lookup import MacLookup
import subprocess
import re

# arp-scan の実行
class ArpScan():
  def __init__(self):
    print("init ArpScan..")

    # mushikago log の出力
    self.mlogger = mushilogger.MushiLogger()


  def execute_arpscan(self, node, link, node_id):
    print('execute arpscan...')
    self.mlogger.writelog("execute arpscan...", "info")

    try:
      res = subprocess.check_output('arp-scan -l -x -N -r 1 -g', shell=True).decode('utf-8')
      print(res)
      self.mlogger.writelog("arpscan result = \n" + res, "info")
    except:
      print("arp-scan error!!")
      self.mlogger.writelog("arpscan error", "error")

    # arp-scan の結果をリストに格納
    iplist = re.split('\t|\n', res)
    iplist.pop(-1) # 最後に出力される改行をリストから削除
    #print(iplist)

    # 取得した情報を json 形式に変換し、登録
    # nodes の作成
    keys = ['id', 'mac', 'vendor']

    # 自分自身(mushikago)を追加
    if (node_id == 0):
      d = {}
      d['id'] = self.get_ipaddr()
      d['mac'] = self.get_macaddr()
      d['vendor'] = "Raspberry Pi"
      d['group'] = node_id
      d['ports'] = []
      d['os'] = "Raspberry Pi"
      d['node_id'] = 0
      d['session'] = ""
      d['ics_protocol'] = {}
      d['ics_device'] = 0
      d['secret_data'] = 0
      d['goap'] = {
        # 同一LANの端末を探索したか T1120
        "Symbol_GetLanNodes": True,
        # TCP ポートスキャンを実行したか T1046 T1018
        "Symbol_TcpScan": None,
        # UDP ポートスキャンを実行したか T1046 T1018
        "Symbol_UdpScan": None,
        # 端末のOSを特定したか T1003, T1059
        "Symbol_IdentOs": None,
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

    for num in range(0, len(iplist), 3):
      d = dict(zip(keys, iplist[num:num+3]))
      d['group'] = node_id
      d['os'] = 'unknown'
      d['node_id'] = num//3 + 1 + node_id
      d['session'] = ""
      d['ics_protocol'] = {}
      d['ics_device'] = 0
      d['secret_data'] = 0
      d['goap'] = {
        # 同一LANの端末を探索したか T1120
        "Symbol_GetLanNodes": True,
        # TCP ポートスキャンを実行したか T1046 T1018
        "Symbol_TcpScan": None,
        # UDP ポートスキャンを実行したか T1046 T1018
        "Symbol_UdpScan": None,
        # 端末のOSを特定したか T1003, T1059
        "Symbol_IdentOs": None,
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
      #node["node"+str(node_num)] = d
      node.append(d)

    # links の作成
    keys = ['target']

    for num in range(0, len(iplist), 3):
      d = dict(zip(keys, iplist[num:num+1]))
      d['source'] = self.get_ipaddr() # 自動で取得できるようにする
      d['node_id'] = num//3 + 1 + node_id
      d['value'] = 1
      #node["node"+str(node_num)] = d
      link.append(d)

    # node id を返り値として返す
    node_id = num//3 + 1 + node_id
    return node_id

    #print(node)
    #print(link)
    #return node


  # meterpreter から ARP モジュールを実行した場合の処理
  def execute_arpscan_fm_mp(self, node, link, node_id, src_ip):
    print('loading arp-scan.log...')
    self.mlogger.writelog("loading arp-scan.log...", "info")

    # arp-scan.log を読み込み
    try:
      res = subprocess.check_output('awk \'BEGIN {OFS="\t"}{print($5, $3)}\' ./arp-scan.log', shell=True).decode('utf-8')
      #print(res)
      self.mlogger.writelog("arpscan result = \n" + res, "info")
    except:
      print("arp-scan file error!!")
      self.mlogger.writelog("arpscan fm mp error", "error")

    mac = MacLookup()
    #mac.update_vendors() # 1年周期くらいでアップデートすればよいと思われる
    
    iplist = re.split('\t|\n', res)
    iplist.pop(-1)
    #print(iplist)
    
    maclist = []

    # 何も端末情報が得られなかった場合
    if len(iplist) == 0:
      print("No exist devices from arpscan...")
      self.mlogger.writelog("No exist devices from arpscan...", "info")
      return node_id
    
    # macアドレスからベンダーを特定
    for num in range(1, len(iplist), 2):
      #print(iplist[num])
      try:
        maclist.append(mac.lookup(iplist[num]))
      except:
        maclist.append("unknown")
     
    #print(maclist)
    
    # node への追加
    keys = ['id', 'mac']

    decrement_count = 0

    print("len(iplist) = {}".format(len(iplist)))
    
    for num in range(0, len(iplist), 2):
      d = dict(zip(keys, iplist[num:num+2]))
      already_scanned = 0

      # arp scan 前に tcp scan 済みだった場合、vendor のみ追加する
      for node_num in range(0, len(node), 1):
        if node[node_num]["id"] == d["id"]:
          node[node_num]["vendor"] = maclist.pop(0)
          already_scanned = 1
          decrement_count += 1
          break

      print("ipaddr = {}".format(d["id"]))
      print("decrement_count = {}".format(decrement_count))
      
      if already_scanned == 0:
        d['vendor'] = maclist.pop(0)
        d['group'] = node_id
        d['os'] = 'unknown'
        d['node_id'] = num//2 + node_id - decrement_count
        #d['node_id'] = (num//2 + 1 + node_id) - decrement_count
        d['session'] = ""
        d['ics_protocol'] = {}
        d['ics_device'] = 0
        d['secret_data'] = 0
        d['goap'] = {
          # 同一LANの端末を探索したか T1120
          "Symbol_GetLanNodes": True,
          # TCP ポートスキャンを実行したか T1046 T1018
          "Symbol_TcpScan": None,
          # UDP ポートスキャンを実行したか T1046 T1018
          "Symbol_UdpScan": None,
          # 端末のOSを特定したか T1003, T1059
          "Symbol_IdentOs": None,
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
        #decrement_count = 0
    
    #print(node)
    

    # links への追加
    keys = ['target']

    decrement_count = 0
    duplicate_count = 0

    for num in range(0, len(iplist), 2):
      d = dict(zip(keys, iplist[num:num+1]))
      already_scanned = 0

      # arp scan 前に tcp scan 済みだった場合、links に追加しない
      for node_num in range(0, len(link), 1):
        if link[node_num]["target"] == d["target"]:
          already_scanned = 1
          duplicate_count += 1
          decrement_count += 1
          break

      print("link ipaddr = {}".format(d["target"]))
      print("link decrement_count = {}".format(decrement_count))

      if already_scanned == 0:
        d['source'] = src_ip
        d['node_id'] = num//2 + node_id - decrement_count
        #d['node_id'] = (num//2 + 1 + node_id) - decrement_count
        d['value'] = 1
        link.append(d)
        #decrement_count = 0
    
    node_id = num//2 + 1 + node_id - duplicate_count
    print("arpscan node_id = {}".format(node_id)) # test
    return node_id
    #print(link)

  
  # IPアドレスの取得
  def get_ipaddr(self):
    try:
      res = subprocess.check_output('ifconfig | grep -A3 eth0 | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
      #print(res)
      return res.replace('\n', '')
    except:
      print("get-ipaddr error!!")
      self.mlogger.writelog("get-ipaddr error!!", "error")


  # MACアドレスの取得
  def get_macaddr(self):
    try:
      res = subprocess.check_output('ifconfig | grep -A3 eth0 | grep -oP \'ether ..:..:..:..:..:..\' | sed \'s/ether //\'', shell=True).decode('utf-8')
      #print(res)
      return res.replace('\n', '')
    except:
      print("get-macaddr error!!")
      self.mlogger.writelog("get-macaddr error!!", "error")
