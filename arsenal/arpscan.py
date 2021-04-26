# arpscan を実行するモジュール
# 本モジュールは基本的にはムシカゴからしか行わない（というよりも L2 の通信なのでできない）
from mac_vendor_lookup import MacLookup
import subprocess
import re

# arp-scan の実行
class ArpScan():
  def __init__(self):
    print("init ArpScan..")

  def execute_arpscan(self, node, link, node_id):
    print('execute arp-scan...')
    try:
      res = subprocess.check_output('arp-scan -l -x -N -r 1 -g', shell=True).decode('utf-8')
      print(res)
    except:
      print("arp-scan error!!")

    # arp-scan の結果をリストに格納
    iplist = re.split('\t|\n', res)
    iplist.pop(-1) # 最後に出力される改行をリストから削除
    #print(iplist)

    # 取得した情報を json 形式に変換し、登録
    #keys = ['ipaddr', 'mac', 'vendor']

    # nodes の作成
    keys = ['id', 'mac', 'vendor']

    # 自分自身(mushikago)を追加
    if (node_id == 0):
      d = {}
      d['id'] = self.get_ipaddr()
      d['mac'] = self.get_macaddr()
      d['vendor'] = "Raspberry Pi"
      d['group'] = 1
      d['ports'] = []
      d['os'] = "Raspberry Pi"
      d['node_id'] = 0
      d['session'] = ""
      d['ics_protocol'] = []
      d['ics'] = []
      d['secret_data'] = 0
      d['goap'] = []
      d['local_account_list'] = []
      d['local_account_pass'] = []
      d['local_account_hash'] = []
      d['domain_account_list'] = []
      d['domain_account_pass'] = []
      d['domain_account_hash'] = []
      d['process_list'] = []
      d['security_process'] = []
      d['network_info'] = []
      d['netstat_info'] = []
      d['network_drive'] = []
      d['pcap_list'] = []
      node.append(d)

    for num in range(0, len(iplist), 3):
      d = dict(zip(keys, iplist[num:num+3]))
      d['group'] = 1
      d['os'] = 'unknown'
      d['node_id'] = num//3 + 1 + node_id
      d['session'] = ""
      d['ics_protocol'] = []
      d['ics'] = []
      d['secret_data'] = 0
      d['goap'] = []
      d['local_account_list'] = []
      d['local_account_pass'] = []
      d['local_account_hash'] = []
      d['domain_account_list'] = []
      d['domain_account_pass'] = []
      d['domain_account_hash'] = []
      d['process_list'] = []
      d['security_process'] = []
      d['network_info'] = []
      d['netstat_info'] = []
      d['network_drive'] = []
      d['pcap_list'] = []
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
  def execute_arpscan_fm_mp(self, node, link, node_id):
    print('loading arp-scan.log...')

    # arp-scan.log を読み込み
    try:
      res = subprocess.check_output('awk \'BEGIN {OFS="\t"}{print($5, $3)}\' ./arp-scan.log', shell=True).decode('utf-8')
      #print(res)
    except:
      print("arp-scan file error!!")
    
    mac = MacLookup()
    #mac.update_vendors() # 1年周期くらいでアップデートすればよいと思われる
    
    iplist = re.split('\t|\n', res)
    iplist.pop(-1)
    #print(iplist)
    
    maclist = []
    
    # macアドレスからベンダーを特定
    for num in range(1, len(iplist), 2):
      #print(iplist[num])
      try:
        maclist.append(mac.lookup(iplist[num]))
      except:
        maclist.append("something vm")
     
    #print(maclist)
    
    # node への追加
    keys = ['id', 'mac']
    
    for num in range(0, len(iplist), 2):
      d = dict(zip(keys, iplist[num:num+2]))
      d['vendor'] = maclist.pop(0)
      d['group'] = 1
      d['os'] = 'unknown'
      d['node_id'] = num//2 + 1 + node_id
      d['session'] = ""
      d['ics_protocol'] = []
      d['ics'] = []
      d['secret_data'] = 0
      d['goap'] = []
      d['local_account_list'] = []
      d['local_account_pass'] = []
      d['local_account_hash'] = []
      d['domain_account_list'] = []
      d['domain_account_pass'] = []
      d['domain_account_hash'] = []
      d['process_list'] = []
      d['security_process'] = []
      d['network_info'] = []
      d['netstat_info'] = []
      d['network_drive'] = []
      d['pcap_list'] = []
      node.append(d)
    
    #print(node)
    
    # links への追加
    keys = ['target']
    
    for num in range(0, len(iplist), 2):
      d = dict(zip(keys, iplist[num:num+1]))
      d['source'] = '10.2.200.80' # 自動で取得できるようにする
      d['node_id'] = num//2 + 1 + node_id
      d['value'] = 1
      link.append(d)
    
    node_id = num//2 + 1 + node_id
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

  # MACアドレスの取得
  def get_macaddr(self):
    try:
      res = subprocess.check_output('ifconfig | grep -A3 eth0 | grep -oP \'ether ..:..:..:..:..:..\' | sed \'s/ether //\'', shell=True).decode('utf-8')
      #print(res)
      return res.replace('\n', '')
    except:
      print("get-macaddr error!!")
