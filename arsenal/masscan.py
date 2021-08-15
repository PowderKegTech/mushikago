from database import mushilogger
import subprocess
import re
from arsenal import mynmap

class MasScan():
  def __init__(self):
    print("init MasScan..")

    self.mlogger = mushilogger.MushiLogger()


  def execute_deep_masscan(self, ipaddr_list, node, node_id):
    #print('execute deep masscan...')
    self.mlogger.writelog("execute deep masscan...", "info")

    pattern = '(.*)port (.*)/tcp(.*)'
    #pattern2 = '(.*)port (.*) on (.*)'
    port_list = []

    #count = 0 
    for ipaddr in ipaddr_list:
      #print("deep scanning to {}...".format(ipaddr))
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

        # Delete duplicate
        port_list = list(set(port_list))

        #print("IP address = {}".format(ipaddr))
        #print("port list = {}\n".format(port_list))
        self.mlogger.writelog("port list =  " + ','.join(port_list), "info")

        # list to str and separate comma
        check_port = ','.join(port_list)
        print("check_port = {}".format(check_port))

        proxy = 1

        #print("deep masscan count = {}".format(count))
        print("deep masscan node_id = {}".format(node_id))

        if len(check_port) != 0:
          mynmapInstance = mynmap.MyNmap()
          mynmapInstance.execute_mas2nmap(ipaddr, node, node_id, proxy, check_port)

        port_list.clear()

      except:
        #print("deep masscan error!!")
        self.mlogger.writelog("deep masscan error!!", "error")

      #count = count + 1
      #node_id = node_id + count
      node_id = node_id + 1


  def execute_masscan(self, nwaddr, src_ip, node, link, node_id):
    #print('execute masscan...')
    self.mlogger.writelog("execute masscan...", "info")

    pattern = '(.*) on (.*)'
    #pattern2 = '(.*)port (.*)/tcp(.*)'
    #pattern2 = '(.*)port (.*) on (.*)'
    ipaddr_list = []
    #port_list = []

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

      # Delete duplicate
      ipaddr_list = list(set(ipaddr_list))
      #port_list = list(set(port_list))

      #print("IP address list = {}\n".format(ipaddr_list))
      self.mlogger.writelog("ip address list =  " + ','.join(ipaddr_list), "info")
      #print("port list = {}\n".format(port_list))

      check_iplist = []
      for ipaddr in ipaddr_list:
        for num in range(0, len(node)): 
          if ipaddr == node[num]["id"]:
            print("{} is checked. remove..".format(ipaddr))
            check_iplist.append(ipaddr)

      for ipaddr in check_iplist:
        ipaddr_list.remove(ipaddr)

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
          "Symbol_GetLanNodes": None,
          "Symbol_TcpScan": True,
          "Symbol_UdpScan": None,
          "Symbol_IdentOs": True,
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

      count = 0
      for ipaddr in ipaddr_list:
        d = {}
        d['target'] = ipaddr
        d['source'] = src_ip
        d['node_id'] = node_id + count
        d['value'] = 1
        link.append(d)
        count = count + 1

      if len(ipaddr_list) > 0:
        self.execute_deep_masscan(ipaddr_list, node, node_id)

      node_id = node_id + count
      
      ipaddr_list.clear()
      #port_list.clear()

      return node_id

    except:
      #print("masscan error!!")
      self.mlogger.writelog("masscan error!!", "error")

