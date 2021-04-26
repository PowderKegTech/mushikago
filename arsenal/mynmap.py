# nmap を実行するモジュール
# 本モジュールを実行する前に、ARP や masscan でIPアドレスは特定しておく必要がある（高速に nmap を実行するため）。
import nmap

class MyNmap():
  def __init__(self):
    print("init MyNmap")

  def execute_nmap(self, ip_addr, num, node):
    detect_ports = {}
    detect_port = []
    tmp = {}
  
    print('\nexecute nmap to {}...'.format(ip_addr))
  
    # 初期設定値
    #check_port = '1-65535'
    check_port = '1-200'
    argument = '-sSV -O'
    protocol = 'tcp'
    
    try:
      # スキャンの実行
      ps = nmap.PortScanner()
      ps.scan(ip_addr, check_port, argument)
  
      # スキャン結果の表示とjsonデータの作成
      ports = ps[ip_addr][protocol].keys()
  
  
      # 各ポートの特定
      for port in ports:
        #print("{}:{}".format(port, ps[ip_addr].tcp(port)))
        #tmp = ps[ip_addr].tcp(port)
        tmp["number"] = port
        tmp2 = dict(tmp, **ps[ip_addr].tcp(port))
        #detect_port["port"+str(i)] = tmp2
        detect_port.append(tmp2)
  
        # OS の特定
        if node[num]["os"] == "unknown":
          if "windows" in ps[ip_addr].tcp(port)['cpe'].lower():
            node[num]["os"] = "Windows"
          elif "linux" in ps[ip_addr].tcp(port)['cpe'].lower():
            node[num]["os"] = "Linux"
          elif "freebsd" in ps[ip_addr].tcp(port)['cpe'].lower():
            node[num]["os"] = "FreeBSD"
          elif "debian" in ps[ip_addr].tcp(port)['extrainfo'].lower():
            node[num]["os"] = "Debian"
  
  
      #print(detect_port)
    except:
      print("No TCP port open!!")
  
    # デバイス情報と連結
    detect_ports["ports"] = detect_port
    node[num] = dict(node[num], **detect_ports) 
    #tmpprint(json.dumps(node))
