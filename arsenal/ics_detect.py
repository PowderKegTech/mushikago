from database import mushilogger
import subprocess
import copy
import pprint

class IcsDetect():
  def __init__(self):
    print("init ICS Detect..")

    self.mlogger = mushilogger.MushiLogger()

  def detect_protocol(self, num, node):
    p_list = {}
    p_list.clear()

    print('analyze pcap file for detect ics protocol...')
    self.mlogger.writelog("analyze pcap file for detect ics protocol...", "info")

    for pcap in node[num]["pcap_list"]:

      with open('./arsenal/ics_protocol_list.txt') as f:
        for protocol in f:
          protocol = protocol.replace('\n', '')

          try:
            res = subprocess.check_output('tshark -r ' + pcap + ' | grep -i \" ' + protocol + ' \"', shell=True).decode('utf-8')
            print(res)
            self.mlogger.writelog(res, "info")

            rows = res.splitlines()
            for row in rows:
              c = row.split()
              p_list[c[4]] = protocol

          except:
            print("tshark error!!")
            self.mlogger.writelog("tshark error!!", "error")

    node[num]["ics_protocol"] = copy.deepcopy(p_list)


  def detect_device(self, num, node):
    with open('./arsenal/ics_vendor_list.txt') as f:
      for vendor in f:
        vendor = vendor.replace('\n', '')
        if vendor.lower() in node[num]["vendor"].lower():
          node[num]["ics_device"] = 1
          break
