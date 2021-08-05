# はじめに実行するプログラム
from goap import goap
import copy
import sys
import subprocess
import csv

# goap と target の内容をファイル書き出し
def goap_write(arg, count):
  if count == 0:
    with open('goap_contents.csv', 'w') as f:
      pass
  else:
    with open('goap_contents.csv', 'a') as f:
      w = csv.writer(f)
      w.writerow(arg)


# IPアドレスと netmask の取得
def get_ipaddr():
  try:
    #res = subprocess.check_output('ifconfig | grep -A3 eth0 | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
    ipaddr = subprocess.check_output('ifconfig eth0 | grep "inet " | grep -oP \'inet [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/inet //\'', shell=True).decode('utf-8')
    netmask = subprocess.check_output('ifconfig eth0 | grep "inet " | grep -oP \'netmask [0-9]*\.[0-9]*\.[0-9]*\.[0-9]*\' | sed \'s/netmask //\'', shell=True).decode('utf-8')
    #print(res)
    return ipaddr.replace('\n', ''), netmask.replace('\n', '')
  except:
    print("get-ipaddr error!!")


# main関数
if __name__ == '__main__':
  # 発見したデバイス情報を格納する辞書
  node_id = 0

  # アクションファイルを指定しているかのチェック
  if (len(sys.argv) != 2):
    print("Usage: # python3 main.py <actionfile>")
    exit(0)

  actionfile = sys.argv[1]

  # GOAP にてプランを作成
  goap_node = goap.GoapSymbol(actionfile)
  count = 0

  # 現在値がゴールに達していたら終了する
  while not (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetLocalSecretInfo"] == goap_node.goal["GoalSymbol_GetLocalSecretInfo"] or goap_node.state["GoalSymbol_GetNwSecretInfo"] == goap_node.goal["GoalSymbol_GetNwSecretInfo"]):

    print("count = {}".format(count))

    # target を選定
    # 1回目の場合
    if count == 0: 
      plan = ["arpscan", "tcpscan"]
      target, netmask = get_ipaddr() 
      node_num = 0

    else: # 2回目以降
      # target の選定
      target, node_num, target_state = goap_node.select_target()

      print("target = {}".format(target))
      #print("node_num = {}".format(node_num))
      #print("target_state = {}".format(target_state))

      if target == None:
        print("There is no target...")
        # ネットワークスキャンをして target を探索する
        node_id = goap_node.network_scan(node_id, goap_node)
        # target の選定
        target, node_num, target_state = goap_node.select_target()

        # target が発見できなかった場合は、処理を終了する。
        if target == None:
          print("After all, there is no target...")
          exit(0)

      # state の設定
      goap_node.state = copy.deepcopy(target_state)

      print("main state = {}".format(goap_node.state))

      # GOAP でプランニング
      plan = goap_node.goap_plannning(goap_node)

      # state の設定(planning で更新された内容を解除)
      goap_node.state = copy.deepcopy(target_state)

    # プランを実行
    print("target = {}".format(target))
    #print("netmask = {}".format(netmask))
    #print("main state = {}".format(goap_node.state))

    node_id = goap_node.plan_execute(goap_node, node_id, plan, target, node_num)

    print("node_id = {}".format(node_id))

    # goap の内容をファイル書き出し
    g_content = copy.deepcopy(plan)
    g_content.insert(0, target)
    goap_write(g_content, count)

    count += 1
    #exit(0)

  print("Penetration testing complete...")
