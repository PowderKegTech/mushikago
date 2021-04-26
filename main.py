# はじめに実行するプログラム
from goap import goap
import copy
import sys

# main関数
if __name__ == '__main__':
  # 発見したデバイス情報を格納する辞書
  node_id = 0

  print(len(sys.argv))

  # アクションファイルを指定しているかのチェック
  if (len(sys.argv) != 2):
    print("Usage: # python3 main.py <actionfile>")
    exit(0)

  actionfile = sys.argv[1]

  # GOAP にてプランを作成
  goap_node = goap.GoapSymbol(actionfile)
  count = 0

  # 現在値がゴールに達していたら終了する
  while not (goap_node.state["GoalSymbol_AttackIcs"] == goap_node.goal["GoalSymbol_AttackIcs"] or goap_node.state["GoalSymbol_GetSecretInfo"] == goap_node.goal["GoalSymbol_GetSecretInfo"]):
    # 現在値を退避
    tmp_state = copy.deepcopy(goap_node.state)

    print("count = {}".format(count))
    print("main state = {}".format(goap_node.state))

    # GOAP でプランニング
    plan = goap_node.goap_plannning(goap_node)

    # 現在値を復元
    goap_node.state = copy.deepcopy(tmp_state)

    print("main state2 = {}".format(goap_node.state))

    print("node_id = {}".format(node_id))

    # プランを実行
    node_id = goap_node.plan_execute(goap_node, node_id, plan)

    """
    if (count == 0):
      goap_node.state["Symbol_ArpPoisoning"] = True
      goap_node.state["GoalSymbol_AttackIcs"] = True

    if (count == 1):
      goap_node.state["Symbol_BruteForce"] = True

    if (count == 2):
      goap_node.state["GoalSymbol_AttackIcs"] = True
    """

    count += 1

  print("Penetration Test Finish..")
