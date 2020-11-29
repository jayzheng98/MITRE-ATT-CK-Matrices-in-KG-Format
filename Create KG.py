from py2neo import Graph, Node, Relationship, NodeMatcher
import csv

# 创建图
g = Graph('http://localhost:7474/', username='neo4j', password='111')
matcher = NodeMatcher(g)


# 建立NEO4J节点
def create_KG():
    g.delete_all()
    i = 0
    with open('G:/Programming files/Python/code/KG/KG-MITRE ATT&CK Matrices/ATT&CK MATRICES Tac.csv', 'r') as f1:
        Tactics_info_list = csv.reader(f1)
        for tac in Tactics_info_list:
            if Tactics_info_list.line_num == 1:
                continue
            Tactics_attrs = {'Name': tac[0].replace(' ', ''), 'Intro': tac[1], 'ID': tac[2], 'Created': tac[3],
                             'Last_Modified': tac[4]}
            Tactics_node = Node("Tactics", **Tactics_attrs)
            g.create(Tactics_node)

            # 建立Tactics节点之间关系
            i = i + 1
            if 1 < i < 13:
                pre_node = cur_node
                cur_node = Tactics_node
                relation1 = Relationship(pre_node, 'ATT&CK step', cur_node)
                g.create(relation1)
            else:
                cur_node = Tactics_node

    with open('G:/Programming files/Python/code/KG/KG-MITRE ATT&CK Matrices/ATT&CK MATRICES Tec.csv', 'r') as f2:
        Techniques_info_list = csv.reader(f2)
        for tec in Techniques_info_list:
            if Techniques_info_list.line_num == 1:
                continue
            Techniques_attrs = {'Name': tec[0], 'ID': tec[1], 'Sub-Tec': tec[2], 'Tactic': tec[3],
                                'Platforms': tec[4], 'Data Sources': tec[5], 'Permissions Required': tec[6]}
            Techniques_node = Node("Techniques", **Techniques_attrs)
            g.merge(Techniques_node, "Techniques", "Name")

            # 建立Tactics和Techniques节点之间关系
            if ',' not in tec[3]:
                Tempnode = matcher.match('Tactics').where("_.Name=~'(?i)" + tec[3] + "'").first()
                if Tempnode != None:
                    relation2 = Relationship(Techniques_node, 'Accomplishes', Tempnode)
                    g.create(relation2)
            else:
                Temp_tac_list = tec[3].split(',')
                for i in range(0, len(Temp_tac_list)):
                    Tempnode = matcher.match('Tactics').where("_.Name=~'(?i)" + Temp_tac_list[i] + "'").first()
                    if Tempnode != None:
                        relation2 = Relationship(Techniques_node, 'Accomplishes', Tempnode)
                        g.create(relation2)

    with open('G:/Programming files/Python/code/KG/KG-MITRE ATT&CK Matrices/ATT&CK MATRICES Miti.csv', 'r') as f3:
        Mitigations_info_list = csv.reader(f3)
        for miti in Mitigations_info_list:
            if Mitigations_info_list.line_num == 1:
                continue
            # 格式化miti[3]数据
            if miti[3] == '[]':
                miti[3] = ['None']
            else:
                miti[3] = miti[3].replace("'", "").replace("[", "").replace("]", "").split(", ")
                # print(miti[3])
            Mitigations_attrs = {'Name': miti[0], 'ID': miti[1], 'Description': miti[2],
                                 'Tecs Addressed by Mitigation': miti[3]}
            Mitigations_node = Node("Mitigations", **Mitigations_attrs)
            g.create(Mitigations_node)

            # 建立Mitigations和Techniques节点之间关系
            for addressed_tec in miti[3]:
                Tempnode = matcher.match('Techniques').where("_.Name=~'" + addressed_tec + "'").first()
                if Tempnode != None:
                    relation3 = Relationship(Mitigations_node, 'Prevents', Tempnode)
                    g.create(relation3)

    with open('G:/Programming files/Python/code/KG/KG-MITRE ATT&CK Matrices/ATT&CK MATRICES Group.csv', 'r') as f4:
        Groups_info_list = csv.reader(f4)
        for group in Groups_info_list:
            if Groups_info_list.line_num == 1:
                continue
            if group[3] == '':
                group[3] = ['None']
            if group[2] == '[]':
                group[2] = ['None']
            else:
                group[2] = group[2].replace("'", "").replace("[", "").replace("]", "").split(", ")
            Groups_attrs = {'Name': group[0], 'ID': group[1], 'Associated groups': group[3],
                                 'Tecs Used by Group': group[2]}
            Groups_node = Node("Groups", **Groups_attrs)
            g.create(Groups_node)

            # 建立Groups和Techniques节点之间关系
            for Used_tec in group[2]:
                Tempnode = matcher.match('Techniques').where("_.ID=~'" + Used_tec + "'").first()
                if Tempnode != None:
                    relation4 = Relationship(Groups_node, 'Uses', Tempnode)
                    g.create(relation4)

# 程序主入口
if __name__ == '__main__':
    create_KG()
