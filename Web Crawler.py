import requests
from lxml import etree
import time
import csv

# 初始化列表，存入爬虫数据
Tactics_info_list = []
Techniques_info_list = []
Techniques_url = []
Mitigations_info_list = []
Mitigations_info_list_temp = []
Mitigations_url = []


# 定义获取tactics相关信息的函数
def get_tactics_info(url):
    headers = {
        'User-Agent': 'user-agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'}
    html = requests.get(url, headers=headers)
    selector = etree.HTML(html.text)
    # 获取Tactics信息
    Tactics_ID = selector.xpath('//div[@class="card-body"]/div[1]/text()')
    Tactics_Created = selector.xpath('//div[@class="card-body"]/div[2]/text()')
    Tactics_LM = selector.xpath('//div[@class="card-body"]/div[3]/text()')
    Tactics_Name = selector.xpath('//div[@class="container-fluid"]/h1/text()')
    Tactics_Intros = selector.xpath('//div[@class="container-fluid"]/div[1]/div[1]/p/text()')
    info_list = [Tactics_Name[0].strip(), Tactics_Intros[0], Tactics_ID[0].strip(), Tactics_Created[0], Tactics_LM[0]]
    Tactics_info_list.append(info_list)

    # 获取Tactics对应的Techniques的url信息（便于之后进入url获取Technique的信息）
    Techniques_url_infos = selector.xpath('//table[@class="table-techniques"]/tbody')
    for info in Techniques_url_infos:
        Techniques_ID = info.xpath('tr[@class="technique"]/td[1]/a/text()')
        for ID in Techniques_ID:
            Techniques_url.append('https://attack.mitre.org/techniques/{}/'.format(str(ID.strip())))


# 定义获取Techniques相关信息的函数
def get_techniques_info(url):
    headers = {
        'User-Agent': 'user-agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'}
    html = requests.get(url, headers=headers)
    selector = etree.HTML(html.text)
    # 获取Techniques信息
    Techniques_Name = selector.xpath('//div[@class="container-fluid"]/h1/text()')
    Techniques_ID = selector.xpath('//div[@class="card-body"]/div/span[contains(text(),"ID")]/../text()')
    Techniques_Platforms = selector.xpath('//div[@class="card-body"]/div/span[contains(text(),"Platforms")]/../text()')
    Techniques_Tactic = selector.xpath('//div[@class="card-body"]/div/span[contains(text(),"Tactic")]/../text()')
    # Techniques_Version = selector.xpath('//div[@class="card-body"]/div/span[contains(text(),"Version")]/../text()')

    Techniques_Sub_tec = selector.xpath(
        '//div[@class="card-body"]/div/span[contains(text(),"Sub-techniques")]/../text()')
    if Techniques_Sub_tec[0].strip() != 'No sub-techniques':
        Techniques_Sub_tec = selector.xpath(
            '//div[@class="card-body"]/div/span[contains(text(),"Sub-techniques")]/../a/text()')
        Techniques_Sub_tec = str(len(Techniques_Sub_tec)) + ' sub-techniques'
    else:
        Techniques_Sub_tec = Techniques_Sub_tec[0].strip()
    Techniques_PR = selector.xpath(
        '//div[@class="card-body"]/div/span[contains(text(),"Permissions Required")]/../text()')
    if Techniques_PR != []:
        Techniques_PR = Techniques_PR[0].strip()
    Techniques_DS = selector.xpath('//div[@class="card-body"]/div/span[contains(text(),"Data Sources")]/../text()')
    if Techniques_DS != []:
        Techniques_DS = Techniques_DS[0].strip()

    info_list = [Techniques_Name[0].strip(), Techniques_ID[0].strip(), Techniques_Sub_tec,
                 Techniques_Tactic[0].replace('\n', '').replace(' ', ''), Techniques_Platforms[0],
                 Techniques_DS, Techniques_PR]
    Techniques_info_list.append(info_list)


# 定义获取Mitigations的url的函数
def get_mitigations_url():
    headers = {
        'User-Agent': 'user-agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'}
    html = requests.get('https://attack.mitre.org/mitigations/enterprise/', headers=headers)
    selector = etree.HTML(html.text)
    # 获取Mitigations基本信息
    Mitigation_ID = selector.xpath('//div[@class="overflow-x-auto"]/table/tbody/tr/td[1]/a/text()')
    Mitigation_Name = selector.xpath('//div[@class="overflow-x-auto"]/table/tbody/tr/td[2]/a/text()')
    Mitigation_Des = selector.xpath('//div[@class="overflow-x-auto"]/table/tbody/tr/td[3]/text()')
    for i in range(0, len(Mitigation_Des)):
        Mitigations_url.append('https://attack.mitre.org/mitigations/{}/'.format(str(Mitigation_ID[i].strip())))
        info_list = [Mitigation_Name[i], Mitigation_ID[i], Mitigation_Des[i].strip()]
        Mitigations_info_list.append(info_list)


# 定义获取Mitigations相关信息的函数
def get_mitigations_info(url):
    headers = {
        'User-Agent': 'user-agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.108 Safari/537.36'}
    html = requests.get(url, headers=headers)
    selector = etree.HTML(html.text)
    # 获取Mitigations解决的技术信息
    Tec_Addressed_by_Mitigation = selector.xpath(
        '//div[@class="container-fluid"]/table/tbody/tr[@class="technique"]/td[3]/a/text()')
    Mitigations_info_list_temp.append(Tec_Addressed_by_Mitigation)


# 定义获取Tactics网页数据的函数
def get_urls1():
    urls = ['https://attack.mitre.org/tactics/TA000{}/'.format(str(i)) for i in range(1, 10)]
    urls.extend(['https://attack.mitre.org/tactics/TA0010/', 'https://attack.mitre.org/tactics/TA0011/',
                 'https://attack.mitre.org/tactics/TA0040/'])
    for url in urls:
        get_tactics_info(url)
        time.sleep(0.05)


# 定义获取Techniques网页数据的函数
def get_urls2():
    for url in Techniques_url:
        get_techniques_info(url)
        time.sleep(0.05)


# 定义获取Mitigations网页数据的函数
def get_urls3():
    get_mitigations_url()
    for url in Mitigations_url:
        get_mitigations_info(url)
        time.sleep(0.05)
    # 合并两个列表
    for i in range(0, len(Mitigations_info_list_temp)):
        Mitigations_info_list[i].append(Mitigations_info_list_temp[i])


# 程序主入口
if __name__ == '__main__':
    # get_urls1()
    # get_urls2()
    get_urls3()
    # 定义表头
    # header1 = ['Name', 'Intro', 'ID', 'Created', 'Last_Modified']
    # header2 = ['Name', 'ID', 'Sub-Tec', 'Tactic', 'Platforms', 'Data Sources', 'Permissions Required']
    header3 = ['Name', 'ID', 'Description', 'Tecs Addressed by Mitigation']
    # 创建工作簿
    # csvfile1 = open('ATT&CK MATRICES Tac.csv', 'w', errors='ignore', newline='')
    # csvfile2 = open('ATT&CK MATRICES Tec.csv', 'w', errors='ignore', newline='')
    csvfile3 = open('ATT&CK MATRICES Miti.csv', 'w', errors='ignore', newline='')
    # sheet1 = csv.writer(csvfile1)
    # sheet2 = csv.writer(csvfile2)
    sheet3 = csv.writer(csvfile3)
    # 写入表头
    # sheet1.writerow(header1)
    # sheet2.writerow(header2)
    sheet3.writerow(header3)
    # 写入爬虫数据
    # for list1 in Tactics_info_list:
    #     sheet1.writerow(list1)
    # for list2 in Techniques_info_list:
    #     sheet2.writerow(list2)
    for list3 in Mitigations_info_list:
        sheet3.writerow(list3)
    # 保存文件
    # csvfile1.close()
    # csvfile2.close()
    csvfile3.close()
