#!/usr/bin/env python
# -*- coding: utf-8 -*-
import re
import time
import json
import requests
from pyquery import PyQuery
from detector import Detector
MAX_TIME = 10
HEADERS = {
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Encoding': 'gzip, deflate, br',
    'Accept-Language': 'en-US,en;q=0.5',
    'Cache-Control': 'no-cache',
    'Connection':'keep-alive',
    'Host':'api.github.com',
    'Pragma':'no-cache',
    'User-Agent':'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:58.0) Gecko/20100101 Firefox/58.0'
}
def get_ip181_proxies():
    """
    http://www.ip181.com/获取HTTPS代理
    """
    html_page = requests.get('http://www.ip181.com/').content.decode('gb2312')
    jq = PyQuery(html_page)

    proxy_list = []
    for tr in jq("tr"):
        element = [PyQuery(td).text() for td in PyQuery(tr)("td")]
        if 'HTTPS' not in element[3]:
            continue

        result = re.search(r'\d+\.\d+', element[4], re.UNICODE)
        if result and float(result.group()) > 5:
            continue
        proxy_list.append((element[0], element[1]))

    return proxy_list,len(proxy_list)

def change_proxy(proxies, index, proxy_num):
    """
    更换https代理服务器
    :param proxies: 代理服务器列表
    :param index: 当前下标
    :param proxy_num: 代理服务器总数
    :return: 代理URL
    """
    index = index % proxy_num
    url = 'http://' + proxies[index][0] + ':' + proxies[index][1]
    return url

def req_url(proxy_url, page):
    """
    访问github api爬取用户的登录名
    :param proxy_url: https代理的URL
    :return:
    """
    proxies = {
        "http": proxy_url,
        "https": proxy_url,
    }
    try:

        r = requests.get("https://api.github.com/search/users?q=repos:%3E22&page={}".format(page), proxies=proxies,
                         headers = HEADERS, timeout = 10 )
    except:
        return None
    html = r.text.decode('utf-8')
    dict1 = json.loads(html)
    login_names = []
    for i in range(len(dict1['items'])):
        login_names.append(dict1['items'][i]['login'])
    return login_names

current_index = 0
f_result = []
def detect_login_names(login_names, proxy_url, proxy_index, proxies, proxy_num):
    proxies_c = {
        "http": proxy_url,
        "https": proxy_url,
    }
    global f_result

    current_time = 0
    temp_num = 0
    global current_index
    for idx, login in enumerate(login_names[current_index:]):
        current_time = current_time+1
        print('number:%d\n' %(idx+current_index))
        if current_time == 9:
            proxy_index = proxy_index + 1
            proxies_temp = change_proxy(proxies, proxy_index, proxy_num)
            proxies_c['http'] = proxies_temp
            proxies_c['https'] = proxies_temp
            current_time = 0
        try:
            r = requests.get('https://api.github.com/users/{}/keys'.format(login), proxies=proxies_c,
                             headers=HEADERS, timeout=10)
        except:

            current_index = idx+current_index
            return None
        html = r.text.decode('utf-8')
        dict1 = json.loads(html)
        keys = []
        if len(dict1) == 0:
            continue
        if isinstance(dict1,dict):
            continue
        for i in range(0, len(dict1)):
            keys.append(dict1[i]['key'])
        Dict_temp = {}
        Dict_temp['login'] = login
        Dict_temp['keys'] = keys
        f_result.append(Dict_temp)
    return f_result
if __name__ == '__main__':
    login_names = []
    proxy_index = 0
    page = 1
    current_time = 0
    (proxies,proxy_num) = get_ip181_proxies()
    proxy_url = change_proxy(proxies, proxy_index, proxy_num)

    print proxy_url
    print proxies
    for page in range(1,35):
        print('page = %d\n'% page)
        ret = req_url(proxy_url, page)
        current_time = current_time+1
        if current_time == 9:
            proxy_index = proxy_index + 1
            proxy_url = change_proxy(proxies, proxy_index, proxy_num)
            current_time = 0
        while ret == None:
            proxy_index = proxy_index+1
            proxy_url = change_proxy(proxies, proxy_index, proxy_num)
            ret = req_url(proxy_url, page)
        login_names.extend(ret)
    print('totol number is :%d\n'% len(login_names))
    #with open('login_names.txt', 'w') as f:
        #for i in range(0,len(login_names)):
            #f.write(login_names[i]+'\n')
    holder = Detector()
    result = detect_login_names(login_names, proxy_url, proxy_index, proxies, proxy_num)
    while result is None:
        proxy_index = proxy_index + 1
        proxy_url = change_proxy(proxies, proxy_index, proxy_num)
        result = detect_login_names(login_names, proxy_url, proxy_index, proxies, proxy_num)
    find_flag = False
    for item in f_result:
        for i in range(len(item['keys'])):
            if Detector.process_ssh(holder, item['keys'][i], item['login']):
                find_flag = True
                with open('test_result.txt', 'a') as f2:
                    f2.write(item['login'] + '\t' +  item['keys'][i])
    if find_flag:
        print('---------find vunerable keys!------------\n')
    else:
        print('---------safe!------------\n')



