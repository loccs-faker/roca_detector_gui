#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# Created on 2018-02-03 18:23:38
# Project: apk_spider

import json
import re
import os
import requests
from pyquery import PyQuery
from detector import Detector
from HTMLParser import HTMLParser

PAGE_START = 1
PAGE_END = 2
DIR_PATH = '/home/caopei/Downloads/apk'
s = requests.session()
s.keep_alive = False

class Handler(object):

    def __init__(self):
        self.main_url = 'http://zhushou.360.cn'
        self.base_url = 'http://zhushou.360.cn/list/index/cid/2/order/download/?page='
        self.download_base_url = 'htp://zhushou.360.cn/detail/index/soft_id/'
        self.page_num = PAGE_START
        self.total_num = PAGE_END
        #self.deal = Deal()

    def on_start(self):
        while self.page_num <= self.total_num:
            url = self.base_url + str(self.page_num)
            html_page = requests.get(url).content
            #link_list = re.findall(r"(?<=&url=).*?apk", html_page)
            #print(link_list)
            jq = PyQuery(html_page)
            icon = jq('.icon_box')
            for li in jq(icon)('li'):
                h3 = jq(li)('h3')
                a = jq(h3)('a')
                result = self.process_detail(a.attr.href)
                #break
            self.page_num += 1

    def process_detail(self, unfinished_url):
        url = self.main_url + unfinished_url
        detail_page = requests.get(url).content
        jq = PyQuery(detail_page)
        size = jq('.s-3')
        #print(size.eq(1).text())
        apk_size = size.eq(1).text()
        apk_size = float(re.match(r'[^A-Z]+',apk_size).group(0))
        if apk_size < 10:

            download_url = jq('dd > a').attr.href
            print(download_url)
            apk_name = jq('h2 > span').attr.title
            print HTMLParser().unescape(apk_name)
            download_url = re.search(r"(?<=&url=).*?\.apk", download_url).group(0)
            print(size.eq(1).text())
            print(download_url)
            self.download_apk(download_url, apk_name)
        return
    def download_apk(self, download_url, apk_name):
        file_name = apk_name + '.apk'
        file_path = os.path.join(DIR_PATH, file_name)
        #print(file_name)
        print(file_path)
        r = requests.get(download_url)
        with open(file_name,'wb') as f:
            f.write(r.content)
        return
handler = Handler()
handler.on_start()
