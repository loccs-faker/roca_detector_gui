# -*- coding: utf-8 -*-
"""
Created on Tue Jan 30 19:25:16 2018

@author: caopei
"""
import ssl 
import sys
import json
from past.builtins.misc import raw_input
if sys.version_info[0] >= 3:
    import urllib.request
else:
    import urllib2
    
ssl._create_default_https_context = ssl._create_unverified_context
usr_name = raw_input('login name:')
url = 'https://api.github.com/users/{}/keys'.format(usr_name)

def process_version_3(url):
    
    req = urllib.request.Request(url)
    html = urllib.request.urlopen(req).read()
    html = html.decode('utf-8')
    #try:
    dict1 = json.loads(html)
    #except:
    #return None
    print(dict1[0]['key'])
result = process_version_3(url)

