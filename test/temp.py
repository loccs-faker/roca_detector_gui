# -*- coding: utf-8 -*-
"""
Created on Tue Jan 16 18:12:11 2018

@author: caopei
"""

for i in range(5000,5050):
    with open('cert04.pem','r') as f1:
        data = f1.read()
        with open('cer0%s.pem'% str(i),'w') as f2:
            f2.write(data)
            
