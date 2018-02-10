#!/usr/bin/env python
# -*- coding: utf-8 -*-
import sys
import os
from roca_gui.detector import Detector
from past.builtins.misc import raw_input


def get_keys(file_name):
    if not os.path.exists(file_name):
        print("file not exist!\n")
        return
    keys = []
    with open(file_name, 'r') as f:
        f.readline()
        while True:
            line = f.readline()
            if line.strip() != '':
                keys.append(line.split(';')[1])
            else:
                break
    return keys


def detect_keys(keys):
    result = []
    find_flag = False
    detector = Detector()
    if keys == []:
        print('no keys!\n')
        return
    for idx, key in enumerate(keys):
        ret = detector.process_raw_mod(key, 'hex')
        if ret is True:
            find_flag = True
            dict = {}
            dict['idx'] = idx
            dict['key'] = key
            result.append(dict)
    if find_flag:
        print('WARNING: Potential vulnerability\n')
        while True:
            todo = raw_input('load result to file?(Y/N):')
            if todo == 'Y':
                with open('csv_result.txt', 'w') as f2:
                    f2.write('idx\t\t\tkey\n\n')
                    for i, dic in enumerate(result):
                        f2.write('%d\t\t\t%s\n' % (dic['idx'], dic['key']))
                break
            elif todo == 'N':
                break
            else:
                print('Wrong input!\n')
    else:
        print('No fingerprinted keys found (OK)!\n')


def main():
    if len(sys.argv) != 2:
        print('wrong arg number.\n')
        return
    file_name = sys.argv[1]
    # print(file_name)
    keys = get_keys(file_name)
    detect_keys(keys)
    #print(keys)


if __name__ == "__main__":
    main()
