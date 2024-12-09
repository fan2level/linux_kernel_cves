# -*-coding:utf-8-*-

import os, sys
from flask import Flask
import json

'''
cve_id
affected_versions
backport
breaks
cmt_msg
cvss2
  score
cvss3
  score
cwe
fixes
nvd_text
ref_urls
  Debian
  ExploitDB
  NVD
  Red Hat
  SUSE
  Ubuntu
'''

def load_cmts(data_file):
    data = None
    try:
        with open(data_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[exception] {e}")
    
    return data

def load_kernel_cves(data_file):
    data = None
    try:
        with open(data_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[exception] {e}")
    
    return data

def load_stream_data(data_file):
    data = None
    try:
        with open(data_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[exception] {e}")
    
    return data

def load_stream_fixes(data_file):
    data = None
    try:
        with open(data_file, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        print(f"[exception] {e}")
    
    return data

if __name__ == '__main__':
    cmts0 = load_cmts("../data/cmts.json")
    kernel_cves0 = load_kernel_cves("../data/kernel_cves.json")
    kernel_cves1 = load_kernel_cves("../data/kernel_cves.update.json")
    stream_data0 = load_stream_data("../data/stream_data.json")
    stream_fixes0 = load_stream_fixes("../data/stream_fixes.json")

    for id in sorted(kernel_cves1.keys(), reverse=True):
        print(f"{id}")
        try:
            for attribute in kernel_cves1[id].keys():
                if type(kernel_cves1[id][attribute]) is dict:
                    print(f"    {attribute}")
                    for feature in kernel_cves1[id][attribute]:
                        print(f"      {feature}")
                elif type(kernel_cves1[id][attribute]) is str:
                    print(f"  {attribute}: {kernel_cves1[id][attribute]}")
                else:
                    continue
        except Exception as e:
            print(f"[exception] {id}: {e}")

    print()
    print('done')
