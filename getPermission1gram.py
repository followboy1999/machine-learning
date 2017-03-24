#!/usr/bin/python
#----- coding=utf8-----

import re
import os
import sys
from utility import *
from collections import *
from config import *
import pandas as pd
import datetime
'''
rootdir = train/
'''
def analysisAlltoCsv(rootdir):
    standard_permiss = {}
    dataframelist_permiss = []
    starttime = datetime.datetime.now()
    for parent,dirnames,filenames in os.walk(rootdir):#遍历每个apk文件
        for sid in filenames:
            if sid == '.DS_Store':
                continue
            apkpath = os.path.join(parent,sid)
            print apkpath
            clean()
            moveFile(apkpath,"workspace/test.apk")   #拷贝到分析目录
            Id = sid.split(".")[0]                   #获取后缀前的md5

            standard_permiss = doAnalysisPermission(Id)           #对apk中使用native code代码进行特征提取              
            dataframelist_permiss.append(standard_permiss)

    pf = pd.DataFrame(dataframelist_permiss)
    pf.to_csv("result/permission1gramfeature.csv",index=False)    #将opcode特征写入csv
    stoptime = datetime.datetime.now
    print "finished job,total time : %d" % (stoptime-starttime).seconds

def doAnalysisPermission(sid):
    try:
         permission =  getDangerPermission("workspace/test.apk")                                #get dangerous permission
    except Exception, e:
        writelog(sid,"Permiss seq error")
        raise e
   
    op3gram = getOpcodeNgram(permission,1)                #一个文件的dangeros permission计数

    standard = {}
    standard["Id"] = sid
    for feature in op3gram:
        standard[feature] = op3gram[feature]
    return standard

def getDangerPermission(filename):
    perm_seq = []
    include = re.compile(r'.*\.permission\.[A-Z_]+')
    cmd = "python tools/androguard/androapkinfo.py -i " + filename + " | grep permission"
    output = commands.getoutput(cmd)
    for line in output.split("\t"):
        m = re.findall(include,line.strip())
        if m:
            #print m[0].split("permission.")[1]
            perm_seq.append(m[0].split("permission.")[1])
    #print perm_seq
    return perm_seq

if __name__ == '__main__':
    analysisAlltoCsv("train/")
    #getDangerPermission("malware/Trojan-Spy.AndroidOS.Adrd.dw_8e1909f264ecf2eb72b290a4da9587a4.apk")
