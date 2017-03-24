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


api_call_list = {}

def getApiCallList():
    inputFile = open('smalicalltable.txt', 'r')
    lines = inputFile.readlines()
    for i in range(0,len(lines)-1,2):
        api_call_list[lines[i+1].strip()]=lines[i].strip()


'''
rootdir = train/
'''
def analysisAlltoCsv(rootdir):
    standard = {}
    dataframelist = []
    starttime = datetime.datetime.now()
    for parent,dirnames,filenames in os.walk(rootdir):#遍历每个apk文件
        for sid in filenames:
            if sid == '.DS_Store':
                continue
            apkpath = os.path.join(parent,sid)
            print apkpath
            clean()
            moveFile(apkpath,"workspace/test.apk")   #拷贝到分析目录
            doUnZip()                                #unzip解压apk到workspace/test
            Id = sid.split(".")[0]                   #获取后缀前的md5

            standard = doAnalysis(Id)                #对apk中的smali文件进行特征提取
            dataframelist.append(standard)

    #print dataframelist
    df = pd.DataFrame(dataframelist)
    df.to_csv("result/api3gramfeature.csv",index=False)   #将api调用特征写入csv
    stoptime = datetime.datetime.now
    print "finished job,total time : %d"  %  (stoptime-starttime).seconds


def doAnalysis(sid):
    try:
        doBakSmali()
    except Exception, e:
        writelog(sid,"API seq error")
        raise e

    return generateApiCallOneFile(sid,"workspace/smali")

def generateApiCallOneFile(sid,rootdir):
    map3gram = defaultdict(Counter)
    for parent,dirnames,filenames in os.walk(rootdir):
        for filename in filenames:
            suffix = os.path.splitext(filename)[1][1:]        #后缀
            classpath = os.path.join(parent,filename)
            if suffix == 'smali':
                apis = getApiSequenceFromDex(classpath)
                op3gram = getOpcodeNgram(apis)                #一个smali文件的api调用序列的计数
                map3gram[filename] = op3gram
                
            elif suffix == 'so':
                #ops = getOpcodeSequenceFromlib(classpath)

                print filename
            else:
                continue

    standard = {}
    standard["Id"] = sid
    if len(map3gram) == 0:
        writelog(sid,"API seq error")
        return standard

    cc = Counter([])
    for d in map3gram.values():
        cc += d
    selectedfeatures = {}
    tc = 0
    for k,v in cc.iteritems():
        if v >= 10:
            selectedfeatures[k] = v
            #print k,v
            tc += 1

    for fid,op3gram in map3gram.iteritems():
        for feature in selectedfeatures:
            #if standard.has_key(feature): 
            #    continue
            #print op3gram
            if feature in op3gram:
                #if int(standard[feature]) < int(op3gram[feature]):
                #print feature,op3gram[feature]
                standard[feature] = op3gram[feature]
                #print feature,standard[feature],op3gram[feature]
            '''
            else:
                standard[feature] = 0
            '''

    #print sorted(standard.iteritems(), key=lambda d:d[1])

    #return sorted(standard.iteritems(), key=lambda d:d[1])
    #print standard
    return standard

def getApiSequenceFromDex(classpath):
    smali_seq = []
    inputFile=open(classpath, 'r')
    lines=inputFile.readlines()
    methodFlag=0
    methodList=[]
    for i in range(len(lines)):
        if lines[i].find(".method")!=-1:
            methodFlag=1
        if lines[i].find(".end method")!=-1:
            methodFlag=0
        if methodFlag == 1:
            if lines[i].find('invoke-') !=-1:
                startpos = lines[i].find("}, L")
                methodname = lines[i][startpos+4:lines[i].find("(",startpos+4)]               
                if api_call_list.has_key(methodname):
                    #print methodname
                    smali_seq.append(api_call_list[methodname])
                
                #smali_seq.append(methodname)
    #print smali_seq
    return smali_seq

def init():
    getApiCallList()

if __name__ == '__main__':
    init()
    analysisAlltoCsv("train/")