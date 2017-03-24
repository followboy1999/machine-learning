#!/usr/bin/python
#----- coding=utf8-----

import re
import os
import sys
from utility import *
from collections import *
from config import *
import pandas as pd


api_call_list = {}
dataframelist = []

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
    standard_op = {}
    dataframelist = []
    dataframelist_op = []
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


#            standard = doAnalysis(Id)                #对apk中的smali文件进行特征提取
#            dataframelist.append(standard)

            standard_op = doAnalysisOp(Id)           #对apk中使用native code代码进行特征提取              
            dataframelist_op.append(standard_op)

    #print dataframelist
#    df = pd.DataFrame(dataframelist)
#    df.to_csv("result/api3gramfeature.csv",index=False)   #将api调用特征写入csv

    pf = pd.DataFrame(dataframelist_op)
    pf.to_csv("result/op3gramfeature.csv",index=False)    #将opcode特征写入csv


def doAnalysisOp(sid):
    opcode_seq = []
    map3gram = defaultdict(Counter)
    for parent,dirnames,filenames in os.walk("workspace/test/lib/armeabi"):
        for filename in filenames:
            if filename == ".DS_Store":
                continue
            sopath = os.path.join(parent,filename)
            suffix = os.path.splitext(filename)[1][1:]        #后缀
            print sopath
            if suffix == "so":
                generateAsm(sopath)                     #生成asm
                if not os.path.exists("workspace/test/lib/armeabi/"+filename.replace("so","asm")):
                    continue                  
                ops = getOpcodeSequenceFromlib("workspace/test/lib/armeabi/"+filename.replace("so","asm"))
                op3gram = getOpcodeNgram(ops)                #一个文件的opcode的计数
                map3gram[filename] = op3gram

    cc = Counter([])
    for d in map3gram.values():
        cc += d
    selectedfeatures = {}
    tc = 0
    for k,v in cc.iteritems():
        if v >= 500:
            selectedfeatures[k] = v
            #print k,v
            tc += 1

    standard = {}
    standard["Id"] = sid
    for fid,op3gram in map3gram.iteritems():
        for feature in selectedfeatures:
            if feature in op3gram:
                standard[feature] = op3gram[feature]

    return standard

def doAnalysis(sid):
    doBakSmali()
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

    standard = {}
    standard["Id"] = sid
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

    

def getOpcodeNgram(ops, n=3):
    opngramlist = [tuple(ops[i:i+n]) for i in range(len(ops)-n)]
    opngram = Counter(opngramlist)
    return opngram


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

def getOpcodeSequenceFromlib(classpath):
    opcode_seq = []
    include = re.compile(r'\s+[A-Z]{1,10}\s+')
    with open(classpath) as f:
        for line in f:
            m = re.findall(include,line)
            if m:
                opc = m[0].strip()
                #print opc
                if opc in arm_op:
                    #print opc
                    opcode_seq.append(opc)
    #print opcode_seq
    return opcode_seq

def getOpcodeSequenceFromlib2(classpath):
    opcode_seq = []
    include = re.compile(r'[a-z]{1,10}\s?')
    exclude = re.compile(r'[a-zA-Z0-9]+\s?=')
    dd_exclude = re.compile(r'\s*dd\s*')
    db_exclude = re.compile(r'\s*db\s*')
    dw_exclude = re.compile(r'\s*dw\s*')
    with open(classpath) as f:
        for line in f:
            if line.lstrip().startswith("_text") or \
            line.lstrip().startswith("start") or \
            line.lstrip().startswith(";") or \
            line.lstrip().startswith("loc_") or \
            line.lstrip().startswith("sub_") or \
            line.lstrip().startswith("var_") or \
            line.lstrip().startswith("arg_") or \
            line.lstrip().startswith("align") or \
            line.lstrip().startswith("_data") or \
            line.lstrip().startswith("public") or \
            line.lstrip().startswith("_rdata") or \
            line.lstrip().startswith("assume") or \
            line.lstrip().startswith("include") or \
            line.lstrip().startswith("off_") or \
            line.lstrip().startswith("dword_") or \
            line.lstrip().startswith("extrn") or \
            line.lstrip().startswith("unicode") or \
            line.lstrip().startswith("word_") or \
            line.lstrip().startswith("db") or \
            line.lstrip().startswith("dd") or \
            line.lstrip().startswith("data") or \
            line.lstrip().startswith("end") or \
            line.lstrip().startswith(".") or\
            ";" in line or \
            "__" in line:
                continue

            m = re.findall(exclude,line)

            if re.findall(exclude,line) or\
            re.findall(dd_exclude,line) or\
            re.findall(db_exclude,line) or\
            re.findall(dw_exclude,line):
                continue
            d = re.findall(include,line)
            if d:
                opc = d[0]
                print line
                opcode_seq.append(opc)
    return opcode_seq

def init():
    getApiCallList()

if __name__ == '__main__':
    init()
    analysisAlltoCsv("test/")
    #getOpcodeSequenceFromlib("workspace/test/lib/armeabi/libhotfix.arm.asm")