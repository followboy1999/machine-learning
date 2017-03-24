#!/usr/bin/python
#--- coding=utf-8 ---

import sys
import md5
import os
from random import *
import pandas as pd
import shutil
from config import *

def getApkMd5(filename):
    m = md5.new()  
    f = open(filename,'rb')  
    maxbuf = 8192  
    while 1:  
        buf = f.read(maxbuf)  
        if not buf:  
            break  
        m.update(buf)
    f.close()
#    print m.hexdigest()
    return m.hexdigest()

'''
1 : commonfile
2 : malwarefile
'''
def generateTrainLabel():
    labels = {}

    commonfile = basepath + "/common"
    trainfile = basepath + "/train"
    files = os.listdir(commonfile)
    for _ in files:
        if _ == '.DS_Store':
            continue
        #print "filename:"+_
        filename = os.path.join(commonfile,_)
        #print filename
        idname = getApkMd5(filename)
        filename2 = os.path.join(trainfile,idname)  
        shutil.copy(filename,filename2+".apk")  
        labels[idname] = "1"

    malwarefile = basepath + "/malware"
    files = os.listdir(malwarefile)
    for _ in files:
        if _ == '.DS_Store':
            continue
        #print "filename:"+_
        filename = os.path.join(malwarefile,_)
        #print filename
        idname = getApkMd5(filename)
        filename2 = os.path.join(trainfile,idname)
        shutil.copy(filename,filename2+".apk")  
        labels[idname] = "2"

    labels = sorted(labels.iteritems(), key=lambda d:d[1])
#    print labels
    opd = pd.DataFrame(labels)
    opd = opd.reset_index(drop=True)
    print opd
    opd.to_csv('trainlabel.csv', encoding='utf-8', index=False)


def generateSubTrainLabel():
    rs = Random()
    rs.seed(1)

    trainlabels = pd.read_csv('trainlabel.csv')
    fids = []
    opd = pd.DataFrame()
    for clabel in range (1,3):
        mids = trainlabels[trainlabels.Class == clabel]
        mids = mids.reset_index(drop=True)

        rchoice = [rs.randint(0,len(mids)-1) for i in range(10)]
        print rchoice   

        rids = [mids.loc[i].Id for i in rchoice]
        fids.extend(rids)
        opd = opd.append(mids.loc[rchoice])
        
    print len(fids)
    opd = opd.reset_index(drop=True)
    print opd
    opd.to_csv('subtrainlabel.csv', encoding='utf-8', index=False)
'''
    sbase = basepath + '/train/'
    tbase = basepath + '/subtrain/'

    for fid in fids:
        fnames = ['{0}.apk'.format(fid),'{0}.bytes'.format(fid)]
        for fname in fnames:
            cspath = sbase + fname
            ctpath = tbase + fname
            shutil.copy(cspath,ctpath)
'''   

if __name__ == '__main__':
    '''
    if len(sys.argv) < 2:
        exit(1)
    print sys.argv
    getApkMd5(sys.argv[1])
    '''
    generateTrainLabel()