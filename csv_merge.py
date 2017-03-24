#!/usr/bin/python

import pandas as pd

trainLabel_com = pd.read_csv('trainlabel_com.csv')
trainLabel_mal = pd.read_csv('trainlabel_mal.csv')

trainLabel = pd.merge(trainLabel_com,trainLabel_mal)
print trainLabel
trainLabel.to_csv("trainLabel1.csv",index=False)    
