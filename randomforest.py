#!/usr/bin/python
#------ coding = utf-8 --------

from sklearn.ensemble import RandomForestClassifier as RF
from sklearn import cross_validation
#from sklearn.metrics import confusion_matrix
import pandas as pd
import sys
from sklearn import metrics

def measure_performance(X,y,clf, show_accuracy=True, 
                        show_classification_report=True, 
                        show_confusion_matrix=True):
    y_pred=clf.predict(X)   
    if show_accuracy:
        print "Accuracy:{0:.3f}".format(metrics.accuracy_score(y,y_pred)),"\n"

    if show_classification_report:
        print "Classification report"
        print metrics.classification_report(y,y_pred),"\n"
        
    if show_confusion_matrix:
        print "Confusion matrix"
        print metrics.confusion_matrix(y,y_pred),"\n"
        



if len(sys.argv)<2:
    print "randomforest.py {api,opcode,permiss,all}"
    exit(1)

param = sys.argv[1]
trainLabel = pd.read_csv('trainlabel.csv')
#print trainLabel

if param == 'api':
    api_trainfeature = pd.read_csv("result/api3gramfeature.csv")
    #print api_trainfeature
    train = pd.merge(api_trainfeature,trainLabel,on='Id')
    train = train.fillna(0)
    #print train
    train.to_csv("train_api.csv",index=False)   
elif param == 'opcode':
    opc_trainfeature = pd.read_csv("result/op3gramfeature.csv")
    train = pd.merge(trainLabel,opc_trainfeature,on='Id')
    train = train.fillna(0)
    train.to_csv("train_opcode.csv",index=False)   
elif param == 'permiss':
    permiss_trainfeature = pd.read_csv("result/permission1gramfeature.csv")
    train = pd.merge(trainLabel,permiss_trainfeature,on='Id')
    train = train.fillna(0)
    train.to_csv("train_per.csv",index=False) 
    #print train  
elif param == 'all':
    api_trainfeature = pd.read_csv("result/api3gramfeature.csv")
    opc_trainfeature = pd.read_csv("result/op3gramfeature.csv")
    permiss_trainfeature = pd.read_csv("result/permission1gramfeature.csv")
    tmp1_trainfeature = pd.merge(api_trainfeature,opc_trainfeature,on='Id')
    tmp2_trainfeature = pd.merge(tmp1_trainfeature,permiss_trainfeature,on='Id')
    #print tmp2_trainfeature

    train = pd.merge(trainLabel,tmp2_trainfeature,on='Id')
    train = train.fillna(0)
    #print train
    #train.to_csv("train_all.csv",index=False)   

else:
    print "randomforest.py {api,opcode,permiss,all}"
    exit(1)

#train.to_csv("train.csv",index=False)    
#print train
labels = train.Class
train.drop(["Class","Id"], axis=1, inplace=True)
train = train.as_matrix()

X_train, X_test, y_train, y_test = cross_validation.train_test_split(train,labels,test_size=0.4)

srf = RF(n_estimators=150, n_jobs=-1)
clf = srf.fit(X_train,y_train)
print srf.score(X_test,y_test)
measure_performance(X_test,y_test,clf, show_classification_report=True, show_confusion_matrix=True)
# y_pred = srf.predict(X_test)
# print confusion_matrix(y_test, y_pred)
