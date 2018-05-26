import sklearn.ensemble
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import sklearn.cross_validation
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_selection import SelectFromModel
from sklearn.cross_validation import train_test_split
from xgboost import XGBClassifier
from sklearn.metrics import accuracy_score
from sklearn.svm import LinearSVC
from sklearn.metrics import confusion_matrix
from sklearn.pipeline import Pipeline
from sklearn.tree import DecisionTreeClassifier
import argparse
import pickle
import sys
import os
from sklearn.externals import joblib
from sklearn import svm
#Author: Flora

df = pd.read_csv('data/ClaMP_Raw-5184+100_raw.csv', index_col=0, parse_dates=True)
df.replace(np.nan, 0, inplace=True) 
no_label = list(df.columns.values)
no_label.remove('label')

X = df.as_matrix(no_label)
y = np.array(df['label'].tolist())

# X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=my_tsize, random_state=my_seed)
#     clf.fit(X_train, y_train)

############Extra Tree classifier  ####################################
clf_extra = ExtraTreesClassifier().fit(X,y)
###########Random Forest classifier ###################################
#clf_random = RandomForestClassifier().fit(X,y)
#######################################################################
#lsvc = LinearSVC(C=0.01, penalty="l1", dual=False).fit(X, y)
##################################################################


model = SelectFromModel(clf_extra, prefit=True)
X_new = model.transform(X)
nb_features = X_new.shape[1]

indices = np.argsort(clf_extra.feature_importances_)[::-1][:nb_features]
for f in range(nb_features):
	print("%d. feature %s (%f)" % (f + 1, df.columns[2+indices[f]], clf_extra.feature_importances_[indices[f]]))
model = SelectFromModel(lsvc, prefit=True)
indices = np.argsort(model.feature_importances_)[::-1][:nb_features]
for f in range(nb_features):
	print("%d. feature %s (%f)" % (f + 1, df.columns[2+indices[f]], lsvc.feature_importances_[indices[f]]))

model = SelectFromModel(clf_random, prefit=True)
X_new = model.transform(X)
indices = np.argsort(clf_random.feature_importances_)[::-1][:nb_features]
for f in range(nb_features):
	print("%d. feature %s (%f)" % (f + 1, df.columns[2+indices[f]], clf_random.feature_importances_[indices[f]]))

features = []
for f in np.argsort(clf_extra.feature_importances_)[::-1][:nb_features]:
	features.append(df.columns[2+f])

print features
print len(features)

plt.title('Feature importances')
plt.barh(range(len(indices)), clf_extra.feature_importances_[indices],color = 'r', align = 'center')
#plt.yticks(range(len(indices)),nb_features)
plt.xlabel('Relative Importance')
plt.show()


#####################################################################################

clf = sklearn.ensemble.RandomForestClassifier(n_estimators=50)
clf_g = sklearn.ensemble.GradientBoostingClassifier(n_estimators=50)
clf_x = XGBClassifier()
clf_d = sklearn.tree.DecisionTreeClassifier(max_depth=10)
clf_c = svm.SVC(kernel='linear', C=1)


my_seed = 123
my_tsize = .2 # 20%

X_train, X_test, y_train, y_test = train_test_split(X_new, y, test_size=my_tsize, random_state=my_seed)
print X_new.shape
clf_x.fit(X_train, y_train)
y_pred = clf_x.predict(X_test)
score = clf_x.score(X_test, y_test)
##########################################################################################
print "Cross validation"
clf_c.fit(X_train, y_train)
print "scores: %f %%" % (clf_c.score(X_test, y_test)*100)
############################################################################################
print "XG BOOST"
print "score: %f %%" % (score*100)
res = clf_x.predict(X_test)
mt = confusion_matrix(y_test, res)
print "False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100)
print 'False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100))

#############################################################################################
print "gradientBoost"
clf_g.fit(X_train, y_train)
y_pred = clf_g.predict(X_test)
score = clf_g.score(X_test, y_test)
print "GradientBoosting"
print "score: %f %%" % (score*100)
res = clf_g.predict(X_test)
mt = confusion_matrix(y_test, res)
print "False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100)
print 'False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100))

####################################################################################################
clf.fit(X_train, y_train)
y_pred = clf.predict(X_test)
score = clf.score(X_test, y_test)
print "Random forest"
print "score: %f %%" % (score*100)
res = clf.predict(X_test)
mt = confusion_matrix(y_test, res)
print "False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100)
print 'False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100))
#########################################################################################################
clf_d.fit(X_train, y_train)
y_pred = clf_d.predict(X_test)
score = clf_d.score(X_test, y_test)
print "Decision tree"
print "score: %f %%" % (score*100)
res = clf_d.predict(X_test)
mt = confusion_matrix(y_test, res)
print "False positive rate : %f %%" % ((mt[0][1] / float(sum(mt[0])))*100)
print 'False negative rate : %f %%' % ( (mt[1][0] / float(sum(mt[1]))*100))
#################################################################################
print('Saving algorithm and feature list in classifier directory...')
joblib.dump(clf, 'classifier.pkl')

open('features.pkl', 'w').write(pickle.dumps(features))
print('Saved')
