import numpy as np
from sklearn import svm
import matplotlib.pyplot as plt
from dnssift import classifier as dnsclassifier
import time, matplotlib, random

learntXMax = -1000.0
learntYMax = -1000.0
learntXMin = 1000.0
learntYMin = 1000.0

def sigmoid(x):
    return 1 / (1 + np.exp(-x))

def refitMinMax(x, y):
    global learntXMax, learntXMin, learntYMax, learntYMin
    if learntXMax < x:
        learntXMax = x
    if learntYMax < y:
        learntYMax = y 
    if learntXMin > x:
        learntXMin = x
    if learntYMin > y:
        learntYMin = y 

def reduceDim(arr, scale=0.1, offset=0):
    inDim = len(arr)
    if inDim <= 20: return np.array(arr)
    x = 0
    y = 0
    dimRange = range(inDim)
    for i in dimRange[0::2]:
        x |= int(arr[i])<<i
    for i in dimRange[1::2]:
        y |= int(arr[i])<<i
    refitMinMax(x,y)
    return np.array([x,y])

clf = svm.OneClassSVM(nu=0.01, kernel="rbf", gamma=0.0001)
"""Load training data set"""
from dnssift.data.dns_tunneling import loader
ds = loader.DataSet()
#extra_pos = ds.loadDs("/home/hazirex/dump/datapoints_pos.csv", "P")
#extra_neg = ds.loadDs("/home/hazirex/dump/datapoints_neg.csv", "N")
"""Generate model"""
pos_samples = [[reduceDim(o[0]), o[1]] for o in ds.test_samples if o[1][1] == 'P']
neg_samples = [[reduceDim(o[0]), o[1]] for o in ds.test_samples if o[1][1] == 'N']
#pos_samples.extend([[reduceDim(o[0]), o[1]] for o in extra_pos])
#neg_samples.extend([[reduceDim(o[0]), o[1]] for o in extra_neg])
training_samples = [[reduceDim(o[0]), o[1]] for o in ds.training_samples if o[1][1] == 'P']
pos_training_samples = [training_samples[i] for i in random.sample(range(len(training_samples)), len(training_samples))]
pos_training_samples = pos_training_samples[0::10]

print("Training sample size: {} out of {}; #pos: {}; #neg: {}".format(len(pos_training_samples), 
                                                                      len(ds.training_samples), len(pos_samples), len(neg_samples)))
"""Start SVM tests"""
svm_train_sample = np.array([o[0] for o in pos_training_samples])
svm_pos_test_sample = np.array([o[0] for o in pos_samples])
svm_neg_test_sample = np.array([o[0] for o in neg_samples])
startTime = time.time()
clf.fit(svm_train_sample)
endTime = time.time()
pred_train = clf.predict(svm_train_sample)
pred_pos = clf.predict(svm_pos_test_sample)
pred_test = clf.predict(svm_neg_test_sample)
svm_train_pred_error = pred_train[pred_train == -1].size
svm_pos_pred_error = pred_pos[pred_pos == -1].size
svm_neg_pred_error = pred_test[pred_test == 1].size
print("SVM pos_error: {}% -- ({} / {})".format(round(100.0*svm_pos_pred_error/len(pos_samples), 2),
                                                 svm_pos_pred_error, len(pos_samples)))
print("SVM neg_error: {}% -- ({} / {})".format(round(100.0*svm_neg_pred_error/len(neg_samples), 2), 
                                                 svm_neg_pred_error, len(neg_samples)))
print("SVM training time: {} seconds".format(endTime-startTime))

"""Start DNSSIF tests"""
dnsC = dnsclassifier.Classifier(True)
startTime = time.time()
dnsC.train(pos_training_samples, len(pos_training_samples)/5)
endTime = time.time()
pos_test = dnsC.classify_many(pos_samples)
neg_test = dnsC.classify_many(neg_samples)
pos_pred_error = len([p for p in pos_test if p == 'N'])
neg_pred_error = len([p for p in neg_test if p == 'P'])
print("DNSSIFT pos_error: {}% -- ({} / {})".format(round(100.0*pos_pred_error/len(pos_samples), 2),
                                                 pos_pred_error, len(pos_samples)))
print("DNSSIFT neg_error: {}% -- ({} / {})".format(round(100.0*neg_pred_error/len(neg_samples), 2), 
                                                 neg_pred_error, len(neg_samples)))
print("DNSSIF training time: {} seconds".format(endTime-startTime))
"""
learntXMin, learntXMax = (learntXMin-50, learntXMax+50)
learntYMin, learntYMax = (learntYMin-50, learntYMax+50)
xx, yy = np.meshgrid(np.linspace(learntXMin, learntXMax, 500), np.linspace(learntYMin, learntYMax, 500))
# plot the line, the points, and the nearest vectors to the plane
Z = clf.decision_function(np.c_[xx.ravel(), yy.ravel()])
Z = Z.reshape(xx.shape)
plt.title("Novelty Detection")
plt.contourf(xx, yy, Z, levels=np.linspace(Z.min(), 0, 7), cmap=plt.cm.Blues_r)
a = plt.contour(xx, yy, Z, levels=[0], linewidths=2, colors='orange')
plt.contourf(xx, yy, Z, levels=[0, Z.max()], colors='yellow')
b1 = plt.scatter(svm_train_sample[:, 0], svm_train_sample[:, 1], c='white')
b2 = plt.scatter(svm_pos_test_sample[:, 0], svm_pos_test_sample[:, 1], c='green')
c = plt.scatter(svm_neg_test_sample[:, 0], svm_neg_test_sample[:, 1], c='red')
plt.axis('tight')
plt.xlim((learntXMin, learntXMax))
plt.ylim((learntYMin, learntYMax))
plt.legend([a.collections[0], b1, b2, c],
           ["learned frontier", "training observations",
            "new regular observations", "new abnormal observations"],
           loc="upper left",
           prop=matplotlib.font_manager.FontProperties(size=11))
plt.xlabel(
    "error train: %d%% ; errors novel regular: %d%% ; "
    "errors novel abnormal: %d%%"
    % (round(100.0*svm_train_pred_error/len(pos_training_samples), 2), 
       round(100.0*svm_pos_pred_error/len(pos_samples), 2), 
       round(100.0*svm_neg_pred_error/len(neg_samples), 2)))
plt.show()"""