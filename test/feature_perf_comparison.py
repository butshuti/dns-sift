import numpy as np
import matplotlib.pyplot as plt
from sklearn import datasets

from sklearn.model_selection import train_test_split
from sklearn.linear_model import SGDClassifier, Perceptron
from sklearn.linear_model import PassiveAggressiveClassifier
from sklearn.linear_model import LogisticRegression

import dnssift.configutils as cfg
from dnssift.data.dns_tunneling import loader

def reduceDim(arr):
    return arr

def sliceArr(arr, start, siz):
    return arr[:]

cfgParams = cfg.parseConf()
MODEL_DATA_DIR = cfgParams["model_data_dir"]
fs_len = 10
fs_overlap = 5

heldout = [0.95, 0.90, 0.75, 0.50, 0.01]
rounds = 20

ds = loader.DataSet(MODEL_DATA_DIR)
test_samples = ds.test_samples
orig_fs_len = len(test_samples[0][0])
offs = 0
last_offs = orig_fs_len-(fs_len-fs_overlap)
trials = [((0, orig_fs_len-1), "ALL")]
while offs < last_offs:
    trials.append(((offs, offs+fs_len), str((offs, offs+fs_len))))
    offs += fs_len - fs_overlap
print("Comparing {} subsets of {}/{}".format(len(trials), fs_len, orig_fs_len))
print("Subsets", [x[1] for x in trials])
classifier = PassiveAggressiveClassifier(loss='squared_hinge', C=1.0)     
xx = 1. - np.array(heldout)
for t in trials:
    X = np.array([sliceArr(x[0], t[0][0], t[0][1]) for x in test_samples])
    Y = np.array([x[1][1] for x in test_samples])     
    print("training from subset %s" % t[1])
    rng = np.random.RandomState(42)
    yy = []
    for i in heldout:
        yy_ = []
        for r in range(rounds):
            X_train, X_test, y_train, y_test = train_test_split(X, Y, test_size=i, random_state=rng)
            classifier.fit(X_train, y_train)
            y_pred = classifier.predict(X_test)
            yy_.append(100 * (1 - np.mean(y_pred == y_test)))
        yy.append(np.mean(yy_))
    plt.plot(xx, yy, label=t[1])

plt.legend(loc="upper right")
plt.xlabel("Proportion train")
plt.ylabel("% Test Error Rate")
plt.show()