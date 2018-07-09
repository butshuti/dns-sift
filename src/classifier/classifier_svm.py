from sklearn import svm
from classifier import ClassifierInterface


class SVMClassifierInterface(ClassifierInterface):
    def __init__(self):
        super(SVMClassifierInterface, self).__init__("SVM")
        self.label_map = {}

    def get_score(self, point):
        return self.classifier.predict([point])[0]

    def classify_with_label(self, point, tag):
        return self.get_label(self.classifier.predict([point])[0])

    def classify_many(self, arr):
        return map(self.get_label, self.classifier.predict([x[0] for x in arr]))

    def train_classifier(self, training_samples):
        self.classifier = svm.OneClassSVM(nu=0.01, kernel="rbf", gamma=0.00001)
        self.classifier.fit([x[0] for x in training_samples])
        labels = {}
        for x in training_samples:
            labels[x[1][1]] = labels.get(x[1][1], {})
            score = self.get_score(x[0])
            labels[x[1][1]][score] = labels[x[1][1]].get(score, 0) + 1
        labels = {x: max(labels[x]) for x in labels}
        for x in labels:
            self.label_map[labels[x]] = x
        return self.classifier

    def get_label(self, val):
        return self.label_map.get(val, "UNKNOWN")


if __name__ == "__main__":
    SVMClassifierInterface().run_main(False)
