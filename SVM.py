from sklearn import svm
from sklearn.externals import joblib
import numpy as np
from vector import getData
import matplotlib.pyplot as plt
import matplotlib
from sklearn.model_selection import learning_curve, ShuffleSplit
import time


def plot_learn_curve(estimator, title, X, y, ylim=None, cv=None, n_jobs=1, train_sizes=np.linspace(.1, 1., 5)):
    matplotlib.rcParams['font.sans-serif'] = ['Simhei']
    matplotlib.rcParams['font.family'] = 'sans-serif'
    plt.title(title)
    if ylim is not None:
        plt.ylim(*ylim)
    plt.xlabel("train exs")
    plt.ylabel("Score")
    train_sizes, train_scores, test_scores = learning_curve(
        estimator, X, y, cv=cv, n_jobs=n_jobs, train_sizes=train_sizes)
    train_score_mean = np.mean(train_scores, axis=1)
    train_score_std = np.std(train_scores, axis=1)
    test_score_mean = np.mean(test_scores, axis=1)
    test_score_std = np.std(test_scores, axis=1)
    plt.grid()

    plt.fill_between(train_sizes, train_score_mean - train_score_std,
                     train_score_mean + train_score_std, alpha=0.1, color='r')
    plt.fill_between(train_sizes, test_score_mean - test_score_std,
                     test_score_mean + test_score_std, alpha=0.1, color='g')
    plt.plot(train_sizes, train_score_mean, 'o-', color='r', label='train score 训练得分')
    plt.plot(train_sizes, test_score_mean, 'o-', color='g', label='cross-validation score 交叉验证得分')

    plt.legend(loc='best')
    return plt


if __name__ == '__main__':
    train_data, train_label, test_data, test_label = getData(threshold=200)

    clf = svm.SVC(gamma='scale', C=0.8, decision_function_shape='ovr', kernel='rbf')
    # 训练
    clf.fit(train_data, train_label)
    print('训练数据集得分： %f.' % clf.score(train_data, train_label))
    # joblib.dump(clf, './out/model/SVM.pkl')

    # 绘制学习图像
    plt.figure(figsize=(9, 4), dpi=100)
    title = 'Learning Curve for Drebin'
    start = time.clock()
    cv = ShuffleSplit(n_splits=10, test_size=.4, random_state=0)
    plot_learn_curve(clf, title, train_data, train_label, cv=cv, n_jobs=8)
    plt.savefig('./out/learning_process.png')
    print('耗时: %f s.' % (time.clock() - start))

    # # 预测
    print('预测正确率 %f .' % clf.score(test_data, test_label))
