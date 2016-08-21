from numpy import random, load, exp
from pybrain.structure.modules import KohonenMap
import matplotlib.pyplot as plt

def sigmoid(x):
    return 1 / (1 + exp(-x))

som = KohonenMap(6, 5)

data  = load("../data/test.ft")
observations = data['arr_0']

plt.ion()
p = plt.plot(som.neurons[:,:,0].flatten(), som.neurons[:,:,1].flatten(), 's')

for i in range(len(observations)):
    # one forward and one backward (training) pass
    som.activate(observations[i])
    som.backward()

    # plot every 100th step
    if i % 100 == 0:
    	print(som.neurons[:,:,0].flatten())
    	print(som.neurons[:,:,0])
    	print("==============")
        p[0].set_data(sigmoid(som.neurons[:,:,0].flatten()), sigmoid(som.neurons[:,:,1]).flatten())
        plt.draw()