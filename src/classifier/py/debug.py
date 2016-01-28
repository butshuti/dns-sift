import matplotlib.pyplot as plt

DEBUG = True
def debug_set(on_off):
    global DEBUG
    DEBUG = on_off
    return

def debug_print(*args):
    global DEBUG
    if DEBUG:
        print(args)
        
def debug_plot(points, mark='c.'):
    for point in points:
        plt.plot(point[0], point[1], mark)
    plt.draw()
    plt.show()