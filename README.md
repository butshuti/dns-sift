# README #
### Summary ###
DNSSift is a proof-of-concept for a host-based DNS firewall, originally developed to detect and block DNS tunneling. It can be used to analyze trends in DNS traffic and when configured with a valid profile it can be used to spot and block the encapsulation of illegal data transfers over DNS ports.
The current implementation was tested on clear-text DNS. Assuming efforts to encrypt DNS traffic will eventually make it to standardization, an ongoing attempt to analyze patterns in encrypted traffic is underway.

### Components ###
- The DNS packet parser, under src/dns
- An interface to a classifier, under src/classifier
- A GUI-based management interface to all the available features, under src/gui
  - Any classification method can be built and plugged in, based on the provided interfaces.

### How to build ###
####Dependencies####
1.  [libpcap-dev](http://sourceforge.net/projects/libpcap/): required for user-level packet capture.
2.  [libnetfilter-queue-dev](http://www.netfilter.org/projects/libnetfilter_queue/): required for accessing and processing packets queued by the kernel packet filter.
3.  [python2.7](https://www.python.org/): The demo classifier is an adaptive clustering-based classifier implemented in python.
4.  [numpy](http://www.numpy.org/) : for simple array manipulations
5.  [python-dev](https://docs.python.org/2/c-api/): This is currently used to glue together the packet parser (C) and the classifier and GUI (python)
6.  autoconf+automake (to configure and prepare the Makefile)
7. Optional: 
  [cherrypy](http://www.cherrypy.org/) (for visualizing DNS clusters in a web browser), 
  [matplotlib](http://matplotlib.org/)+[sklearn](http://scikit-learn.org/stable/) (for visualizing the feature map of a given training model)

####Building the app###
- If any changes were made to configure.ac, run autoreconf
- If necessary, link install-sh in the working directory to the install-sh script under the current version of automake (e.g: "ln /usr/share/automake-1.15/install-sh install-sh")
- Run **./configure & make** 

####Database configuration####
Running the app supposes the existence of a training set of normal DNS traffic. The data can be synthesized by running the app in training mode, which extracts features from network traffic and dumps them in a csv file. Using the management GUI, the collected csv files can be imported to the model directory for use by the classifier. It is important to collect a sample of 'NORMAL' DNS traffic for the target system to use as a model in order to minimize false alerts.
####How to run tests####
* The management GUI allows you to load csv file containing captured DNS traffic and test it on a loaded model (current the format of the capture must be according to this tools feature point output). To load a csv file into the model directory, right click the directory tag (normal/anomalous) and follow the contextual menus.
* Future versions will support direct replay of pcap captures as well.
####Deployment instructions####
The program is distributed as a C extension to the python interpreter, so it must be deployed as a python package, after building the extension. The following are the required steps:

* Build the application (as described above in 'Building the app')
* Run **make install** as root.
* Done (now the package will be ready system-wide to be used as a python package).
* To start the program, run **python -m dnssift.interface**
* **python -m dnssift.interface** will load a management GUI (as in the image below) with options to start the main filter daemon, to configure DNS profile models, or to start the cherrypy web engine to look at live reports.

![dnssift-tk.png](https://bitbucket.org/repo/jj6x4X/images/4213329108-dnssift-tk.png)
### Contribution guidelines ###

* Writing tests: future
* Code review: future

### Who do I talk to? ###

* Research team: [Logix Labs](http://logix.rw/labs).