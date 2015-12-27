# README #
### Summary ###
DNSSift is a proof-of-concept for a host-based DNS firewall, originally developed to detect and block DNS filtering.
### Components ###
- The DNS packet parser, under src/dns
- An interface to a classifier, under src/classifier
  - Any classification method can be build and plugged in, based on the provided interface.

### How to build ###
####Dependencies####
1.  [libpcap-dev](http://sourceforge.net/projects/libpcap/): required for user-level packet capture.
2.  [libnetfilter-queue-dev](http://www.netfilter.org/projects/libnetfilter_queue/): required for accessing and processing packets packets queued by the kernel packet filter.
3.  [python](https://www.python.org/: The demo classifier is an adaptive clustering-based classifier implemented in python.
  - [numpy](http://www.numpy.org/) : for simple array manipulations
4.  autoconf (to configure and prepare the Makefile)

####Building the app###
- Run
  - If necessary, run autoreconf
  - **./configure & make**

####Database configuration####
Running the app supposes the existence of a training set of normal DNS traffic, provided under src/classifier/test_data/dns_tunneling. The data can be synthesized by running the app in training mode, which extracts features from network traffic and dumps them in a file. It is important to consider the assumption that THE TRAINING DATA IS CONSIDERED FREE OF ATTACK DATA, based on the nature of the current classifier.
####How to run tests####
* Coming soon
####Deployment instructions####
* Not yet ready for deployment!

### Contribution guidelines ###

* Writing tests: future
* Code review: future

### Who do I talk to? ###

* Research team: [http://logix.rw/labs](Logix Labs).