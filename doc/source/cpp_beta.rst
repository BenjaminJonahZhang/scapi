.. _cpp_beta:

SCAPI in C++ (Beta)
===================

Until recently SCAPI was a java-only library that in some cases wrapped native elements using JNI.
SCAPI is now supported and maintained in C++ version as well.
Roughly speacking, Java-SCAPI is great for fast development of application and for POCing cryptographic protocols.
However, when performance is a main concern, a c++ implementation might be more suitable.

This is still "work in progress" and should be considered as beta. 
There are few modules that exist in the java version but were still not ported to the C++ version.
The SCAPI team is working these days on expending the c++ implementation further.

.. _Linux:

The following explains how to install libscapi (SCAPI c++) on Ubuntu. For other Linux variants it should work as well with the appropriate adjustments.

Prerequisites on Linux
---------------------
Update and install git, gcc, and open ssl. On Ubuntu environment is should look like: ::

  $ sudo apt-get update
  $ sudo apt-get install -y git build-essential
  $ sudo apt-get install -y libssl-ocaml-dev libssl-dev  
  
Download and install boost (the last step might take some time. patience): ::
  
  $ wget -O boost_1_60_0.tar.bz2 http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.bz2/download
  $ tar --bzip2 -xf boost_1_60_0.tar.bz2
  $ cd boost_1_60_0
  $  ./bootstrap.sh
  $  ./b2 

More details about boost here: http://www.boost.org/doc/libs/1_60_0/more/getting_started/unix-variants.html  

Download and build libscap: ::

  $ cd ~
  $ git clone https://github.com/cryptobiu/libscapi.git
  $ cd libscapi
  $ make
  
Publish new libs: ::
  
  $ sudo ldconfig ~/boost_1_60_0/stage/lib/ ~/libscapi/install/lib/

Build and run test: ::

  $ cd ~/libscapi/test
  $ make
  $ ./tests.exe

Build and run simple samples: ::

  $ cd ~/libscapi/samples
  $ make
  $ ./simple_sha1.exe # should run and output some data
  $ ./simple_dlog.exe # should run and output some data

Build and run complex samples:
Semi-honset YAO: ::

  $ cd ~/libscapi/samples/YAO
  $ make

Edit file ~/libscapi/samples/Yao/YaoConfig.txt and update a section (e.g., AES) and choose this section in the 'section' param
for example verify that under AES the circuit_file path is updated to:
circuit_file = /home/ubuntu/libscapi/samples/assets/circuits/AES/NigelAes.txt

open two terminals and cd to: ~/libscapi/samples/Yao.
run in one terminal: ::
  
  $ ./App1.exe 1 ./YaoConfig.txt

And in the other: ::

  $ ./App1.exe 2 ./YaoConfig.txt

Another advanced example is the sigma protocols one: ::

  $ cd ~/libscapi/samples/sigma
  $ make
  
Optional: Edit the config file (should work using the default)
In one terminal: ::

  $ ./SigmaProtocolExample.exe 1 ./SigmaConfig.txt

And in the other: ::

  $ ./SigmaProtocolExample.exe 2 ./SigmaConfig.txt

.. _Further: 

Further Reading
---------------

For further reading - refer to the extensive Java documentation. 
The c++ implementation usally follows the same concept except when language specific need required some change.
 
  
.. _git: http://git-scm.org/
.. _gcc: http://gcc.gnu.org/
.. _boost: http://www.boost.org/doc/libs/1_60_0/more/getting_started/unix-variants.html
.. _cryptopp: https://www.cryptopp.com/
.. _OpenSSL: https://www.openssl.org/
.. _scapi_java: http://scapi.readthedocs.org/en/latest/install.html

