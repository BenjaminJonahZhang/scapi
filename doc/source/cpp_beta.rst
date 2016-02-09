.. _cpp_beta:

SCAPI in C++ (Beta)
===================

Until recently Scapi was a java-only library that in some cases wrapped native elements using JNI.
We recently started to implement a c++ version of Scapi.
Java-Scapi is great for fast development of application and for POCing cryptographic protocols.
However, when performance is a main concern, a c++ implementation might be more suitable.

This is still "work in progress" and should be considered as beta. 
Currently the main part that was implemented is the "primitive layer" of scapi
but the scapi team is working these days on expending the c++ implementaion further.

.. _Linux:

Prerequisites on Linux
---------------------
There are a few prerequisites you must install before being able to compile scapi on your machine. 
First you'll need to intall scapi for java first - see `scapi_java`_
You'll need to install:

1. Install `git`_
2. Install the `gcc`_ compiler environment: `gcc`, `make`, `ar`, `ld`, etc.
3. Install `boost`_ make sure you are installing version 1_60. Follow instructions in the link. boost lib should be installed under ~/boost_1_60_0. Notice - there is no need to build boost - only the src is enough
4. Install `cryptopp`_
5. Install `OpenSSL`_

On Ubuntu environment is should look like: ::

  $ sudo apt-get update
  $ sudo apt-get install build-essential
  $ sudo apt-get install git
  $ sudo apt-get install libcrypto++9v5 libcrypto++9v5-dbg
  $ sudo apt-get install libssl-ocaml-dev libssl-dev  
  $ cd ~ 
  $ wget http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.bz2/download
  $ tar -xvf ./download
  
  
.. _Source:

Installing Scapi from Source (On UNIX-based Operating Systems)
--------------------------------------------------------------

In order to install scapi: ::

  $ git clone git://github.com/cryptobiu/scapi.git
  $ git submodule init
  $ git submodule update
  $ cd scapi/src/cpp/ScapiCpp
  $ make
  
.. _Tests:

Running the tests
-----------------

Go to the scapi_test folder and run make and then execute test.exe: ::

  $ cd ~/scapi/src/cpp/scapi_tests
  $ make
  $ ./test.exe

.. _Link:

Likning against the scapi lib
-----------------------------

Can look at the different make file for reference. We inlcuded few sample files for quick start: ::

  $ cd scapi/src/cpp/CodeExamples
  $ make
  $ ./simple_dlog.exe
  $ ./simple_sha1.exe

More advanced examples can be found under Yao folder. This example require two instance running on the same machine. To compile and run: ::

  $ cd scapi/src/cpp/CodeExamples/Yao
  $ make
  $ ./App1.exe 1

and in another instance: ::
  
  $ ./App1.exe 2

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
.. _scapi_java: https://github.com/cryptobiu/scapi/edit/master/doc/source/install.rst

