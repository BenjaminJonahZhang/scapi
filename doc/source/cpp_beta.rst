.. _cpp_beta:

Introduction
============

Until recently Scapi was a java-only library that in some cases warpped native constructs using JNI.
We recently started to implement a c++ version of Scapi.
Java scapi is great for fast development of application and protocols that need cryptographic constract.
However, when performance is the main concern a c++ implementation might be more suitable.

This is still "work in progress" and should be considered as beta. 
Currently the main part that was implemented is the "primitive layer" of scapi
but the scapi team is working these days on expending the c++ implementaion further.

Installation
============
C++ Scapi is very simple to build, and link against.

.. _Linux:

Prequisities on Linux
---------------------
There are a few prerequisites you must install before being able to compile scapi on your machine. 
You'll need to install:

1. Install `git`_
2. Install the `gcc`_ compiler environment: `gcc`, `make`, `ar`, `ld`, etc.
3. Install `boost`_
4. Install `cryptopp`_
5. Install `OpenSSL`_

On Ubuntu environment is should look like: ::

  $ sudo apt-get install build-essential
  $ sudo apt-get install git
  $ sudo apt-get install boost libboost-all-dev
  $ sudo apt-get install libcrypto++9 libcrypto++9-dbg libcrypto++-dev
  $ sudo apt-get install libssl-ocaml-dev libsslcommon2-dev

Installing Scapi from Source (On UNIX-based Operating Systems)
--------------------------------------------------------------

In order to install scapi: ::

  $ git clone git://github.com/cryptobiu/scapi.git
  $ cd scapi/src/cpp/ScapiCpp
  $ make
  
Running the tests
---------------------------------------------------
Compiling c++ scapi create file called ``ScapiTests.exe``. Exceuting this file with run all the c++ test.
All of them should pass and you should get a notification about it.

Likning against the scapi lib
-----------------------------
We inlcuded few sample files for quick start: ::

  $ cd scapi/src/cpp/CodeExamples
  $ g++ -std=c++11 -static simple_dlog.cpp ../ScapiCpp/scapi.a -lcrypto -lcrypto++ -ldl -lc
  $ ./a.out

Running the exectuble that was created (``a.out``) should produce few prints after using the OpenSSL implementation of Dlog. 

Further Reading
---------------

For furthre reading - refer to the extensive Java documentation. 
The c++ implementation usally follows the same concept except when language specific need required some change.
 
  
.. _git: http://git-scm.org/
.. _gcc: http://gcc.gnu.org/
.. _boost: http://www.boost.org/
.. _cryptopp: https://www.cryptopp.com/
.. _OpenSSL: https://www.openssl.org/
