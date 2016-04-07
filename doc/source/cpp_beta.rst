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

Installing SCAPI - Linux
---------------------
The following explains how to install libscapi (SCAPI c++) on Ubuntu. For other Linux variants it should work as well with the appropriate adjustments.

Prerequisites
~~~~~~~~~~~~

Update and install git, gcc, gmp, and open ssl. On Ubuntu environment is should look like: ::

  $ sudo apt-get update
  $ sudo apt-get install -y git build-essential
  $ sudo apt-get install -y libssl-ocaml-dev libssl-dev 
  $ sudo apt-get install -y libgmp3-dev
  
Download and install boost (the last step might take some time. patience): ::
  
  $ wget -O boost_1_60_0.tar.bz2 http://sourceforge.net/projects/boost/files/boost/1.60.0/boost_1_60_0.tar.bz2/download
  $ tar --bzip2 -xf boost_1_60_0.tar.bz2
  $ cd boost_1_60_0
  $  ./bootstrap.sh
  $  ./b2 

More details about boost here: http://www.boost.org/doc/libs/1_60_0/more/getting_started/unix-variants.html  

Building libscapi and publishing libs
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Download and build libscapi: ::

  $ cd ~
  $ git clone https://github.com/cryptobiu/libscapi.git
  $ cd libscapi
  $ make
  
Publish new libs: ::
  
  $ sudo ldconfig ~/boost_1_60_0/stage/lib/ ~/libscapi/install/lib/

Building and Running the Tests
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

In order to build and run tests: ::

  $ cd ~/libscapi/test
  $ make
  $ ./tests.exe

Samples
~~~~~~~

Build and run the samples program: ::

  $ cd ~/libscapi/samples
  $ make

In order to see all available samples: ::

 $ ./libscapi_example.exe
 
In order to run simple examples (dlog or sha1): ::

 $ ./libscapi_example.exe dlog 
 $ ./libscapi_example.exe sha1
 
You should get some print outs if everything works well.

In order to run the CommExample. Open two terminals. In the first run: ::
 
 $ ./libscapi_example.exe comm 1 Comm/CommConfig.txt
 
And in the other run: ::

 $ ./libscapi_example.exe comm 2 Comm/CommConfig.txt

In order to run Semi-honset YAO, run in the first terminal: ::

  $ ./libscapi_example.exe yao 1 Yao/YaoConfig.txt

And in the second: ::
  
  $ ./libscapi_example.exe yao 2 Yao/YaoConfig.txt
  
Finally in order to run the Sigma example - in the first terminal run: ::

  $ ./libscapi_example.exe sigma 1 SigmaPrototocls/SigmaConfig.txt

And in the second terminal: ::

 $ ./libscapi_example.exe sigma 1 SigmaPrototocls/SigmaConfig.txt

You can edit the config file in order to play with the different params in all examples.

.. _Windows:

Installing SCAPI - Windows
---------------------

Installing scapi on windows will require git client and Visual Studio IDE. We tested it with VS2015.

Prerequisites: 

1. Download and install open ssl for windows: https://slproweb.com/products/Win32OpenSSL.html (choose 64bit not light)
2. Download and install boost binaries for windos: https://sourceforge.net/projects/boost/files/boost-binaries/1.60.0/ choose 64 bit version 14

The windows solutions assume that boost is installed at ``C:\local\boost_1_60_0`` and that OpenSSL at: ``C:\OpenSSL-Win64``


Pull libscapi from GitHub. For convenient we will assume that libscapi is located at: ``c:\code\scapi\libscapi```. If it is located somewhere eles then the following paths should be adjusted accrodingly.

1. Build Miracl for windows 64:
	A. Open solution MiraclWin64.sln at: ``C:\code\libscapi\lib\MiraclCompilation``
	B. Build the solution once for debug and once for release
2. Build OTExtension for window 64:
	A. Open solution OTExtension.sln at ``C:\code\libscapi\lib\OTExtension\Win64-sln``
	B. Build solution once for debug and once for release
3. Build GarbledCircuit project
	A. Open solution ScGarbledCircuitWin64.sln at ``C:\code\libscapi\lib\ScGarbledCircuit\ScGarbledCircuitWin64``
	B. Build solution once for debug and once for release
4. Build the NTL solution:
  	A. Open solution NTL-WIN64.sln at ``C:\code\libscapi\lib\NTL\windows\NTL-WIN64``
  	B. Build solution once for debug and once for release
5. Build Scapi Solution including examples and test:
	A. Open solution ScapiCpp.sln at ``C:\code\libscapi\windows-solutions\scapi-sln``
	B. Build solution once for debug and once for release - (as needed)
	
6. Run tests.
	A. Go to ``C:\code\libscapi\windows-solutions\scapi-sln\x64\debug``
	B. run ./scapi_tests.exe and make sure all is green
7. Run example:
	A. open two terminals
	B. in both of them go to: ``C:\code\libscapi\windows-solutions\scapi-sln\x64\debug``
	C. In the first run:  ``"code examples.exe" 1 ..\..\..\..\samples\SigmaProtocols\SigmaConfig.txt``
	   In the second run: ``"code examples.exe" 2 ..\..\..\..\samples\SigmaProtocols\SigmaConfig.txt``
	D. Make sure you get success notice

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

