=======================
The Communication Layer
=======================

.. contents::

----------------------
Communication Design
----------------------

The communication layer provides communication services for any interactive cryptographic protocol. The basic communication channel is plain (unauthenticated and unencrypted). Secure channels can be obtained using TLS or by using a pre-shared symmetric key. This layer is heavily used by the interactive protocols in SCAPI' third layer and by MPC protocols. It can also be used by any other cryptographic protocol that requires communication. The communication layer is comprised of two basic communication types: a two-party communication channel and a multiparty layer that arranges communication between multiple parties.

Two-Party communication
------------------------------------------------

The two party communication layer provides a way to setup a two-party channel and communicate between them. This implementation improves on the previous SCAPI two-party channel in the following aspects:

	* The user can choose between three different channel types: a socket-based channel, a queue-based channel, and a TLS channel (for each of the socket and queue options). Each option has it own advantages and disadvantages, and the user should analyze which channel is most appropriate. In general, a queue is a more robust channel, but is less efficient than a socket channel.

	* The queue channels avoid, or more accurately automatically recover from, communication failures. Thus, an application that needs to be robust and recover from such failures should use the queue channel.

	* TLS/SSL is used for providing secure communication. (In many cases, this is more convenient than the previous SCAPI channel which used SCAPI encryption and authentication and thus required preshared keys.)

	* Any number of channels can be established between a single pair of parties. Each party provides the number of channels that are desired, and the communication setup function returns a map containing this number of channels. This is very important for multithreading (e.g., SCAPI oblivious transfer protocols receive a channel in their constructor; in order to run many OTs in parallel, it is necessary to generate a different channel for each thread). We stress that only one port is needed, even if many channels are created. The different channels have unique internal port numbers, but use only a single external port number.

All the classes in the two-party communication are in the ``edu.biu.scapi.twoPartyComm`` package.


Plain communication
~~~~~~~~~~~~~~~~~~~~~~~~

This type of channel delivers every message as is, without encryption or authentication. It is possible to encrypt and/or authenticate the channel by wrapping the channel with SCAPI's encrypted and/or authenticated channel at scapi.edu.biu.comm. (Note that this requires pre-shared symmetric keys.) Alternatively, the SSL communication can be used instead, as described below.

There are two different implementations of the plain communication channel: socket communication and queue communication.


Socket communication
^^^^^^^^^^^^^^^^^^^^^^

This implementation of a plain communication channel uses the ``Socket`` and ``ServerSocket`` of the ``java.net`` package. 

Internally, there are two sockets for each channel: one socket for sending messages (sendSocket) and another socket to receive messages (receiveSocket). This mechanism makes the communication more convenient and easy to understand.

The class that implements this communication type is called :java:ref:`SocketCommunicationSetup`.


Queue communication
^^^^^^^^^^^^^^^^^^^^^

This implementation of a plain communication channel uses the JMS API for sending and receiving messages.

JMS enables distributed communication that is loosely coupled. A component sends a message to a destination, and the recipient can retrieve the message from the destination. However, the sender and the receiver do not have to be available at the same time in order to communicate. In fact, the sender does not need to know anything about the receiver; nor does the receiver need to know anything about the sender. The sender and the receiver only need to know which message format and which destination to use. In this respect, messaging differs from tightly coupled technologies, like Remote Method Invocation (RMI), which requires an application to know a remote application's methods. Moreover, the JMS API knows how to automatically recover from communication failures; in case a connection falls during the communication, it is automatically reconnected. In addition, messages cannot get lost in the communication. A queue is therefore a far more robust method of communication.

In SCAPI's implementation, the server manages two queues between each pair of parties P1 and P2: one of them is used for P1 to send messages and for P2 to receive them, and the other is used for P2 to send messages and for P1 to receive them.

The class that implements this communication type is called :java:ref:`QueueCommunicationSetup`. This class gets a ConnectionFactory in the constructor and uses it to create the JMS connection. This allows us to deal with every JMS implementation. In addition, we provide a concrete implementation that uses ActiveMQ implementation of JMS that creates the factory inside the constructor. Thus, the user can use this class instead of dealing with the factory construction. 

.. note::
	In order to use Queue-based communication, a queue server needs to be configured, and up and running. We remark, however, that the queue server can be run by one of the parties if desired and so no additional machines are actually needed.


SSL communication
~~~~~~~~~~~~~~~~~~~~

In this type of channel, the establishment of the secure channel, and the encryption and authentication are carried out by the TLS protocol. The implementation uses mutual (client and server) authentication and so both parties need certificates. The protocol version used is TLS v1.2 and forward-secure cipher suites are used.

.. note::
	TLS v1.2 is supported from Java 7 only. In order to use the SSL channel, you need to make sure that you have at least Java 7 installed.

The security of SSL relies on the ability of each party to validate that it has received the authentic certificate of the other party. We support two ways to validate the other party's certificate. The first is to use a CA-signed certificate and carry out the validation using the CA certificate in the party's existing certificate store. The second is to use a self-signed certificate and carry out the validation using a method called "certificate pinning" which just means that it is assumed that each party already has the other party's certificate and trusts it. We now describe these two methods:


* CA-signed certificate 

  With this method, it is assumed that the parties have certificates that were signed by a trusted CA. In order to validate the authenticity of the certificate, the protocol takes the CA key from the trustStore and verifies that the certificate is indeed signed by the CA and is therefore valid.

  The steps that should be taken in order to work with a CA certificate are as follows:
    
     1. Open cmd and go to your JAVA_HOME path. For example: ::

		>> cd C:\Program Files\Java\jre6\bin
    
     2. Generate a key store: ::

		>> keytool -genkey -alias {your_domain} -keyalg RSA -keysize 2048 -keypass changeit -keystore scapiKeystore.jks
    
     3. Create a certificate request to send to the CA: ::

		>> keytool -certreq -alias {your_domain} -keystore scapiKeystore.jks -file scapiCert.csr
    
     4. The Certificate Signing Request that you generated can be submitted to a CA to create a certificate signed by the CA.
    
	.. note::
		You must obtain the signed certificated from the CA before carrying out the following steps.
    
     5. Install the CA root and any intermediate certificates into the keystore: ::

		>> keytool -import -trustcacerts -alias {root_certificate_alias} -file root.crt -keystore scapiKeystore.jks
    
     6. Install the generated server certificate into the keystore: ::

		>> keytool -import -trustcacerts -alias <server_certificate_alias> -file scapiCert.crt -keystore scapiKeystore.jks
    
     7. Install the CA root and any intermediate certificates into the truststore: ::

		>> keytool -import -trustcacerts -alias {root_certificate_alias} -file root.crt -keystore scapiCacerts.jks

     8. After you have the scapiKeystore.jks and scapiCacerts.jks files, put them in your project root directory.

  After the CA certificate has been installed, the parties can use any certificate signed by that CA without any further manual setup.

* Self-signed certificate and certificate pinning

  With this method, the users sign the certificates themselves and send them to the other parties in some out-of-band communication before running the protocol. It is assumed that the parties manually validate the authenticity of the certificates (e.g., by comparing their fingerprints over the phone). Each party has two certificates. The first is the certificate that the party generated itself; this should be installed in the keyStore. The second is the certificate that it received from the other party; this certificate should be installed in the trustStore, and declared as "trusted". During the SSL handshake, each party receives the certificate of the other party. Since this certificate was already declared as "trusted", SSL accepts the certificate as valid. Each party is responsible to generate its own self-signed certificate, put it in its keystore and send it to the other party. Moreover, each party must receive the self-signed certificate of the other party and put it in its truststore.

  To help with the certificate generation process, we describe here the exact steps that should be taken:
    
    1. Open cmd and go to your JAVA_HOME path. For example: ::

		>> cd C:\Program Files\Java\jre6\bin
    
    2. Generate a self signed certificate and put it in the key store: ::

		>> keytool -genkey -alias {your_domain} -keyalg RSA -keysize 2048 -keypass changeit -keystore scapiKeystore.jks
    
    3. Get the certificate file from the key store in order to send it to the other party: ::

		>> keytool -export -alias {your_domain} -storepass changeit -file myCert.cer -keystore scapiKeystore.jks
    
    4. When receiving the other party's certificate: ::

		>> keytool -import -v -trustcacerts -alias {other_party_domain} -file otherCert.cer -keystore scapiCacerts.jks -keypass changeit
    
    5. After you have the scapiKeystore.jks and scapiCacerts.jks files, put them in your project root directory.
    

There are two different implementations of the SSL communication channel: SSL socket communication and SSL queue communication.


SSL socket communication
^^^^^^^^^^^^^^^^^^^^^^^^^

This is a special case of socket communication that uses an SSL socket instead of a plain one. This implementation uses the ``SSLSocket`` and ``SSLServerSocket`` of ``javax.net.ssl`` package. 

This implementation loads the scapiKeystore.jks and scapiCacerts.jks mentioned above. The names of the files are hardcoded and thus should not be changed. Make sure to put these files in the project directory so that they can be found.

The class that implements this communication type is called :java:ref:`SSLSocketCommunicationSetup`.


SSL queue communication
^^^^^^^^^^^^^^^^^^^^^^^^^

This is a special case of Queue communication that uses the SSL protocol during the communication with the JMS broker (server). 

The way to construct an SSL queue differs from the way to construct an SSL socket. Unlike a socket construction, where there are unique classes for SSL sockets, in the JMS implementation the classes are the same. The only thing that determines the communication type is the URI given in the ``ConnectionFactory`` constructor. To create a plain and insecure communication use tcp://localhost:port uri; to create a secure connection that uses SSL protocol use **ssl**://localhost:port uri. In SCAPI's QueueCommunicationSetup class the connectionFactory is given as an argument to the constructor, when the factory is already initialized with the URI. As a result, the choice of whether or not to use the SSL protocol or not is the user responsibility.

We provide a concrete implementation of SSL queue communication that uses the ActiveMQ implementation, called :java:ref:`SSLActiveMQCommunicationSetup`. Like plain queue communication, the SSLActiveMQCommunicationSetup creates the factory inside the constructor and this way the user can avoid the factory construction. If a different SSL queue implementation is used, then the factory needs to be used, and the client and server certificates need to be loaded into the key store and trust store. 

.. Note::
	In the SSL queue implementation, the other party of the SSL protocol is the JMS broker. Thus, the certificate that needs to be placed in the trust store is the certificate of the broker. In addition, this means that the broker server must either be trusted, or it must run on the same machine as one of the parties. Otherwise, the broker itself can run an man-in-the-middle attack.

SCAPI's :java:ref:`SSLActiveMQCommunicationSetup` implementation loads the scapiKeystore.jks and scapiCacerts.jks files mentioned above. It is the user's responsibility to put these files in the project library so that they can be found. On the ActiveMQ server side, there is a file called activemq.xml that manages the broker properties. In order to use the broker in SSL protocols one should add the following lines to this file: ::

	<sslContext>
		<sslContext keyStore="{path_to_broker_keystore}/{name_of_broker_keystore}.jks"
					keyStorePassword="{broker_keystore_password}"
					trustStore="{path_to_broker_truststore}/{name_of_broker_truststore}.jks" 
					trustStorePassword="{broker_truststore_password}"/>
    </sslContext>
        
    <transportConnectors>
        <transportConnector name="ssl" uri="ssl://0.0.0.0:61617?maximumConnections=1000&amp;wireFormat.maxFrameSize=104857600;transport.tcpNoDelay=true;transport.needClientAuth=true;transport.enabledProtocols=TLSv1.2;transport.enabledCipherSuites=TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256"/>
	    <transportConnector name="https" uri="https://0.0.0.0:8443?maximumConnections=1000&amp;wireFormat.maxFrameSize=104857600"/>
            ...
    </transportConnectors>

.. note::
	In order to use ActiveMQ with the SSL protocol use the port 61617. This is unlike with plain queue communication where the port number is 61616.

We have specified the enabled SSL protocol to be TLSv1.2, and the enabled cipher suites to be TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256 and TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256. Moreover, we have specified the broker to use client authentication, and in addition to not use Nagle's algorithm. If you wish to enable Nagle's algorithm, then change the SSL tcpNoDelay property to false. 


Multiparty communication
-----------------------------

This is the communication layer for multiparty protocols, that provides a way to setup channels between all parties in a protocol and communicate between them. 

Like the two party communciation, this implementation improves the previous SCAPI multiparty communication in some aspects, including letting the user choose the channel type and the amount of channels between each pair of parties, option to recover from communication failures and secure channels.

All the classes in the multiparty communication are in the ``edu.biu.scapi.multiPartyComm`` package.

The previous multiparty implementation in the ``edu.biu.scapi.comm`` package is from now on deprecated. We recommend not to use it since it will not be supported anymore. 

The new multiparty implementation has two main parts: 

	* The first part is a communication that uses ActiveMQ queues in order to communicate between the parties. It uses a :java:ref:`TwoPartyCommunicationSetup` instance between each pair of parties. Thus, the classes that implement the queue multiparty communication are very slim since they delegate all functionality to the underline two party instances.
	
	* The second part is a communication that uses sockets in order to communicate between the parties. In this implementation, using the two party communication will be less effective. A Two party object listens to incoming connection on a given fixed port. If the multiparty communication will use two party instances, every two party instance will have the same port number (given to the mltiparty comm) so all the objects will listen on the same port. This cannot be done in parallel since only one socket can be bind to each port at the same time. So the communication can be done only serially and that is not efficient. In light of this, we chose to have a different, but very similar, implementation that listens to incoming connections from **all** parties. When receiving a connection, the listenning thread will determine which party is calling and set the created socket to this party. The creation of the channels and the conneting step will be identical to the two party communication.
 
Both queues and sockets multiparty implementations have a plain communication and a secure communication channels. All the instructions (regarding the SSL protocol, ActiveMQ usage, etc) are the same as in the TwoPartyCommunicationSetup classes.

---------------------------------
Setting up communication
---------------------------------

There are several steps involved in setting up a communication channel between parties. Each one of them will be explained below:

Fetch the list of parties from a properties file
--------------------------------------------------

The first step towards obtaining communication services is to setup the connections between the different parties. Each party needs to run the setup process, at the end of which the established connections are obtained. The established connections are called channels. The list of parties and their addresses are usually obtained from a properties file. The format of the properties file depends on the concrete communication type.


The format of the socket properties file is as follows: ::

	NumOfParties = 2  
	IP0 = <ip address of this application>  
	IP1 = <ip address of the other party>  
	Port0 = <port number of this application>  
	Port1 = <port number of party>

The format of the queue properties file is as follows:  ::

	URL = <URL of the JMS broker> 
	NumOfParties = 2  
	ID0 = <ID of this party>  
	ID1 = <ID of the other party>

.. note::

	The properties files and the classes that load them are not a necessary part of the communication. This is merely one way to construct the PartyData objects that are needed in the communication setup phase. However, an application can also just construct these objects directly.

An example of the properties file used in socket communication (including SSL socket) called *SocketParties0.properties*, is as follows: ::

    # A configuration file for the parties

    NumOfParties = 2

    IP0 = 132.71.122.117
    IP1 = 132.71.122.117

    Port0 = 8001
    Port1 = 8000

An example of the properties file used in queue communication called *JMSParties0.properties* is as follows: ::

    # A configuration file for the parties

    URL = 132.71.122.117:61616

    NumOfParties = 2

    ID0 = 0
    ID1 = 1
 
The socket and queue ``LoadParties`` classes are used for reading the properties file for socket and queue communication, respectively:   

.. code-block:: java

    import edu.biu.scapi.twoPartyComm.LoadSocketParties;
    import edu.biu.scapi.twoPartyComm.SocketPartyData;

    LoadSocketParties loadParties = new LoadSocketParties("SocketParties1.properties");
    List<PartyData> listOfParties = loadParties.getPartiesList();
    
or 

.. code-block:: java

    import edu.biu.scapi.twoPartyComm.LoadQueueParties;
    import edu.biu.scapi.twoPartyComm.QueuePartyData;

    LoadQueueParties loadParties = new LoadQueueParties("JmsParties1.properties");
    List<PartyData> listOfParties = loadParties.getPartiesList();

Each party is represented by an instance of the ``PartyData`` class. A ``List<PartyData>`` object is required in the `communication setup phase`_.

.. _`communication setup phase`:

Setting up the actual communication
--------------------------------------

This step is different for two-party communication and for multiparty communication.

Two-Party communication
~~~~~~~~~~~~~~~~~~~~~~~~~

The ``TwoPartyCommunicationSetup`` interface is responsible for establishing secure communication to the other party. An application requesting from ``TwoPartyCommunicationSetup`` to prepare for communication needs to create the required concrete communicationSetup class: ``SocketCommunicationSetup``, ``SSLSocketCommunicationSetup`` and ``QueueCommunicationSetup``:

.. java:type:: public class SocketCommunicationSetup implements TwoPartyCommunicationSetup, TimeoutObserver
    :package: package edu.biu.scapi.twoPartyComm;

.. java:type:: public class SSLSocketCommunicationSetup extends SocketCommunicationSetup
	:package: package edu.biu.scapi.twoPartyComm;
    
.. java:type:: public class QueueCommunicationSetup implements TwoPartyCommunicationSetup, TimeoutObserver
    :package: package edu.biu.scapi.twoPartyComm;
    
There is no specific class for SSL Queue communication because QueueCommunicationSetup can be used for SSL too. The actual communication protocol is determined in the ``ConnectionFactory`` constructor. The connectionFactory is given in the QueueCommunicationSetup's constructor when it is already initialized. Thus, if SSL is to be used, then this needs to be specified in the factory creation, before calling the QueueCommunicationSetup constructor. As we have explained above, we have implemented a concrete class that uses the ActiveMQ implementation of JMS with SSL. It is called SSLActiveMQCommunicationSetup and will be explained later. The advantage of using this class is that the factory is not needed.

All concrete classes implement the org.apache.commons.exec.TimeoutObserver interface. This interface supplies a mechanism for notifying classes that a timeout has occurred.

In order to setup the actual communication, one of the following constructors is called (using the PartyData objects obtained from the LoadParties method previously used).


.. java:method:: public void SocketCommunicationSetup(PartyData me, PartyData party) 
    :outertype: SocketCommunicationSetup

    :param PartyData me: Data of the current application.
    :param PartyData party: Data of the other application to communicate with.
    
.. java:method:: public void SSLSocketCommunicationSetup(PartyData me, PartyData party, String storePassword)
    :outertype: SSLCommunicationSetup

    :param PartyData me: Data of the current application.
    :param PartyData party: Data of the other application to communicate with.
    :param String storePassword: The password of the keystore and truststore.

.. java:method:: public void SSLSocketCommunicationSetup(PartyData me, PartyData party, String keyStoreName, String trustStoreName, String storePass)

	:param PartyData me: Data of the current application.
	:param PartyData party: Data of the other application to communicate with.
	:param String keyStoreName: Name of the key store file of this party.
	:param String trustStoreName: Name of the trust store file of this party.
	:param String storePassword: The password of the keystore and truststore.
	
.. java:method:: public void QueueCommunicationSetup(ConnectionFactory factory, DestroyDestinationUtil destroyer, PartyData me, PartyData party)
    :outertype: QueueCommunicationSetup

    :param ConnectionFactory factory: The class used to create the JMS connection. We get it from the user in order to be able to work with all types of connections.
    :param DestroyDestinationUtil destroyer: The class that delete the created destinations. Should match to the given factory.
    :param PartyData me: Data of the current application.
    :param PartyData party: Data of the other application to communicate with.

All constructors receive the data of the current and the other application. Note that the party data is different for socket and queue communication.

The :java:ref:`SSLSocketCommunicationSetup` constructor also receive the password of the keyStore and trustStore where the certificates are placed. This is needed for accessing the party's own private key. Also, there are constructors that get the key store and trust store files' names if the user does not want to use the default files.

The :java:ref:`QueueCommunicationSetup` constructor also receives the JMS factory and destroyer as parameters. We implement a derived classes that uses the ActiveMQ implementation of JMS, called :java:ref:`ActiveMQCommunicationSetup` (for plain communication) and :java:ref:`SSLActiveMQCommunicationSetup` (for SSL communication). The constructors of these classes receive the parties' data and the ActiveMQ broker's URL and create both the factory and the ``DestroyDestinationUtil``. Thus, the user can use this class instead of dealing with the factory and destroyer construction. Thus, instead of using ``QueueCommunicationSetup`` described above, one can call:

.. java:method:: public void ActiveMQCommunicationSetup(String url, PartyData me, PartyData party)
    :outertype: ActiveMQCommunicationSetup

    :param String url: URL of the ActiveMQ broker.
    :param PartyData me: Data of the current application.
    :param PartyData party: Data of the other application to communicate with.

.. java:method:: public void SSLActiveMQCommunicationSetup(String url, PartyData me, PartyData party, String storePass)
    :outertype: SSLActiveMQCommunicationSetup

    :param String url: URL of the ActiveMQ broker.
    :param PartyData me: Data of the current application.
    :param PartyData party: Data of the other application to communicate with.
    :param String storePass: The password of the keystore and truststore.

.. java:method:: public void SSLActiveMQCommunicationSetup(String url, PartyData me, PartyData party, String keyStoreName, String trustStoreName, String storePass)

	:param String url: URL of the ActiveMQ broker.
	:param PartyData me: Data of the current application.
	:param PartyData party: Data of the other application to communicate with.
	:param String keyStoreName: Name of the key store file of this party.
	:param String trustStoreName: Name of the trust store file of this party.
	:param String storePass: The password of the keystore and truststore.
		
After calling the constructor of the communication setup class, the application should call one of the :java:ref:`TwoPartyCommunicationSetup::prepareForCommunication` functions in order to establish connections:

.. java:method:: public Map<String, Channel> prepareForCommunication(String[] connectionsIds, long timeOut)
    :outertype: TwoPartyCommunicationSetup
    
    :param String[] connectionsIds: The names of the required connections.
    :param long timeOut: A time-out (in milliseconds) specifying how long to wait for connections to be established.
    :return: a map of the established channels.
    
.. java:method:: public Map<String, Channel> prepareForCommunication(int connectionsNum, long timeOut)
    :outertype: TwoPartyCommunicationSetup
    
    :param int connectionsNum: The number of requested connections. The IDs of the created connection will be set with defaults values.
    :param long timeOut: A time-out (in milliseconds) specifying how long to wait for connections to be established.
    :return: a map of the established channels.

In both of the above functions, the user can generate one or more connections between the parties. The channels are connected using a **single port** for each application, specified in the PartyData objects given in the constructor. The first function is used when the user wishes to provide the name of each connection. The second function is used if the user wishes these “names” to be generated automatically. In this case, the name of a channel is actually the index of the channel. That is, the first created channel is named “1”, the second is “2” and so on. These functions can be called several times. The class internally stores the number of created channels so that the next index can be given, when using the second function.

By default, Nagle algorithm is disabled since it has much better performance for cryptographic algorithms. In order to change the default value, call the ``enableNagle()`` function in the socket implementations. In the queue implementations the Nagle algorithm can be changes only in construction time so we added a constructor with ``boolean enableNagle`` to let the user determine if Nagle algorithm should be used or not.

Here is an example on how to use the :java:ref:`SocketCommunicationSetup` class:

.. code-block:: java

    import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.exceptions.DuplicatePartyException;
    import edu.biu.scapi.twoPartyComm.LoadSocketParties;
    import edu.biu.scapi.twoPartyComm.PartyData;
    import edu.biu.scapi.twoPartyComm.SocketCommunicationSetup;
    import edu.biu.scapi.twoPartyComm.SocketPartyData;
    import edu.biu.scapi.twoPartyComm.TwoPartyCommunicationSetup;

    //Prepare the parties list.
    LoadSocketParties loadParties = new LoadSocketParties("SocketParties1.properties");
    List<PartyData> listOfParties = loadParties.getPartiesList();
    
    TwoPartyCommunicationSetup commSetup = new SocketCommunicationSetup(listOfParties.get(0), listOfParties.get(1));

    //Call the prepareForCommunication function to establish one connection within 2000000 milliseconds.
    Map<String, Channel> connections = commSetup.prepareForCommunication(1, 2000000);
    
    //Return the channel to the calling application. There is only one created channel.
    return (Channel) connections.values().toArray()[0];

In order to use the :java:ref:`SSLSocketCommunicationSetup` class one should add the password parameter to the constructor:

.. code-block:: java

    import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.exceptions.DuplicatePartyException;
    import edu.biu.scapi.twoPartyComm.LoadSocketParties;
    import edu.biu.scapi.twoPartyComm.PartyData;
    import edu.biu.scapi.twoPartyComm.SSLSocketCommunicationSetup;
    import edu.biu.scapi.twoPartyComm.TwoPartyCommunicationSetup;

    //Prepare the parties list.
    LoadSocketParties loadParties = new LoadSocketParties("SocketParties1.properties");
	List<PartyData> listOfParties = loadParties.getPartiesList();
	
	TwoPartyCommunicationSetup commSetup = new SSLSocketCommunicationSetup(listOfParties.get(0), listOfParties.get(1), "changeit");
	
	//Call the prepareForCommunication function to establish one connection within 2000000 milliseconds.
	Map<String, Channel> connections = commSetup.prepareForCommunication(1, 2000000);
	
	//Return the channel with the other party. There was only one channel created.
	return (Channel) connections.values().toArray()[0];

Here is an example of how to use the :java:ref:`ActiveMQCommunicationSetup` class:

.. code-block:: java

    import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.exceptions.DuplicatePartyException;
    import edu.biu.scapi.twoPartyComm.LoadQueueParties;
    import edu.biu.scapi.twoPartyComm.PartyData;
    import edu.biu.scapi.twoPartyComm.ActiveMQCommunicationSetup;
    import edu.biu.scapi.twoPartyComm.TwoPartyCommunicationSetup; 

    //Prepare the parties list.
    LoadQueueParties loadParties = new LoadQueueParties("JmsParties1.properties");
    List<PartyData> listOfParties = loadParties.getPartiesList();

    TwoPartyCommunicationSetup commSetup = new ActiveMQCommunicationSetup(loadParties.getURL(), listOfParties.get(0), listOfParties.get(1));
	
    //Call the prepareForCommunication function to establish two connections within 2000000 milliseconds.
    Map<String, Channel> connections = commSetup.prepareForCommunication(2, 2000000);
    
    //Return the channels to the calling application. 
    return connections.values().toArray();

And an example to :java:ref:`SSLActiveMQCommunicationSetup` class:

.. code-block:: java

	import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.exceptions.DuplicatePartyException;
    import edu.biu.scapi.twoPartyComm.LoadQueueParties;
    import edu.biu.scapi.twoPartyComm.PartyData;
    import edu.biu.scapi.twoPartyComm.SSLActiveMQCommunicationSetup;
    import edu.biu.scapi.twoPartyComm.TwoPartyCommunicationSetup;
	 
	//Prepare the parties list.
	LoadQueueParties loadParties = new LoadQueueParties("JmsParties1.properties");
	List<PartyData> listOfParties = loadParties.getPartiesList();
		
	TwoPartyCommunicationSetup commSetup = new SSLActiveMQCommunicationSetup(loadParties.getURL(), listOfParties.get(0), listOfParties.get(1), "changeit");
		
	Map<String, Channel> connections = commSetup.prepareForCommunication(1, 2000000);
		
	//Return the channels to the calling application. 
	return connections.values().toArray();

Multiparty communication
~~~~~~~~~~~~~~~~~~~~~~~~~

The ``MultipartyCommunicationSetup`` interface is responsible for establishing secure communication between the current running application to each other party in the protocol. An application requesting from ``MultipartyCommunicationSetup`` to prepare for communication needs to create the required concrete  multiparty communicationSetup class: ``SocketMultipartyCommunicationSetup``, ``SSLSocketMultipartyCommunicationSetup``, ``ActiveMQMultipartyCommunicationSetup`` and ``SSLActiveMQMultipartyCommunicationSetup``:

.. java:type:: public class SocketMultipartyCommunicationSetup implements MultipartyCommunicationSetup, TimeoutObserver
    :package: package edu.biu.scapi.multiPartyComm;

.. java:type:: public class SSLSocketMultipartyCommunicationSetup extends SocketMultipartyCommunicationSetup
	:package: package edu.biu.scapi.multiPartyComm;
    
.. java:type:: public class ActiveMQMultipartyCommunicationSetup implements MultipartyCommunicationSetup
    :package: package edu.biu.scapi.multiPartyComm;

.. java:type:: public class SSLActiveMQMultipartyCommunicationSetup extends ActiveMQMultipartyCommunicationSetup
    :package: package edu.biu.scapi.multiPartyComm;
    
Here, unlike the two party implementation there is no abstract class for queue communication. As mentioned above, the queue multiparty communication uses two party instances between the current running application and any other party in the protocol. In order to create the underling two party objects, one should know exactly which specific class he should create. This specific two party object fixed the multiparty implementation and that is the reason it cannot be abstract.

The socket implementations implement the org.apache.commons.exec.TimeoutObserver interface. This interface supplies a mechanism for notifying classes that a timeout has occurred. The queue implementations should not implementat this interface since they use the two party queue implementation that implements the TimeoutObserver interface.

In order to setup the actual communication, one of the following constructors is called (using the PartyData list obtained from the LoadParties method previously used).


.. java:method:: public void SocketMultipartyCommunicationSetup(List<PartyData> parties) 
    :outertype: SocketMultipartyCommunicationSetup

    :param List<PartyData> parties: Data of the current application.
    
.. java:method:: public void SSLSocketMultipartyCommunicationSetup(List<PartyData> parties, String storePass)
    :outertype: SSLSocketMultipartyCommunicationSetup

    :param List<PartyData> parties: Data of the current application.
    :param String storePass: The password of the keystore and truststore.

.. java:method:: public void SSLSocketMultipartyCommunicationSetup(List<PartyData> parties, String keyStoreName, String trustStoreName, String storePass)
    :outertype: SSLSocketMultipartyCommunicationSetup

    :param List<PartyData> parties: Data of the current application.
    :param String keyStoreName: Name of the key store file of this party.
    :param String trustStoreName: Name of the trust store file of this party.
    :param String storePass: The password of the keystore and truststore.
	
.. java:method:: public void ActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties)
    :outertype: ActiveMQMultipartyCommunicationSetup

    :param String url: URL of the ActiveMQ broker.
    :param List<PartyData> parties: Data of the current application.

.. java:method:: public void SSLActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, String storePass)
    :outertype: SSLActiveMQMultipartyCommunicationSetup

    :param String url: URL of the ActiveMQ broker.
    :param List<PartyData> parties: Data of the current application.
    :param String storePass: The password of the keystore and truststore.

.. java:method:: public void SSLActiveMQMultipartyCommunicationSetup(String url, List<PartyData> parties, String keyStoreName, String trustStoreName, String storePass)
    :outertype: SSLActiveMQMultipartyCommunicationSetup

    :param String url: URL of the ActiveMQ broker.
    :param List<PartyData> parties: Data of the current application.
    :param String keyStoreName: Name of the key store file of this party.
    :param String trustStoreName: Name of the trust store file of this party.
    :param String storePass: The password of the keystore and truststore.

All constructors receive the data of all the parties participate in the protocol, while the first party in the list represents the current running party. Note that the party data objects are different for socket and queue communication.

As in the two parties communication, the secure multiparty classes also receive in the constructor the password of the keyStore and trustStore where the certificates are placed, and there are constructors that get the key store and trust store files' names.

After calling the constructor of the communication setup class, the application should call the :java:ref:`MultipartyCommunicationSetup::prepareForCommunication` function in order to establish connections:

.. java:method:: public Map<PartyData, Map<String, Channel>> prepareForCommunication(Map<PartyData, Object> connectionsPerParty, long timeOut)	
    :outertype: MultipartyCommunicationSetup
    
    :param Map<PartyData,Object> connectionsPerParty: provides the amount of connections or the names of connections that should be created between the current application and other parties in the protocol.
    :param long timeOut: A time-out (in milliseconds) specifying how long to wait for connections to be established.
    :return: a map contains the connected channels. The key to the map is a PartyData object (represents a party participates in the protocol) and the value is the created connections to this party.
    
Notice that in the two party implementation there are two prepareForCommunication functions. One gets the **number** of requested connections and one gets the **names** of the requested connections. Here, there is only one function that can get both things, since the parameter type is ``Map<PartyData, Object>`` and object can be anything. This is done that way because of technical reasons, since for java ``Map<PartyData, Integer>`` and ``Map<PartyData, string[]>`` are the same thing and therefore java does not allow to split that into two different functions.

As in the two party communication, the user can generate one or more connections between the parties. The channels are connected using a **single port** for each application, specified in the first PartyData object in the given parties list.

Here is an example on how to use the :java:ref:`SocketMultipartyCommunicationSetup` class:

.. code-block:: java

    import java.util.List;
    import java.util.Map;

	import edu.biu.scapi.comm.Channel;
	import edu.biu.scapi.comm.multiPartyComm.MultipartyCommunicationSetup;
	import edu.biu.scapi.comm.multiPartyComm.SocketMultipartyCommunicationSetup;
	import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
	import edu.biu.scapi.comm.twoPartyComm.PartyData;

	 //Prepare the parties list.
	 LoadSocketParties loadParties = new LoadSocketParties("MultiPartySocketParties1.properties");
	
    List<PartyData> listOfParties = loadParties.getPartiesList();

	//Create the communication setup class.
	MultipartyCommunicationSetup commSetup = new SocketMultipartyCommunicationSetup(listOfParties);
		
	//Request two chanels between me and each other party.
	HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();

	connectionsPerParty.put(listOfParties.get(1), 2);
	connectionsPerParty.put(listOfParties.get(2), 2);

	//Call the prepareForCommunication function to establish the connections within 2000000 milliseconds.
	Map<PartyData, Map<String, Channel>> connections = commSetup.prepareForCommunication(connectionsPerParty, 2000000);
	
	//Returns the channels to the other parties. 
	return connections;

In order to use the :java:ref:`SSLSocketMultipartyCommunicationSetup` class one should add the key store name, trust store name and password to the constructor:

.. code-block:: java

    import java.util.List;
    import java.util.Map;

	import edu.biu.scapi.comm.Channel;
	import edu.biu.scapi.comm.multiPartyComm.MultipartyCommunicationSetup;
	import edu.biu.scapi.comm.multiPartyComm.SSLSocketMultipartyCommunicationSetup;
	import edu.biu.scapi.comm.twoPartyComm.LoadSocketParties;
	import edu.biu.scapi.comm.twoPartyComm.PartyData;
    
    //Prepare the parties list.
    LoadSocketParties loadParties = new LoadSocketParties("SocketParties1.properties");
	List<PartyData> listOfParties = loadParties.getPartiesList();
	
	//Create the communication setup class.
	MultipartyCommunicationSetup commSetup = new SSLSocketMultipartyCommunicationSetup(listOfParties, "p1Keystore.jks", "p1Cacerts.jks", "changeit");
		
	//Request two chanels between me and each other party.
	HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();
	connectionsPerParty.put(listOfParties.get(1), 2);
	connectionsPerParty.put(listOfParties.get(2), 2);

	//Call the prepareForCommunication function to establish the connections within 2000000 milliseconds.
	Map<PartyData, Map<String, Channel>> connections = commSetup.prepareForCommunication(connectionsPerParty, 2000000);
	
	//Returns the channels to the other parties. 
	return connections;

Here is an example of how to use the :java:ref:`ActiveMQMultipartyCommunicationSetup` class:

.. code-block:: java

    import java.util.List;
    import java.util.Map;

	import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.exceptions.DuplicatePartyException;
    import edu.biu.scapi.twoPartyComm.LoadQueueParties;
    import edu.biu.scapi.twoPartyComm.PartyData;
    import edu.biu.scapi.multiPartyComm.ActiveMQMultiPartyCommunicationSetup;
    import edu.biu.scapi.multiPartyComm.MultipartyCommunicationSetup; 

	//Prepare the parties list.
	LoadQueueParties loadParties = new LoadQueueParties("MultiPartyQueueParties1.properties");
    List<PartyData> listOfParties = loadParties.getPartiesList();
		
	//Create the communication setup class.
	MultipartyCommunicationSetup commSetup = new ActiveMQMultipartyCommunicationSetup(loadParties.getURL(), listOfParties);
		
	//Request two chanels between me and each other party.	
	HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();
	connectionsPerParty.put(listOfParties.get(1), 2);
	connectionsPerParty.put(listOfParties.get(2), 2);

	//Call the prepareForCommunication function to establish the connections within 2000000 milliseconds.
	Map<PartyData, Map<String, Channel>> connections = commSetup.prepareForCommunication(connectionsPerParty, 2000000);
		
	//Returns the channels to the other parties. 
	return connections;

And an example to :java:ref:`SSLActiveMQMultipartyCommunicationSetup` class:

.. code-block:: java

	import java.util.List;
    import java.util.Map;

	import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.exceptions.DuplicatePartyException;
    import edu.biu.scapi.twoPartyComm.LoadQueueParties;
    import edu.biu.scapi.twoPartyComm.PartyData;
    import edu.biu.scapi.multiPartyComm.ActiveMQMultiPartyCommunicationSetup;
    import edu.biu.scapi.multiPartyComm.MultipartyCommunicationSetup; 

	//Prepare the parties list.
	LoadQueueParties loadParties = new LoadQueueParties("MultiPartySSLQueueParties1.properties");
	List<PartyData> listOfParties = loadParties.getPartiesList();
		
	//Create the communication setup class.
	MultipartyCommunicationSetup commSetup = new SSLActiveMQMultipartyCommunicationSetup(loadParties.getURL(), listOfParties,"changeit");
	
	//Request two chanels between me and each other party.		
	HashMap<PartyData, Object> connectionsPerParty = new HashMap<PartyData, Object>();
	connectionsPerParty.put(listOfParties.get(1), 2);
	connectionsPerParty.put(listOfParties.get(2), 2);
	
	//Call the prepareForCommunication function to establish the connections within 2000000 milliseconds.
	Map<PartyData, Map<String, Channel>> connections = commSetup.prepareForCommunication(connectionsPerParty, 2000000);
	
	//Returns the channels to the other parties. 
	return connections;


.. _`connecting success`: 

Verifying that the connections were established
----------------------------------------------------

In two-party protocols, success means that all requested channels have been established between the parties. The output from the prepareForCommunication function is a map containing the established channels.

In multi-party protocols, different computations may require different types of success when checking the connections between all the parties that were supposed to participate. Some protocols may need to make sure that absolutely all parties participating in it have established connections one with another; other protocols may need only a certain percentage of connections to have succeeded. In the current multiparty communication setup implementation, we implement success as all requested channels have been established. In the future we may support different levels of success.

In case a timeout has occurred before all requested channels have been connected, all connected channels will be closed and a ``ScapiRuntimeException`` will be thrown.

Closing the connection
-------------------------

The application is responsible for closing the communicationSetup class that creates the channels. This is because this class may contain some members that need to be closed. For example, the :java:ref:`QueueCommunicationSetup` has the JMS Connection object as a class member, and this must be closed at the end of the setup.

Needless to say, the application must also close each created channel when it is no longer needed.

----------------------------------
Using an established connection
----------------------------------

A connection is represented by the :java:ref:`Channel` interface. Once a channel is established, we can ``send()`` and ``receive()`` data between parties.

.. java:type:: public interface Channel
   :package: edu.biu.scapi.comm

.. java:method:: public void send(Serializable data) throws IOException
   :outertype: Channel

   Sends a message *msg* to the other party, *msg* must be a ``Serializable`` object.

.. java:method:: public Serializable receive() throws ClassNotFoundException, IOException
   :outertype: Channel

   Receives a message from the channel. 

   :return: Returns the received message as ``Serializable``. Conversion to the right type is the responsiblity of the caller.

.. java:method:: public void close()
   :outertype: Channel

   Closes the connection.

.. java:method:: public boolean isClosed()
   :outertype: Channel

   :return: ``true`` if the connection is closed, ``false`` otherwise.

-----------------------------
Security of the connection
-----------------------------

.. note::
    This section is relevant for all channel types **except the SSLChannel**. SSL channels do the encryption and authentication in the SSL protocol and therefore do not need to be wrapped with SCAPI's encrypted and/or authenticated channels. The methods described here are useful for anyone who does not wish to setup certificates and would rather work with pre-shared secrets.

A channel can have Plain, Encrypted or Authenticated security level, depending on the requirements of the application. The type of security set by `CommunicationSetup` classes is *Plain* security, and is represented by the classes :java:ref:`PlainTCPChannel`, :java:ref:`PlainTCPSocketChannel` and :java:ref:`QueueChannel`. In case a higher security standard is needed, the user must set it manually, by using the decorator classes :java:ref:`AuthenticatedChannel` and :java:ref:`EncryptedChannel`.


Plain Channel
---------------

Plain security is the default type of security set by the CommunicationSetup classes. The :java:ref:`PlainTCPChannel`, :java:ref:`PlainTCPSocketChannel` and :java:ref:`QueueChannel` classes are plain channels by default and so do not provide authentication or encryption. The plain channel types are as follows:

.. java:type:: public class PlainTCPChannel extends Channel
   :package: edu.biu.scapi.comm

.. java:type:: public class PlainTCPSocketChannel extends Channel
   :package: edu.biu.scapi.twoPartyComm
 
.. java:type:: public class QueueChannel extends Channel
   :package: edu.biu.scapi.twoPartyComm

AuthenticatedChannel
--------------------

.. java:type:: public class AuthenticatedChannel extends ChannelDecorator

   This channel ensures :java:ref:`UnlimitedTimes` security level, meaning that there is no a priori bound on the number of messages that can be MACed. The owner of the channel is responsible for setting the MAC algorithm to use and making sure that the MAC is initialized with a suitable key. Then, every message sent via this channel is authenticated using the underlying MAC algorithm and every message received is verified by it.

   The user needs not worry about any of the authentication and verification tasks as they are carried out automatically by the channel. Note that plain objects are passed to the channel and received from the channel and the processes of MACing and verifying the MAC are carried out inside the channel, invisible to the user.

.. java:constructor:: public AuthenticatedChannel(Channel channel, Mac mac) throws SecurityLevelException
   :outertype: AuthenticatedChannel

   This public constructor can be used by anyone holding a channel that is connected. Such a channel can be obtained by running the prepareForCommunication function of :java:ref:`CommunicationSetup` which returns a set of already connected channels.

   :param channel: an already connected channel
   :param mac: the MAC algorithm required to authenticate the messages sent by this channel
   :throws SecurityLevelException: if the MAC algorithm passed is not UnlimitedTimes-secure

.. java:method:: public void setKey(SecretKey key) throws InvalidKeyException
   :outertype: AuthenticatedChannel

   Sets the key of the underlying MAC algorithm. This function must be called before sending or receiving messages if the MAC algorithm passed to this channel had not been set with a key yet. The key can be set indefinite number of times depending on the needs of the application.

   :param key: a suitable SecretKey
   :throws InvalidKeyException: if the given key does not match the underlying MAC algorithm.

Example of Usage:
~~~~~~~~~~~~~~~~~~

We assume in this example that ``ch`` is an already established channel as we have already shown how to setup a channel using CommunicationSetup. We stress that this is the code for one party, but both parties must decorate their respective channels with :java:ref:`AuthenticatedChannel` in order for it to work.

.. code-block:: java

    import java.security.InvalidKeyException;
    
    import javax.crypto.SecretKey;
    import javax.crypto.spec.SecretKeySpec;
    
    import edu.biu.scapi.comm.*;
    import edu.biu.scapi.midLayer.symmetricCrypto.mac.Mac;
    import edu.biu.scapi.tools.Factories.*;
    import edu.biu.scapi.exceptions.*;
    
    public AuthenticatedChannel createAuthenticatedChannel(Channel ch) {
        Mac mac = null;
        
	    mac = new ScCbcMacPrepending(new BcAES());
        
        ///You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    //SecretKey macKey = SecretKeyGeneratorUtil.generateKey("AES");
	    //Instead, we use a secretKey that has already been agreed upon by both parties:
		byte[] aesFixedKey = new byte[]{-61, -19, 106, -97, 106, 40, 52, -64, -115, -19, -87, -67, 98, 102, 16, 21};
	    SecretKey key = new SecretKeySpec(aesFixedKey, "AES");
	    
        try {
	    mac.setKey(key);
        } catch (InvalidKeyException e) {
	    e.printStackTrace();
        }
        
        //Decorate the Plain TCP Channel with the authentication
        AuthenticatedChannel authenChannel = null;
        try {
	    authenChannel = new AuthenticatedChannel(ch, mac);
        } catch (SecurityLevelException e) {
	    // This exception will not happen since we chose a Mac that meets the Security Level requirements
	    e.printStackTrace();
        }
        
        return authenChannel;
    }


After converting the channel to an authenticated channel, we can simply call ``send()`` and ``receive()`` again in the same manner as before, only this time the messages are authenticated for us.

EncryptedChannel
------------------

.. java:type:: public class EncryptedChannel extends ChannelDecorator
 
   This channel ensures :java:ref:`CPA` security level (security in the presence of chosen-plaintext attacks). The owner of the channel is responsible for setting the encryption scheme to use and making sure that the encryption scheme is initialized with a suitable key. Then, every message sent via this channel is encrypted and decrypted using the underlying encryption scheme. As with an authenticated channel, the encryption and decryption are carried out invisibly to the user (who sends and receives plain objects).

   We remark that in the setting of secure computation, encrypted but not authenticated channels should typically not be used.

.. java:constructor:: public EncryptedChannel(Channel channel, SymmetricEnc encScheme) throws SecurityLevelException
   :outertype: EncryptedChannel

   This public constructor can be used by anyone holding a channel that is connected. Such a channel can be obtained by running the prepareForCommunications function of :java:ref:`CommunicationSetup` which returns a set of already connected channels.

   The function creates a new EncryptedChannel that wraps the already connected channel mentioned above. The encryption scheme must be CPA-secure, otherwise an exception is thrown. The encryption scheme does not need to be initialized with a key at this moment (even though it can be), but before sending or receiving a message over this channel the relevant secret key must be set with `setKey()`_.

   :param channel: an already connected channel
   :param encScheme: a symmetric encryption scheme that is CPA-secure.
   :throws SecurityLevelException: if the encryption scheme is not CPA-secure

.. _`setKey()`:

.. java:method:: public void setKey(SecretKey key) throws InvalidKeyException
   :outertype: EncryptedChannel


   Sets the key of the underlying encryption scheme. This function must be called before sending or receiving messages if the encryption scheme passed to this channel had not been set with a key yet. The key can be set indefinite number of times depending on the needs of the application.

   :param key: a suitable SecretKey
   :throws InvalidKeyException: if the given key does not match the underlying MAC algorithm.

Example of Usage
~~~~~~~~~~~~~~~~~~

This example is very similar to the previous one. As before we only show how to decorate the established channel after :java:ref:`CommunicationSetup` is called.

.. code-block:: java

    import java.io.IOException;
    import java.security.InvalidKeyException;
    
    import javax.crypto.SecretKey;
    import javax.crypto.spec.SecretKeySpec;
    
    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.EncryptedChannel;
    import edu.biu.scapi.exceptions.SecurityLevelException;
    import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
    import edu.biu.scapi.primitives.prf.AES;
    import edu.biu.scapi.primitives.prf.bc.BcAES;
    
    public EncryptedChannel createEncryptedChannel(Channel ch) {
        ScCTREncRandomIV enc = null;
        try {
	    // first we generate the secret key for the PRP that is used by the encryption object.
    			
	    // You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    // SecretKey encKey = SecretKeyGeneratorUtil.generateKey("AES");
	    //Instead, we use a secretKey that has already been agreed upon by both parties:
	    byte[] aesFixedKey = new byte[]{-61, -19, 106, -97, 106, 40, 52, -64, -115, -19, -87, -67, 98, 102, 16, 21};
	    SecretKey encKey = new SecretKeySpec(aesFixedKey, "AES");
	    
	    // now, we initialize the PRP, set the key, and then initialize the encryption object
	    AES aes = new BcAES();	
	    aes.setKey(encKey);
	    enc = new ScCTREncRandomIV(aes);
	    
        } catch (InvalidKeyException e) {
	    e.printStackTrace();
        }
        
        //Decorate the Plain TCP Channel with the EncryptedChannel class
        EncryptedChannel encChannel = null;
        try {
	    encChannel = new EncryptedChannel(ch, enc);
        } catch (SecurityLevelException e) {
	    // This exception will not happen since we chose an encryption scheme that meets the Security Level requirements
	    e.printStackTrace();
        }
        
        return encChannel;
    }

Encrypted and Authenticated Channel
-------------------------------------

We now provide an example of both encrypted and authenticated communication. This example is very similar to the previous ones. When using encryption and authentication in the correct order (encrypt-then-authenticate), authenticated encryption security is obtained (which is in particular CCA secure).

.. code-block:: java

    import java.io.IOException;
    import java.security.InvalidKeyException;
    
    import javax.crypto.SecretKey;
    import javax.crypto.spec.SecretKeySpec;
    
    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.EncryptedChannel;
    import edu.biu.scapi.exceptions.SecurityLevelException;
    import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScCTREncRandomIV;
    import edu.biu.scapi.midLayer.symmetricCrypto.encryption.ScEncryptThenMac;
    import edu.biu.scapi.midLayer.symmetricCrypto.mac.ScCbcMacPrepending;
    import edu.biu.scapi.primitives.prf.AES;
    import edu.biu.scapi.primitives.prf.bc.BcAES;
    
    public EncryptedChannel createSecureChannel(Channel ch) {
        ScCTREncRandomIV enc = null;
        ScCbcMacPrepending cbcMac = null;
        try {
	    // first, we set the encryption object
        	
	    // You could generate the key here and then somehow send it to the other party so the other party uses the same secret key
	    // SecretKey encKey = SecretKeyGeneratorUtil.generateKey("AES");
	    //Instead, we use a secretKey that has already been agreed upon by both parties:
	    byte[] aesFixedKey = new byte[]{-61, -19, 106, -97, 106, 40, 52, -64, -115, -19, -87, -67, 98, 102, 16, 21};
	    SecretKey aesKey = new SecretKeySpec(aesFixedKey, "AES");
	    
	    AES encryptAes = new BcAES();
	    encryptAes.setKey(aesKey);
	    
	    // create encryption object from PRP
	    enc = new ScCTREncRandomIV(encryptAes);
	    
	    // second, we create the mac object
	    AES macAes = new BcAES();		
	    
	    macAes.setKey(aesKey);
	    // create Mac object from PRP
	    cbcMac = new ScCbcMacPrepending(macAes);
	    
        } catch (InvalidKeyException e) {
	    e.printStackTrace();
        }
        
        //Create the encrypt-then-mac object using encryption and authentication objects. 
        ScEncryptThenMac encThenMac = null;
        encThenMac = new ScEncryptThenMac(enc, cbcMac);
        
        //Decorate the Plain TCP Channel with the authentication
        EncryptedChannel secureChannel = null;
        try {
	    secureChannel = new EncryptedChannel(ch, encThenMac);
	} catch (SecurityLevelException e) {
	    // This exception will not happen since we chose a Mac that meets the Security Level requirements
	    e.printStackTrace();
	}
	
	return secureChannel;
    }







	
Multiparty communication
-----------------------------------------------------------

The multiparty communication layer will be updated soon to be based on the two-party communication layer. Meanwhile, the description below is for the old implementation which will soon be deprecated.

Fetch the list of parties from a properties file
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The first thing that needs to be done to obtain communication services is to setup the connections between the different parties. Each party needs to run the setup process at the end of which the established connections are obtained. The established connections are called *channels*. The list of parties and their addresses are usually obtained from a Properties file. For example, here is a properties file called *Parties0.properties*: ::

    # A configuration file for the parties

    NumOfParties = 2

    IP0 = 127.0.0.1
    IP1 = 127.0.0.1

    Port0 = 8001
    Port1 = 8000

In order to read this file, we can use the ``LoadParties`` class:

.. code-block:: java

    import edu.biu.scapi.comm.Party;
    import edu.biu.scapi.comm.LoadParties;
    
    LoadParties loadParties = new LoadParties("Parties0.properties");
    List<Party> listOfParties = loadParties.getPartiesList();

Each party is represented by an instance of the ``Party`` class. A ``List<Party>`` object is required in the `multiParty communication setup phase`_.

.. _`multiParty communication setup phase`:

Setup communication to other parties
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The ``CommunicationSetup`` Class is responsible for establishing secure communication to other parties. An application requesting from ``CommunicationSetup`` to prepare for communication needs to call the ``CommunicationSetup::prepareForCommunication()`` function:

.. java:type:: public class CommunicationSetup implements TimeoutObserver
    :package: edu.biu.scapi.comm

CommunicationSetup implements the org.apache.commons.exec.TimeoutObserver interface. This interface supplies a mechanism for notifying classes that a timeout has arrived.

.. java:method:: Map<InetSocketAddress, Channel> prepareForCommunication(List<Party> listOfParties, ConnectivitySuccessVerifier successLevel, long timeOut, boolean enableNagle)
    :outertype: CommunicationSetup

    :param List<Party> listOfParties: The list of parties to connect to. As a convention, we will set the first party in the list to be the requesting party, that is, the party represented by the application.
    :param ConnectivitySuccessVerifier successLevel: The type of `multi party connecting success`_ required.
    :param long timeOut: A time-out (in milliseconds) specifying how long to wait for connections to be established and secured.
    :param boolean enableNagle: Whether or not `Nagle's algorithm <http://en.wikipedia.org/wiki/Nagle's_algorithm>` can be enabled.
    :return: a map of the established channels.

Here is an example on how to use the `CommunicationSetup` class, we leave the discussion about the `ConnectivitySuccessVerifier` instance to the next section.

.. code-block:: java

    import java.net.InetSocketAddress;
    import java.util.List;
    import java.util.Map;

    import edu.biu.scapi.comm.Party;
    import edu.biu.scapi.comm.LoadParties;

    import edu.biu.scapi.comm.Channel;
    import edu.biu.scapi.comm.CommunicationSetup;

    import edu.biu.scapi.comm.ConnectivitySuccessVerifier;
    import edu.biu.scapi.comm.NaiveSuccess;

    //Prepare the parties list.
    LoadParties loadParties = new LoadParties("Parties0.properties");
    List<Party> listOfParties = loadParties.getPartiesList();
    
    //Create the communication setup.
    CommunicationSetup commSetup = new CommunicationSetup();
    
    //Choose the naive connectivity success algorithm.
    ConnectivitySuccessVerifier naive = new NaiveSuccess();
    
    long timeoutInMs = 60000; //The maximum amount of time we are willing to wait to set a connection.
    
    Map<InetSocketAddress, Channel> map = commSetup.prepareForCommunication(listOfParties, naive, timeoutInMs);
    
    // prepareForCommunication() returns a map with all the established channels,
    // we return only the first one since this code assumes the two-party case.
    return map.values().iterator().next();

.. _`multi party connecting success`: 

Verifying that the connections were established
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Different Multi-parties computations may require different types of success when checking the connections between all the parties that were supposed to participate. Some protocols may need to make sure that absolutely all parties participating in it have established connections one with another; other protocols may need only a certain percentage of connections to have succeeded. There are many possibilities and each one of them is represented by a class implementing the ``ConnectivitySuccessVerifier`` interface. The different classes that implement this interface will run different algorithms to verify the level of success of the connections. It is up to the user of the ``CommunicationSetup`` class to choose the relevant level and pass it on to the ``CommunicationSetup`` upon calling the ``prepareForCommuncation`` function.

.. java:type:: public interface ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

.. java:method:: public boolean hasSucceded(EstablishedConnections estCon, List<Party> originalListOfParties)
   :outertype: ConnectivitySuccessVerifier

   This function gets the information about the established connections as input and the original list of parties, then it runs a certain algorithm (determined by the implementing class), and it returns true or false according to the level of connectivity checked by the implementing algorithm.

   :param estCon: the actual established connections
   :param originalListOfParties: the original list of parties to connect to
   :return: ``true`` if the level of connectivity was reached (depends on implementing algorithm) and ``false`` otherwise.
   
Naive
^^^^^^

.. java:type:: public class NaiveSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

NaiveSuccess does not actually check the connections but rather always returns true. It can be used when there is no need to verify any level of success in establishing the connections.

Clique
^^^^^^^

.. java:type:: public class CliqueSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

   **For future implementation.**
   
   * Check if connected to all parties in original list.
   * Ask every party if they are connected to all parties in their list.
   * If all answers are true, return true,
   * Else, return false.

SecureClique
^^^^^^^^^^^^^

.. java:type:: public class SecureCliqueSuccess implements ConnectivitySuccessVerifier
   :package: edu.biu.scapi.comm

   **For future implementation.**
   
   * Check if connected to all parties in original list.
   * Ask every party if they are connected to all parties in their list. USE SECURE BROADCAST. DO NOT TRUST THE OTHER PARTIES.
   * If all answers are true, return true,
   * Else, return false.