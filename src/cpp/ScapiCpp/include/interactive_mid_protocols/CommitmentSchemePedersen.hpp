#pragma once

#include "CommitmentScheme.hpp"
#include "../comm/TwoPartyComm.hpp"
#include "ZKPedersen.hpp"
#include <map>


/**
* Concrete implementation of commitment message used by Pedersen commitment scheme.
*/
class CmtPedersenCommitmentMessage : public CmtCCommitmentMsg{
	// in Pedersen schemes the commitment object is a groupElement. 
	// in order to this class be a serializable, we get it as GroupElementSendableData.
private:
	GroupElementSendableData* c;
	long id; // the id of the commitment
	int serializedSize_;
public:
	/**
	* Constructor that sets the commitment and id.
	* @param c the actual commitment object. In Pedersen schemes the commitment object is a groupElement.
	* @param id the commitment id.
	*/
	CmtPedersenCommitmentMessage(GroupElementSendableData* c, long id) {
		this->c = c;
		this->id = id;
	}

	void* getCommitment() override { return c; };
	long getId() override { return id; };
	byte* toByteArray() override {
		byte* byteGe = c->toByteArray();
		int idSize = bytesCount(id);
		byte* bytesId = new byte[idSize];
		encodeBigInteger(id, bytesId, idSize);
		int geSize = c->getSerializedSize();
		serializedSize_ = idSize + geSize;
		byte * result = new byte[serializedSize_];
		copy(byteGe, byteGe + geSize, result);
		copy(bytesId, bytesId + idSize, result + geSize);
	}
	virtual int serializedSize() override { return serializedSize_; };
	void init_from_byte_array(byte* arr, int size) { //TBD
	};

};

/**
* Concrete implementation of decommitment message used by Pedersen commitment scheme.
*/
class CmtPedersenDecommitmentMessage : public CmtCDecommitmentMessage {
private:
	biginteger x; // committer's private input x in Zq
	int len;
	BigIntegerRandomValue* r; 	// random value sampled during the sampleRandomValues stage;
public:
	/**
	* Constructor that sets the given committed value and random value.
	* @param x the committed value
	* @param r the random value used for commit.
	*/
	CmtPedersenDecommitmentMessage(biginteger x, BigIntegerRandomValue* r) {
		this->x = x;
		this->r = r;
		this->len = bytesCount(x);
	};
	/**
	* Returns the committed value.
	*/
	byte* getSerializedX() override{
		byte* res = new byte[len];
		encodeBigInteger(x, res, len);
		return res;
	}
	int getSerializedXSize() override { return len; };
	BigIntegerRandomValue* getR() override{ return r; };
};

/**
* This class holds the value sent by the receiver to the committer in the pre-process
* phase which is part of the initialization stage.
*/
class CmtPedersenPreprocessMessage{
private:
	GroupElementSendableData* h;
public:
	/**
	* Constructor that sets the given groupElement.
	* @param h the value sent by the receiver to the committer in the pre-process phase
	*/
	CmtPedersenPreprocessMessage(GroupElementSendableData* h) { this->h = h; };
	/**
	* This function return the h values which is calculated by the receiver in the pre-process
	* phase as follows:
	* SAMPLE a random value a in  Zq
	* COMPUTE h = g^a
	* SEND h to Committer.
	*/
	GroupElementSendableData* getH() { return h; };
};

/**
* This class holds the values used by the Pedersen Committer during the commitment phase
* for a specific value that the committer commits about.
* This value is kept attached to a random value used to calculate the commitment,
* which is also kept together in this structure.
*/
class CmtPedersenCommitmentPhaseValues : public CmtCommitmentPhaseValues {
private:
	// The random value used in the computation of the commitment for the specific commitval.
	BigIntegerRandomValue* r;
	// The value that the committer commits about. This value is not sent to the receiver in the 
	// commitment phase, it is sent in the decommitment phase.
	CmtCommitValue* commitval;
	// The value that the committer sends to the receiver in order to
	// commit commitval in the commitment phase.
	GroupElement* computedCommitment;

public:
	/**
	* Constructor that sets the given random value, committed value and the commitment object.
	* This constructor is package private. It should only be used by the classes in the package.
	* @param r random value used for commit.
	* @param commitVal the committed value
	* @param computedCommitment the commitment
	*/
	CmtPedersenCommitmentPhaseValues(BigIntegerRandomValue* r, CmtCommitValue* commitVal,
		GroupElement* computedCommitment) {
		this->r = r;
		this->commitval = commitVal;
		this->computedCommitment = computedCommitment;
	};

	/**
	* @return The random value used in the computation of the commitment.
	*/
	BigIntegerRandomValue* getR() override { return r; };

	/**
	* Returns the value that the committer commits about. 
	* This value is not sent to the receiver in the commitment phase, 
	* it is sent in the decommitment phase.
	*/
	CmtCommitValue* getX() override { return commitval; };

	/**
	* Returns the value that the committer sends to the receiver in order to commit commitval in 
	* the commitment phase.
	*/
	void* getComputedCommitment() override { return computedCommitment; };
};

/*
* This abstract class performs all the core functionality of the receiver side of Pedersen commitment.
* Specific implementations can extend this class and add or override functions as necessary.
*/
class CmtPedersenReceiverCore : public CmtReceiver {
	/*
	* runs the following protocol:
	* "Commit phase
	*		SAMPLE a random value a <- Zq
	*		COMPUTE h = g^a
	*		SEND h to C
	*		WAIT for message c from C
	*		STORE values (h,c)
	*	Decommit phase
	*		WAIT for (r, x)  from C
	*		IF  c = g^r * h^x AND x <- Zq
	*	    	OUTPUT ACC and value x
	*		ELSE
	*	        OUTPUT REJ"
	*
	*/

protected:
	ChannelServer* channel;
	DlogGroup* dlog;
	std::mt19937 random;
	biginteger trapdoor; // sampled random value in Zq that will be the trpadoor.
	// h is a value calculated during the creation of this receiver and is sent to
	// the committer once in the beginning.
	GroupElement* h;
	// The committer may commit many values one after the other without decommitting.
	// And only at a later time decommit some or all those values. In order to keep track
	// of the commitments and be able to relate them afterwards to the decommitments we keep 
	// them in the commitmentMap. The key is some unique id known to the application
	// running the committer. The exact same id has to be use later on to decommit the 
	// corresponding values, otherwise the receiver will reject the decommitment.
	map<long, CmtPedersenCommitmentMessage*> commitmentMap;


	/**
	* This constructor only needs to get a connected channel (to the committer). 
	* All the other needed elements have default values.
	* If this constructor is used for the recevier then also the default constructor 
	* needs to be used by the committer.
	*/
	CmtPedersenReceiverCore(ChannelServer* channel);

	/**
	* Constructor that receives a connected channel (to the committer),the DlogGroup agreed upon between them and a SecureRandom object.
	* The Committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	*/
	CmtPedersenReceiverCore(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random) {
		doConstruct(channel, dlog, random);
	}

private:
	biginteger qMinusOne;

	/**
	* Sets the given parameters and execute the preprocess phase of the scheme.
	* @param channel
	* @param dlog
	* @param random
	*/
	void doConstruct(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random);

	/**
	* Runs the preprocess stage of the protocol:
	* "SAMPLE a random value a <- Zq
	*	COMPUTE h = g^a
	*	SEND h to C".
	* The pre-process phase is performed once per instance.
	* If different values are required, a new instance of the receiver and the committer
	* need to be created.
	*/
	void preProcess();
public:
	/**
	* Wait for the committer to send the commitment. When the message is received and
	* after reconstructing the group element, save it in the commitmentMap using the id
	* also received in the message.<P>
	* Pseudo code:<P>
	* "WAIT for message c from C<P>
	*  STORE values (h,c)".
	*/
	CmtRBasicCommitPhaseOutput* receiveCommitment() override;

	/**
	* Wait for the decommitter to send the decommitment message.
	* If there had been a commitment for the requested id then proceed with validation,
	* otherwise reject.
	*/
	CmtCommitValue* receiveDecommitment(long id) override;

	/**
	* Run the decommitment phase of the protocol:<P>
	* "IF  c = g^r * h^x AND x <- Zq<P>
	*	    OUTPUT ACC and value x<P>
	*	ELSE<P>
	*	    OUTPUT REJ".	<P>
	* @param id of the commitment
	* @param x
	* @param r
	* @return the committed value
	*/
	CmtCommitValue* verifyDecommitment(CmtCCommitmentMsg* commitmentMsg,
		CmtCDecommitmentMessage* decommitmentMsg) override;

	void** getPreProcessedValues() override;
	int getPreProcessedValuesSize() override;

	void* getCommitmentPhaseValues(long id) override {
		return dlog->reconstructElement(true, 
			(GroupElementSendableData*) commitmentMap[id]->getCommitment());
	};
};

/**
* This abstract class performs all the core functionality of the committer side of
* Pedersen commitment. <p>
* Specific implementations can extend this class and add or override functions as necessary.
*/
class CmtPedersenCommitterCore : public CmtCommitter {
	/*
	* runs the following protocol:
	* "Commit phase
	*		IF NOT VALID_PARAMS(G,q,g)
	*			REPORT ERROR and HALT
	*		WAIT for h from R
	*		IF NOT h in G
	*			REPORT ERROR and HALT
	* 		SAMPLE a random value r <- Zq
	* 		COMPUTE  c = g^r * h^x
	* 		SEND c
	*	Decommit phase
	*		SEND (r, x) to R
	*		OUTPUT nothing."
	*
	*/
protected:
	ChannelServer* channel;
	DlogGroup* dlog;
	std::mt19937 random;
	// the key to the map is an ID and the value is a structure that has the Committer's
	// private input x in Zq,the random value used to commit x and the actual commitment.
	// Each committed value is sent together with an ID so that the receiver can keep it in
	// some data structure. This is necessary in the cases that the same instances of committer
	// and receiver can be used for performing various commitments utilizing the values calculated
	// during the pre-process stage for the sake of efficiency.
	map<long, CmtPedersenCommitmentPhaseValues*> commitmentMap;
	// the content of the message obtained from the receiver during the pre-process phase which occurs upon construction.
	GroupElement* h;

	/**
	* Constructor that receives a connected channel (to the receiver) and chooses 
	* default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	*/
	CmtPedersenCommitterCore(ChannelServer* channel);

	/**
	* Constructor that receives a connected channel (to the receiver),
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	*/
	CmtPedersenCommitterCore(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random) {
		doConstruct(channel, dlog, random);
	};
private:
	biginteger qMinusOne;
	/**
	* Sets the given parameters and execute the preprocess phase of the scheme.
	* @param channel
	* @param dlog
	* @param random
	*/
	void doConstruct(ChannelServer* channel, DlogGroup* dlog, std::mt19937 randomm);
	/**
	* Runs the preprocess phase of the commitment scheme:
	* "WAIT for h from R
	* IF NOT h in G
	*	REPORT ERROR and HALT"
	*/
	void preProcess();
	/**
	* Receives message from the receiver.
	* @return the received message
	*/
	CmtPedersenPreprocessMessage* waitForMessageFromReceiver();

public:
	/**
	* Runs the following lines of the commitment scheme: <P>
	* "SAMPLE a random value r <- Zq<P>
	* 	COMPUTE  c = g^r * h^x". <p>
	*/
	CmtCCommitmentMsg* generateCommitmentMsg(CmtCommitValue* input, long id) override;
	
	/**
	* Runs the commit phase of the commitment scheme. <P>
	* "SAMPLE a random value r <- Zq<P>
	* 	COMPUTE  c = g^r * h^x<P>
	* 	SEND c".
	*/
	void commit(CmtCommitValue* in, long id) override;
	CmtCDecommitmentMessage* generateDecommitmentMsg(long id) override;
	/**
	* Runs the decommit phase of the commitment scheme.<P>
	* "SEND (r, x) to R<P>
	*	OUTPUT nothing."
	*/
	void decommit(long id) override;
	
	void** getPreProcessValues() override;
	CmtCommitmentPhaseValues* getCommitmentPhaseValues(long id) override{
		return commitmentMap[id]; 
	};
};

/**
* Concrete implementation of committer that executes the Pedersen commitment scheme 
* in the committer's point of view.<p>
* For more information see Protocol 6.5.3, page 164 of 
* <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes 
* document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class CmtPedersenCommitter : public CmtPedersenCommitterCore, public CmtCommitter, 
	public PerfectlyHidingCmt, public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) 
	* and chooses default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenCommitter(ChannelServer* channel) : CmtPedersenCommitterCore(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), 
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	*/
	CmtPedersenCommitter(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random) :
		CmtPedersenCommitterCore(channel, dlog, random) {};
	
	CmtCommitValue* generateCommitValue(byte* x, int len) override;
	byte* generateBytesFromCommitValue(CmtCommitValue* value) override;
	CmtCommitValue* sampleRandomCommitValue() override;
};

/**
* Concrete implementation of receiver that executes the Pedersen commitment
* scheme in the receiver's point of view.<p>
* For more information see Protocol 6.5.3, page 164 of
* <i>Efficient Secure Two-Party Protocols</i> by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.1 of pseudo codes 
* document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf} .<p>
*/
class CmtPedersenReceiver : public CmtPedersenReceiverCore, public CmtReceiver, 
	public PerfectlyHidingCmt, public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The committer needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenReceiver(ChannelServer* channel) : CmtPedersenReceiverCore(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	* The committer needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	* @throws SecurityLevelException if the given dlog is not DDH secure
	* @throws InvalidDlogGroupException if the given dlog is not valid.
	* @throws IOException if there was a problem in the communication
	*/
	CmtPedersenReceiver(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random) :
		CmtPedersenReceiverCore(channel, dlog, random) {};

	/**
	* This function converts the given commit value to a byte array.
	* @param value
	* @return the generated bytes.
	*/
	byte* generateBytesFromCommitValue(CmtCommitValue* value) override;
};

/**
* Concrete implementation of committer with proofs.
* This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
*/
class CmtPedersenWithProofsCommitter : public CmtPedersenCommitter, public CmtWithProofsCommitter {
private:
	// proves that the committer knows the committed value.
	ZKPOKFromSigmaCmtPedersenProver* knowledgeProver;
	// proves that the committed value is x.
	// usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to prove committed value.
	// in Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	// in order to be able to use the Pedersen scheme we need to prove committed value with ZKPOK instead.
	ZKPOKFromSigmaCmtPedersenProver* committedValProver;
	
	/**
	* Creates the ZK provers using sigma protocols that prove Pedersen's proofs.
	* @param t
	*/
	void doConstruct(int t);

public:
	/**
	* Default constructor that gets the channel and creates the ZK provers with default Dlog group.
	* @param channel
	*/
	CmtPedersenWithProofsCommitter(ChannelServer* channel, int statisticalParamater) :
		CmtPedersenCommitter(channel) { doConstruct(statisticalParamater); };

	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses them to
	* create the ZK provers.
	* @param channel
	* @param dlog
	* @param t statistical parameter
	* @param random
	*/
	CmtPedersenWithProofsCommitter(ChannelServer* channel, DlogGroup* dlog, int t, 
		std::mt19937 random) : CmtPedersenCommitter(channel, dlog, random) { doConstruct(t); };
	void proveKnowledge(long id) override;
	void proveCommittedValue(long id) override;
};

/**
* Concrete implementation of receiver with proofs.
* This implementation uses ZK based on SigmaPedersenKnowledge and SIgmaPedersenCommittedValue.
*/
class CmtPedersenWithProofsReceiver : public CmtPedersenReceiver, public CmtWithProofsReceiver {
private:
	// Verifies that the committer knows the committed value.
	ZKPOKFromSigmaCmtPedersenVerifier* knowledgeVerifier;
	// Verifies that the committed value is x.
	// Usually, if the commitment scheme is PerfectlyBinding secure, than a ZK is used to verify committed value.
	// In Pedersen, this is not the case since Pedersen is not PerfectlyBinding secure.
	// In order to be able to use the Pedersen scheme we need to verify committed value with ZKPOK instead.
	ZKPOKFromSigmaCmtPedersenVerifier* committedValVerifier;
	/**
	* Creates the ZK verifiers using sigma protocols that verifies Pedersen's proofs.
	* @param t
	*/
	void doConstruct(int t);
public:
	/**
	* Default constructor that gets the channel and creates the ZK verifiers with default Dlog group.
	* @param channel
	*/
	CmtPedersenWithProofsReceiver(ChannelServer* channel, int t) : CmtPedersenReceiver(channel) {
		doConstruct(t);
	};

	/**
	* Constructor that gets the channel, dlog, statistical parameter and random and uses them to create the ZK provers.
	* @param channel
	* @param dlog
	* @param t statistical parameter
	* @param random
	*/
	CmtPedersenWithProofsReceiver(ChannelServer* channel, DlogGroup* dlog, int t,
		std::mt19937 random) : CmtPedersenReceiver(channel, dlog, random) { doConstruct(t); };

	bool verifyKnowledge(long id) override;
	
	CmtBigIntegerCommitValue* verifyCommittedValue(long id) override;
};

/**
* Concrete implementation of committer that executes the Pedersen trapdoor commitment
* scheme in the committer's point of view.<p>
* This commitment is also a trapdoor commitment in the sense that the receiver after
* the commitment phase has a trapdoor value, that if known by the committer would enable
* it to decommit to any value. <p>
* This trapdoor is output by the receiver and can be used by a higher-level application
* (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).<p>
*
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i>
* by Hazay-Lindell.<p>
*
* The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes document 
* at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class CmtPedersenTrapdoorCommitter : public CmtPedersenCommitter, public CmtCommitter, 
	public PerfectlyHidingCmt, public CmtOnBigInteger {

	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The receiver needs to be instantiated with the default constructor too.
	* @param channel
	*/
	CmtPedersenTrapdoorCommitter(ChannelServer* channel) : CmtPedersenCommitter(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), the DlogGroup agreed upon between them and a SecureRandom object.
	* The Receiver needs to be instantiated with the same DlogGroup, otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	*/
	CmtPedersenTrapdoorCommitter(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random) :
		CmtPedersenCommitter(channel, dlog, random) {};

	/**
	* Validate the h value received from the receiver in the pre process phase.
	* @param trap the trapdoor outputed from the receiver's commit phase.
	* @return true, if valid; false, otherwise.
	*/
	bool validate(CmtRCommitPhaseOutput* trap);
};

/**
* Concrete implementation of receiver that executes the Pedersen trapdoor commitment
* scheme in the receiver's point of view.<p>
* This commitment is also a trapdoor commitment in the sense that the receiver after
* the commitment phase has a trapdoor value, that if known by the committer would enable
* it to decommit to any value. <p>
* This trapdoor is output by the receiver and can be used by a higher-level application
* (e.g., by the ZK transformation of a sigma protocol to a zero-knowledge proof of knowledge).<p>
* For more information see Protocol 6.5.3, page 164 of <i>Efficient Secure Two-Party Protocols</i>
* by Hazay-Lindell.<p>
* The pseudo code of this protocol can be found in Protocol 3.3 of pseudo codes 
* document at {@link http://cryptobiu.github.io/scapi/SDK_Pseudocode.pdf}.<p>
*/
class CmtPedersenTrapdoorReceiver : public CmtPedersenReceiver, public CmtReceiver, 
	public PerfectlyHidingCmt, public CmtOnBigInteger {
public:
	/**
	* Constructor that receives a connected channel (to the receiver) and chooses default dlog and random.
	* The committer needs to be instantiated with the default constructor too.
	* @param ServerChannel
	*/
	CmtPedersenTrapdoorReceiver(ChannelServer* channel) : CmtPedersenReceiver(channel) {};

	/**
	* Constructor that receives a connected channel (to the receiver), 
	* the DlogGroup agreed upon between them and a SecureRandom object.
	* The committer needs to be instantiated with the same DlogGroup, 
	* otherwise nothing will work properly.
	* @param channel
	* @param dlog
	* @param random
	*/
	CmtPedersenTrapdoorReceiver(ChannelServer* channel, DlogGroup* dlog, std::mt19937 random) :
		CmtPedersenReceiver(channel, dlog, random) {};

	/**
	* Returns the receiver's trapdoor from the preprocess phase.
	*/
	biginteger getTrapdoor() { return trapdoor; };
	CmtRBasicCommitPhaseOutput* receiveCommitment() override {
		// get the output from the super.receiverCommiotment.
		CmtRBasicCommitPhaseOutput* output = this->receiveCommitment();
		// wrap the output with the trapdoor.
		return new CmtRTrapdoorCommitPhaseOutput(trapdoor, output->getCommitmentId()); 
	};
};
