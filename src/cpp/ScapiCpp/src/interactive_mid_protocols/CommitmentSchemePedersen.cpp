#include "../../include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../../include/primitives/DlogCryptopp.hpp"

/*********************************/
/*   CmtPedersenReceiverCore     */
/*********************************/
CmtPedersenReceiverCore::CmtPedersenReceiverCore(ChannelServer* channel) {
	auto r = get_seeded_random();
	DlogGroup * dg = new CryptoPpDlogZpSafePrime(256, r);
	doConstruct(channel, dg, r);
};

void CmtPedersenReceiverCore::doConstruct(ChannelServer* channel, DlogGroup* dlog,
	std::mt19937 random) {
	// the underlying dlog group must be DDH secure.
	DDH* ddh = dynamic_cast<DDH*>(dlog);
	if (!ddh)
		throw SecurityLevelException("DlogGroup should have DDH security level");

	// validate the params of the group.
	if (!dlog->validateGroup())
		throw InvalidDlogGroupException("Group is not valid");

	this->channel = channel;
	this->dlog = dlog;
	this->random = random;
	qMinusOne = dlog->getOrder()-1;
	// the pre-process phase is actually performed at construction
	preProcess();
}

void CmtPedersenReceiverCore::preProcess() {
	boost::random::uniform_int_distribution<biginteger> ui(0, qMinusOne);
	trapdoor = ui(random);
	h = dlog->exponentiate(dlog->getGenerator(), trapdoor);
	auto sendableData = h->generateSendableData();
	byte* raw_msg = sendableData->toByteArray();
	int len = sendableData->getSerializedSize();
	channel->write_fast(raw_msg, len);
}

CmtRBasicCommitPhaseOutput* CmtPedersenReceiverCore::receiveCommitment() {
	auto v = channel->read_one();
	// creata a sendableData object from the dlog to support polymorphism
	GroupElementSendableData* sendableData = dlog->getGenerator()->generateSendableData();
	sendableData->init_from_byte_array(&(v->at(0)), v->size());
	//CmtPedersenCommitmentMessage* msg = new CmtPedersenCommitmentMessage(sendableData);

	//commitmentMap.put(Long.valueOf(msg.getId()), msg);
	//return new CmtRBasicCommitPhaseOutput(msg.getId());
}
