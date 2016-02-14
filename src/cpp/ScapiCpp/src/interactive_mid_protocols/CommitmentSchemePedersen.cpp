#include "../../include/interactive_mid_protocols/CommitmentSchemePedersen.hpp"
#include "../../include/primitives/DlogOpenSSL.hpp"

/*********************************/
/*   CmtPedersenReceiverCore     */
/*********************************/
CmtPedersenReceiverCore::CmtPedersenReceiverCore(shared_ptr<ChannelServer> channel) {
	auto r = get_seeded_random();
	auto dg = make_shared<OpenSSLDlogZpSafePrime>(256, r);
	doConstruct(channel, dg, r);
};

void CmtPedersenReceiverCore::doConstruct(shared_ptr<ChannelServer> channel, 
	shared_ptr<DlogGroup> dlog, std::mt19937 random) {
	// the underlying dlog group must be DDH secure.
	DDH* ddh = dynamic_cast<DDH*>(dlog.get());
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
	trapdoor = getRandomInRange(0, qMinusOne, random);
	h = dlog->exponentiate(dlog->getGenerator(), trapdoor);
	auto sendableData = h->generateSendableData();
	auto raw_msg = sendableData->toByteArray();
	int len = sendableData->getSerializedSize();
	channel->write_fast(raw_msg.get(), len);
}

shared_ptr<CmtRCommitPhaseOutput> CmtPedersenReceiverCore::receiveCommitment() {
	// create an empty CmtPedersenCommitmentMessage 
	auto msg = make_shared<CmtPedersenCommitmentMessage>();
	// read encoded CmtPedersenCommitmentMessage from channel
	auto v = channel->read_one();
	// init the empy CmtPedersenCommitmentMessage using the encdoed data
	msg->init_from_byte_array(&(v->at(0)), v->size());
	commitmentMap[msg->getId()] = msg;
	delete v; // no need to hold it anymore - already decoded and copied
	return make_shared<CmtRBasicCommitPhaseOutput>(msg->getId());
}
