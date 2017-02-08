#include "MaliciousYaoProtocol.h"

/**
 * Create the offline protocol.
 * It contains the following steps:
 * 1. Create the communication between the parties
 * 2. Create circuits and other execution parameters for the protocol
 * 3. Create the OT sender / receiver
 * 4. Create the protocol party
 * 5. Create MaliciousYaoHandler with all the created arguments.
 */
JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_NativeMaliciousYao_MaliciousYaoOfflineParty_createYaoParty
(JNIEnv * env, jobject, jint id, jstring configFileName) {
	//Convert the jni objects to c++ objects.
	const char* configFile = env->GetStringUTFChars(configFileName, NULL);
	MaliciousYaoConfig yaoConfig(configFile);
	//set io_service for peer to peer communication
	boost::asio::io_service* io_service = new boost::asio::io_service();
	//set crypto primitives
	CryptoPrimitives::setCryptoPrimitives(yaoConfig.ec_file);
	
	CryptoPrimitives::setNumOfThreads(yaoConfig.num_threads);

	cout << "N1 = " << yaoConfig.n1 << " B1 = " << yaoConfig.b1 << " s1 = " << yaoConfig.s1 << " p1 = " << yaoConfig.p1 << " N2 = " << yaoConfig.n2 << " B2 = " << yaoConfig.b2 <<
		" s2 = " << yaoConfig.s2 << " p2 = " << yaoConfig.p2 << endl;

	shared_ptr<CommunicationConfig> commConfig(new CommunicationConfig(yaoConfig.parties_file, id, *io_service));
	auto commParty = commConfig->getCommParty();
	//make connection
	for (int i = 0; i < commParty.size(); i++)
		commParty[i]->join(500, 5000);

	//make circuit
	vector<shared_ptr<GarbledBooleanCircuit>> mainCircuit;
	vector<shared_ptr<GarbledBooleanCircuit>> crCircuit;

	mainCircuit.resize(yaoConfig.num_threads);
	crCircuit.resize(yaoConfig.num_threads);

	for (int i = 0; i<yaoConfig.num_threads; i++) {
		mainCircuit[i] = shared_ptr<GarbledBooleanCircuit>(GarbledCircuitFactory::createCircuit(yaoConfig.main_circuit_file,
			GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
		crCircuit[i] = shared_ptr<GarbledBooleanCircuit>(CheatingRecoveryCircuitCreator(yaoConfig.cr_circuit_file, mainCircuit[i]->getNumberOfGates()).create());
	}
	auto mainExecution = make_shared<ExecutionParameters>(nullptr, mainCircuit, yaoConfig.n1, yaoConfig.s1, yaoConfig.b1, yaoConfig.p1);
	auto crExecution = make_shared<ExecutionParameters>(nullptr, crCircuit, yaoConfig.n2, yaoConfig.s2, yaoConfig.b2, yaoConfig.p2);

	MaliciousYaoHandler* handler = nullptr;
	if (id == 1) {

		//OT malicious sender
		//Get the data of the OT server.
		auto maliciousOtServer = commConfig->getMaliciousOTServer();
#ifdef _WIN32
		shared_ptr<OTBatchSender> otSender = make_shared<OTExtensionMaliciousSender>(*maliciousOtServer, mainCircuit[0]->getNumberOfInputs(2));
#else
		shared_ptr<OTBatchSender> otSender = make_shared<OTExtensionBristolSender>(maliciousOtServer->getPort(), false, commConfig->getCommParty()[0]);
#endif

		OfflineProtocolP1* p1 = new OfflineProtocolP1(mainExecution, crExecution, commConfig, otSender);

		handler = new MaliciousYaoHandler((long)p1, yaoConfig, commConfig, io_service);
	}
	else if (id == 2) {
		//OT malicious receiver
		//Get the data of the OT server.
		auto maliciousOtServer = commConfig->getMaliciousOTServer();
#ifdef _WIN32
		shared_ptr<OTBatchReceiver> otReceiver = make_shared<OTExtensionMaliciousReceiver>(*maliciousOtServer, mainCircuit[0]->getNumberOfInputs(2));
#else
		shared_ptr<OTBatchReceiver> otReceiver = make_shared<OTExtensionBristolReceiver>(maliciousOtServer->getIpAddress().to_string(), maliciousOtServer->getPort(), false, commConfig->getCommParty()[0]);
#endif

		OfflineProtocolP2* p2 = new OfflineProtocolP2(mainExecution, crExecution, commConfig, otReceiver, false);
		handler = new MaliciousYaoHandler((long)p2, yaoConfig, commConfig, io_service);
	}
	return (long)handler;
}

/**
 * Execute the offline protocol.
 */
JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_NativeMaliciousYao_MaliciousYaoOfflineParty_runProtocol
(JNIEnv * env, jobject, jint id, jlong maliciousHandler) {
	string tmp = "reset times";
	byte tmpBuf[20];
	MaliciousYaoHandler* handler = (MaliciousYaoHandler*)maliciousHandler;
	auto commParty = handler->getCommConfig()->getCommParty();
	if (id == 1) {
		OfflineProtocolP1* p1 = (OfflineProtocolP1*)handler->getParty();
		int readsize = commParty[0]->read(tmpBuf, tmp.size());
		commParty[0]->write((const byte *)tmp.c_str(), tmp.size());
		
		auto start = chrono::high_resolution_clock::now();

		p1->run();

		// we measure how much time did the protocol take
		auto end = chrono::high_resolution_clock::now();
		auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		cout << "\nOffline protocol party 1 took " << runtime << " miliseconds.\n";

		cout << "\nSaving buckets to files...\n";
		start = chrono::high_resolution_clock::now();

		auto mainBuckets = p1->getMainBuckets();
		auto crBuckets = p1->getCheatingRecoveryBuckets();
		mainBuckets->saveToFiles(handler->getConfig().bucket_prefix_main1);
		crBuckets->saveToFiles(handler->getConfig().bucket_prefix_cr1);

		end = chrono::high_resolution_clock::now();
		runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		cout << "\nSaving buckets took " << runtime << " miliseconds.\n";

	}
	else if (id == 2) {
		OfflineProtocolP2* p2 = (OfflineProtocolP2*)handler->getParty();
		
		commParty[0]->write((const byte *)tmp.c_str(), tmp.size());
		int readsize = commParty[0]->read(tmpBuf, tmp.size());
		
		auto start = chrono::high_resolution_clock::now();

		//run the protocol
		p2->run();

		// we measure how much time did the protocol take
		auto end = chrono::high_resolution_clock::now();
		auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		cout << "\nOffline protocol party 2 took " << runtime << " miliseconds.\n";

		cout << "\nSaving buckets to files...\n";
		start = chrono::high_resolution_clock::now();

		auto mainBuckets = p2->getMainBuckets();
		auto crBuckets = p2->getCheatingRecoveryBuckets();
		mainBuckets->saveToFiles(handler->getConfig().bucket_prefix_main2);
		crBuckets->saveToFiles(handler->getConfig().bucket_prefix_cr2);
		p2->getMainProbeResistantMatrix()->saveToFile(handler->getConfig().main_matrix);
		p2->getCheatingRecoveryProbeResistantMatrix()->saveToFile(handler->getConfig().cr_matrix);

		end = chrono::high_resolution_clock::now();
		runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		cout << "\nSaving buckets took " << runtime << " miliseconds.\n";
	}
}

/**
 * Delete the allocated memory.
 * First delete the protocol party, then delete the handler.
 */
JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_NativeMaliciousYao_MaliciousYaoOfflineParty_deleteMaliciousYao
(JNIEnv *, jobject, jint id, jlong maliciousHandler) {
	MaliciousYaoHandler* handler = (MaliciousYaoHandler*)maliciousHandler;
	if (id == 1) {
		delete (OfflineProtocolP1*)handler->getParty();
	} else 
		delete (OfflineProtocolP2*)handler->getParty();
	delete handler;
}

/**
* Create the online protocol.
* It contains the following steps:
* 1. Create the communication between the parties
* 2. Readthe buckets from the disk
* 3. Only p2 - create circuits and other execution parameters for the protocol
* 4. Create the protocol party
* 5. Create MaliciousYaoHandler with all the created arguments.
*/
JNIEXPORT jlong JNICALL Java_edu_biu_SCProtocols_NativeMaliciousYao_MaliciousYaoOnlineParty_createYaoParty
(JNIEnv *env, jobject, jint id, jstring configFileName) {

	//Convert the jni objects to c++ objects.
	const char* configFile = env->GetStringUTFChars(configFileName, NULL);
	MaliciousYaoConfig yaoConfig(configFile);
	//set io_service for peer to peer communication
	boost::asio::io_service* io_service = new boost::asio::io_service();
	//set crypto primitives
	CryptoPrimitives::setCryptoPrimitives(yaoConfig.ec_file);

	CryptoPrimitives::setNumOfThreads(yaoConfig.num_threads);

	shared_ptr<CommunicationConfig> commConfig(new CommunicationConfig(yaoConfig.parties_file, id, *io_service));
	auto commParty = commConfig->getCommParty();
	//make connection
	for (int i = 0; i < commParty.size(); i++)
		commParty[i]->join(500, 5000);

	int BUCKET_ID = 0;

	MaliciousYaoHandler* handler = nullptr;
	if (id == 1) {
		// we load the bundles from file
		vector<shared_ptr<BucketBundle>> mainBuckets(yaoConfig.n1), crBuckets(yaoConfig.n1);
		
		for (int i = 0; i<yaoConfig.n1; i++) {

			mainBuckets[i] = BucketBundleList::loadBucketFromFile(yaoConfig.bucket_prefix_main1 + "." + to_string(BUCKET_ID) + ".cbundle");
			crBuckets[i] = BucketBundleList::loadBucketFromFile(yaoConfig.bucket_prefix_cr1 + "." + to_string(BUCKET_ID++) + ".cbundle");
		}
		auto input = CircuitInput::fromFile(yaoConfig.input_file_1);
		handler = new MaliciousYaoHandler(yaoConfig, commConfig, io_service, mainBuckets, crBuckets, input);
	}
	else if (id == 2) {
		vector<shared_ptr<BucketLimitedBundle>> mainBuckets(yaoConfig.n1), crBuckets(yaoConfig.n1);
		for (int i = 0; i < yaoConfig.n1; i++) {

			mainBuckets[i] = BucketLimitedBundleList::loadBucketFromFile(yaoConfig.bucket_prefix_main2 + "." + to_string(BUCKET_ID) + ".cbundle");
			crBuckets[i] = BucketLimitedBundleList::loadBucketFromFile(yaoConfig.bucket_prefix_cr2 + "." + to_string(BUCKET_ID++) + ".cbundle");
		} 
		
		//create boolean circuit
		auto mainBC = make_shared<BooleanCircuit>(new scannerpp::File(yaoConfig.main_circuit_file));
		auto crBC = make_shared<BooleanCircuit>(new scannerpp::File(yaoConfig.cr_circuit_file));

		//create garbled circuit
		vector<shared_ptr<GarbledBooleanCircuit>> mainCircuit(yaoConfig.b1);
		vector<shared_ptr<GarbledBooleanCircuit>> crCircuit(yaoConfig.b2);

		for (int i = 0; i<yaoConfig.b1; i++) {
			mainCircuit[i] = shared_ptr<GarbledBooleanCircuit>(GarbledCircuitFactory::createCircuit(yaoConfig.main_circuit_file,
				GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
		}

		for (int i = 0; i<yaoConfig.b2; i++) {
			crCircuit[i] = shared_ptr<GarbledBooleanCircuit>(CheatingRecoveryCircuitCreator(yaoConfig.cr_circuit_file, mainCircuit[0]->getNumberOfGates()).create());
		}
		
		auto mainExecution = make_shared<ExecutionParameters>(mainBC, mainCircuit, yaoConfig.n1, yaoConfig.s1, yaoConfig.b1, yaoConfig.p1);
		auto crExecution = make_shared<ExecutionParameters>(crBC, crCircuit, yaoConfig.n2, yaoConfig.s2, yaoConfig.b2, yaoConfig.p2);

		// we load the bundles from file
		auto mainMatrix = make_shared<KProbeResistantMatrix>();
		auto crMatrix = make_shared<KProbeResistantMatrix>();
		mainMatrix->loadFromFile(yaoConfig.main_matrix);
		crMatrix->loadFromFile(yaoConfig.cr_matrix);
		auto input = CircuitInput::fromFile(yaoConfig.input_file_2);
		handler = new MaliciousYaoHandler(yaoConfig, commConfig, io_service, mainExecution, crExecution, mainMatrix, crMatrix, mainBuckets, crBuckets, input);
	}
	return (long)handler;
}

/**
 * Execute the online phase of the protocol.
 * The buckets to use are the bucket indexed by startExecutionNumber to endExecutionNumber.
 */
JNIEXPORT jbyteArray JNICALL Java_edu_biu_SCProtocols_NativeMaliciousYao_MaliciousYaoOnlineParty_runProtocol
(JNIEnv * env, jobject, jint id, jlong maliciousHandler, jint startExecutionNumber, jint endExecutionNumber) {
	MaliciousYaoHandler* handler = (MaliciousYaoHandler*)maliciousHandler;
	auto commParty = handler->getCommConfig()->getCommParty();

	// only now we start counting the running time 
	string tmp = "reset times";
	byte tmpBuf[20];

	vector<long long> times;
	vector<byte> output;
	chrono::high_resolution_clock::time_point start, end;
	long time;

	for (int i = startExecutionNumber; i < endExecutionNumber; i++) {
		if (id == 1) {
			commParty[0]->write((const byte*)tmp.c_str(), tmp.size());
			int readsize = commParty[0]->read(tmpBuf, tmp.size());
			
			auto mainBucket = handler->getMainBuckets1()[i];
			auto crBucket = handler->getCRBuckets1()[i];

			start = chrono::high_resolution_clock::now();

			OnlineProtocolP1 protocol(*(handler->getCommConfig()), *mainBucket, *crBucket);
			protocol.setInput(handler->getInput());
			protocol.run();

			end = chrono::high_resolution_clock::now();
			time = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			times.push_back(time);
		}
		else if (id == 2) {

			int readsize = commParty[0]->read(tmpBuf, tmp.size());
			commParty[0]->write((const byte*)tmp.c_str(), tmp.size());

			auto mainBucket = handler->getMainBuckets2()[i];
			auto crBucket = handler->getCRBuckets2()[i];

			auto mainTables = saveBucketGarbledTables(handler->getConfig().b1, mainBucket.get());
			auto crTables = saveBucketGarbledTables(handler->getConfig().b2, crBucket.get());

			start = chrono::high_resolution_clock::now();

			OnlineProtocolP2 protocol(*(handler->getMainExecution()), *(handler->getCRExecution()), handler->getCommConfig()->getCommParty()[0], mainBucket, crBucket, handler->getMainMatrix().get(), handler->getCRMatrix().get());
			protocol.setInput(*handler->getInput());
			protocol.run();

			end = chrono::high_resolution_clock::now();
			time = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
			times.push_back(time);

			restoreBucketTables(handler->getConfig().b1, mainBucket.get(), mainTables);
			restoreBucketTables(handler->getConfig().b2, crBucket.get(), crTables);
			output = protocol.getOutput().getOutput();
		}
	}
	int count = 0;
	for (int i = 0; i < times.size(); i++) {
		count += times[i];
		cout << times[i] << " ";
	}
	auto average = count / times.size();
	cout << endl;
	cout << times.size() << " executions took in average " << average << " milis." << endl;
	
	//Create a jni object and fill it with the protocol output.
	jbyteArray result = env->NewByteArray(output.size());
	env->SetByteArrayRegion(result, 0, output.size(), (jbyte*)output.data());

	//Return the output
	return result;
}

/**
* Delete the allocated memory.
* First delete the protocol party, then delete the handler.
*/
JNIEXPORT void JNICALL Java_edu_biu_SCProtocols_NativeMaliciousYao_MaliciousYaoOnlineParty_deleteMaliciousYao
(JNIEnv *, jobject, jint id , jlong maliciousHandler) {
	MaliciousYaoHandler* handler = (MaliciousYaoHandler*)maliciousHandler;
	if (id == 1) {
		delete (OnlineProtocolP1*)handler->getParty();
	}
	else
		delete (OnlineProtocolP2*)handler->getParty();
	delete handler;
}

block** saveBucketGarbledTables(int size, BucketLimitedBundle * bucket) {
	block** tables = new block*[size];

	for (int i = 0; i<size; i++) {
		auto bundle = bucket->getLimitedBundleAt(i);
		tables[i] = (block *)_mm_malloc(bundle->getGarbledTablesSize(), SIZE_OF_BLOCK);
		memcpy((byte *)tables[i], (byte *)bundle->getGarbledTables(), bundle->getGarbledTablesSize());
	}

	return tables;

}

void restoreBucketTables(int size, BucketLimitedBundle* bucket, block** tables) {
	for (int i = 0; i<size; i++) {
		bucket->getLimitedBundleAt(i)->setGarbledTables(tables[i]);
	}
	delete[] tables;
}

int main(int argc, char* argv[]) {
	int partyNum = atoi(argv[1]);
	//set io_service for peer to peer communication
	boost::asio::io_service io_service;
	//set crypto primitives
	CryptoPrimitives::setCryptoPrimitives("C:/Github/libscapi/include/configFiles/NISTEC.txt");
	int counter = 1;

	//home directory path for all files
	const  string HOME_DIR = "C:/Github/libscapi/protocols/MaliciousYao/lib/";

	//files path
	const string CIRCUIT_FILENAME = HOME_DIR + string("/assets/circuits/AES/NigelAes.txt");
	const string CIRCUIT_INPUT_FILENAME = HOME_DIR + string("/assets/circuits/AES/AESPartyOneInputs.txt");
	const string CIRCUIT_CHEATING_RECOVERY = HOME_DIR + string("/assets/circuits/CheatingRecovery/UnlockP1Input.txt");
	const string BUCKETS_PREFIX_MAIN = HOME_DIR + string("/data/P1/aes");
	const string BUCKETS_PREFIX_CR = HOME_DIR + string("/data/P1/cr");
	//read config file data and set communication config to make sockets.
	
	int N1 = 32;
	int B1 = 7;
	int s1 = 40;
	double p1 = 0.62;

	int N2 = 32;
	int B2 = 20;
	int s2 = 40;
	double p2 = 0.71;
	int numOfThreads = 8;//atoi(argv[counter++]);
	CryptoPrimitives::setNumOfThreads(numOfThreads);

	cout << "N1 = " << N1 << " B1 = " << B1 << " s1 = " << s1 << " p1 = " << p1 << " N2 = " << N2 << " B2 = " << B2 <<
		" s2 = " << s2 << " p2 = " << p2 << endl;
	
	shared_ptr<CommunicationConfig> commConfig(new CommunicationConfig(HOME_DIR + string("/assets/conf/PartiesConfig.txt"), partyNum, io_service));
	auto commParty = commConfig->getCommParty();
	//make connection
	for (int i = 0; i < commParty.size(); i++)
		commParty[i]->join(500, 5000);

	

	//make circuit
	vector<shared_ptr<GarbledBooleanCircuit>> mainCircuit;
	vector<shared_ptr<GarbledBooleanCircuit>> crCircuit;

	if (numOfThreads == 0)
		numOfThreads = 1;

	mainCircuit.resize(numOfThreads);
	crCircuit.resize(numOfThreads);

	for (int i = 0; i<numOfThreads; i++) {
		mainCircuit[i] = shared_ptr<GarbledBooleanCircuit>(GarbledCircuitFactory::createCircuit(CIRCUIT_FILENAME,
			GarbledCircuitFactory::CircuitType::FIXED_KEY_FREE_XOR_HALF_GATES, true));
		crCircuit[i] = shared_ptr<GarbledBooleanCircuit>(CheatingRecoveryCircuitCreator(CIRCUIT_CHEATING_RECOVERY, mainCircuit[i]->getNumberOfGates()).create());
	}
	auto mainExecution = make_shared<ExecutionParameters>(nullptr, mainCircuit, N1, s1, B1, p1);
	auto crExecution = make_shared<ExecutionParameters>(nullptr, crCircuit, N2, s2, B2, p2);

	string tmp = "reset times";
	cout << "tmp size = " << tmp.size() << endl;
	byte tmpBuf[20];
	int totalTimes = 0;

	if (partyNum == 1) {
		
		cout << "\nP1 start communication\n";

		//OT malicious sender
		//Get the data of the OT server.
		auto maliciousOtServer = commConfig->getMaliciousOTServer();
#ifdef _WIN32
		shared_ptr<OTBatchSender> otSender = make_shared<OTExtensionMaliciousSender>(*maliciousOtServer, mainCircuit[0]->getNumberOfInputs(2));
#else
		shared_ptr<OTBatchSender> otSender = make_shared<OTExtensionBristolSender>(maliciousOtServer->getPort(), false, commConfig->getCommParty()[0]);
#endif
		
		OfflineProtocolP1* protocol = nullptr;
		
		for (int j = 0; j<10; j += 4) {
			cout << "in first loop. num threads = " << j << endl;
			CryptoPrimitives::setNumOfThreads(j);

			for (int i = 0; i < 5; i++) {
				if (protocol != nullptr)
					delete protocol;
				int readsize = commParty[0]->read(tmpBuf, tmp.size());
				commParty[0]->write((const byte *)tmp.c_str(), tmp.size());
				// we start counting the running time just before estalishing communication
				auto start = chrono::high_resolution_clock::now();
				
				// and run the protocol
				protocol = new OfflineProtocolP1(mainExecution, crExecution, commConfig, otSender);
				protocol->run();
			
				// we measure how much time did the protocol take
				auto end = chrono::high_resolution_clock::now();
				auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
				totalTimes += runtime;
				cout << "\nOffline protocol party 1 with " << j << " threads took " << runtime << " miliseconds.\n";

			}

			cout << " average time of running OfflineP1 with " << j << " threads = " << totalTimes / 5 << endl;
			totalTimes = 0;
		}


		cout << "\nSaving buckets to files...\n";
		auto start = chrono::high_resolution_clock::now();

		auto mainBuckets = protocol->getMainBuckets();
		auto crBuckets = protocol->getCheatingRecoveryBuckets();
		mainBuckets->saveToFiles(BUCKETS_PREFIX_MAIN);
		crBuckets->saveToFiles(BUCKETS_PREFIX_CR);

		auto end = chrono::high_resolution_clock::now();
		auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		cout << "\nSaving buckets took " << runtime << " miliseconds.\n";

		delete protocol;

		//end commenication
		io_service.stop();
		
		cout << "\nP1 end communication\n";
	}
	else if (partyNum == 2) {
		
		cout << "\nP1 start communication\n";

		const string MAIN_MATRIX = HOME_DIR + "/data/P2/aes.matrix";
		const string CR_MATRIX = HOME_DIR + "/data/P2/cr.matrix";

		auto maliciousOtServer = commConfig->getMaliciousOTServer();
		cout << "num ot = " << mainCircuit[0]->getNumberOfInputs(2) << endl;
#ifdef _WIN32
		shared_ptr<OTBatchReceiver> otReceiver = make_shared<OTExtensionMaliciousReceiver>(*maliciousOtServer, mainCircuit[0]->getNumberOfInputs(2));
#else
		shared_ptr<OTBatchReceiver> otReceiver = make_shared<OTExtensionBristolReceiver>(maliciousOtServer->getIpAddress().to_string(), maliciousOtServer->getPort(), false, commConfig->getCommParty()[0]);
#endif
		
		OfflineProtocolP2* protocol = nullptr;

		for (int j = 0; j < 10; j += 4) {
			cout << "in first loop. num threads = " << j << endl;
			CryptoPrimitives::setNumOfThreads(j);

			for (int i = 0; i < 5; i++) {

				if (protocol != nullptr)
					delete protocol;

				commParty[0]->write((const byte *)tmp.c_str(), tmp.size());
				int readsize = commParty[0]->read(tmpBuf, tmp.size());
				// we start counting the running time just before estalishing communication
				auto start = chrono::high_resolution_clock::now();

				// and run the protocol
				protocol = new OfflineProtocolP2(mainExecution, crExecution, commConfig, otReceiver, false);
				protocol->run();

				// we measure how much time did the protocol take
				auto end = chrono::high_resolution_clock::now();
				auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
				totalTimes += runtime;
				cout << "\nOffline protocol party 2 with " << j << "threads took " << runtime << " miliseconds.\n";

			}

			cout << " average time of running OfflineP2 with " << j << " threads = " << totalTimes / 5 << endl;
			totalTimes = 0;
		}


		cout << "\nSaving buckets to files...\n";
		auto start = chrono::high_resolution_clock::now();

		auto mainBuckets = protocol->getMainBuckets();
		auto crBuckets = protocol->getCheatingRecoveryBuckets();
		mainBuckets->saveToFiles(BUCKETS_PREFIX_MAIN);
		crBuckets->saveToFiles(BUCKETS_PREFIX_CR);
		protocol->getMainProbeResistantMatrix()->saveToFile(MAIN_MATRIX);
		protocol->getCheatingRecoveryProbeResistantMatrix()->saveToFile(CR_MATRIX);

		auto end = chrono::high_resolution_clock::now();
		auto runtime = chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
		cout << "\nSaving buckets took " << runtime << " miliseconds.\n";

		delete protocol;
		//end commenication
		io_service.stop();
		
		cout << "\nP2 end communication\n";
	}
	else {
		std::cerr << "Usage: libscapi_examples yao <party_number(1|2)> <config_path>" << std::endl;
		return 1;
	}

	return 0;
}
