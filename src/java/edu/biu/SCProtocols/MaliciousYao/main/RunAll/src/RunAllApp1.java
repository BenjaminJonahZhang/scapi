import java.io.FileWriter;
import java.io.IOException;


public class RunAllApp1 {
	
	private static final String HOME_DIR = "C:/GitHub/Development/MaliciousYaoProtocol/MaliciousYao";
	private static final String AES_CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/AES/NigelAes.txt";
	private static final String AES_CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/AES/AESPartyOneInputs.txt";
	private static final String ADD_CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/ADD/NigelAdd32.txt";
	private static final String ADD_CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/ADD/ADDPartyOneInputs.txt";
	private static final String SHA1_CIRCUIT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/NigelSHA1.txt";
	private static final String SHA1_CIRCUIT_INPUT_FILENAME = HOME_DIR + "/assets/circuits/SHA1/SHA1PartyOneInputs.txt";
	
	private static final String AES_CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1Input.txt";
	private static final String AES_BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/aes";
	private static final String AES_BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/cr";
	private static final String ADD_CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputAdd.txt";
	private static final String ADD_BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/add";
	private static final String ADD_BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/addCr";
	private static final String SHA1_CIRCUIT_CHEATING_RECOVERY = HOME_DIR + "/assets/circuits/CheatingRecovery/UnlockP1InputASha1.txt";
	private static final String SHA1_BUCKETS_PREFIX_MAIN = HOME_DIR + "/data/P1/sha";
	private static final String SHA1_BUCKETS_PREFIX_CR = HOME_DIR + "/data/P1/shaCr";
	
	public static void main(String[] args) throws IOException {
		
		int N1_32 = 32;
		int B1_32 = 8;
		int s1_32 = 40;
		double p1_32 = 0.73;
	
		int N2_32 = 32;
		int B2_32 = 24;
		int s2_32 = 40;
		double p2_32 = 0.8;
		
		int N1_128 = 128;
		int B1_128 = 6;
		int s1_128 = 40;
		double p1_128 = 0.77;
		
		int N2_128 = 128;
		int B2_128 = 14;
		int s2_128 = 40;
		double p2_128 = 0.76;
		
		int N1_1024 = 1024;
		int B1_1024 = 4;
		int s1_1024 = 40;
		double p1_1024 = 0.72;
		
		int N2_1024 = 1024;
		int B2_1024 = 10;
		int s2_1024 = 40;
		double p2_1024 = 0.85;
		
		String outputFileOffline = "AES_Offline_P1.csv";
		String outputFileOnline = "AES_Online_P1.csv";
		
		//Delete the existing files.
		FileWriter outputOffline = new FileWriter(outputFileOffline);
		outputOffline.close();
		FileWriter outputOnline = new FileWriter(outputFileOnline);
		outputOnline.close();
		OfflineAppP1 aesOffline = new OfflineAppP1(AES_CIRCUIT_FILENAME, AES_CIRCUIT_INPUT_FILENAME, AES_CIRCUIT_CHEATING_RECOVERY, AES_BUCKETS_PREFIX_MAIN, AES_BUCKETS_PREFIX_CR);
		OnlineAppP1 aesOnline = new OnlineAppP1();
//		
		System.out.println("Run AES Offline, 32 buckets");
		aesOffline.run(N1_32, B1_32, s1_32, p1_32, N2_32, B2_32, s2_32, p2_32, outputFileOffline);
		
		System.out.println("Run AES Online, 32 buckets");
		aesOnline.run(AES_CIRCUIT_FILENAME, AES_CIRCUIT_INPUT_FILENAME, AES_CIRCUIT_CHEATING_RECOVERY, AES_BUCKETS_PREFIX_MAIN, AES_BUCKETS_PREFIX_CR, N1_32, B1_32, s1_32, p1_32, N2_32, B2_32, s2_32, p2_32, outputFileOnline);
		
//		System.out.println("Run AES Offline, 128 buckets");
//		aesOffline.run(N1_128, B1_128, s1_128, p1_128, N2_128, B2_128, s2_128, p2_128, outputFileOffline);
//		
//		System.out.println("Run AES Online, 128 buckets");
//		aesOnline.run(AES_CIRCUIT_FILENAME, AES_CIRCUIT_INPUT_FILENAME, AES_CIRCUIT_CHEATING_RECOVERY, AES_BUCKETS_PREFIX_MAIN, AES_BUCKETS_PREFIX_CR, N1_128, B1_128, s1_128, p1_128, N2_128, B2_128, s2_128, p2_128, outputFileOnline);
//		System.out.println("Run AES, 1024 buckets");
//		aes.run(N1_1024, B1_1024, s1_1024, p1_1024, N2_1024, B2_1024, s2_1024, p2_1024);
	
//		System.out.println("Run ADD, 32 buckets");
//		AppP1 add = new AppP1();
//		add.run(ADD_CIRCUIT_FILENAME, ADD_CIRCUIT_INPUT_FILENAME, ADD_CIRCUIT_CHEATING_RECOVERY, ADD_BUCKETS_PREFIX_MAIN, ADD_BUCKETS_PREFIX_CR, N1_32, B1_32, s1_32, p1_32, N2_32, B2_32, s2_32, p2_32);
//		System.out.println("Run ADD, 128 buckets");
//		add.run(ADD_CIRCUIT_FILENAME, ADD_CIRCUIT_INPUT_FILENAME, ADD_CIRCUIT_CHEATING_RECOVERY, ADD_BUCKETS_PREFIX_MAIN, ADD_BUCKETS_PREFIX_CR, N1_128, B1_128, s1_128, p1_128, N2_128, B2_128, s2_128, p2_128);
//		System.out.println("Run ADD, 1024 buckets");
//		add.run(ADD_CIRCUIT_FILENAME, ADD_CIRCUIT_INPUT_FILENAME, ADD_CIRCUIT_CHEATING_RECOVERY, ADD_BUCKETS_PREFIX_MAIN, ADD_BUCKETS_PREFIX_CR, N1_1024, B1_1024, s1_1024, p1_1024, N2_1024, B2_1024, s2_1024, p2_1024);

//		AppP1 sha = new AppP1();
//		sha.run(SHA1_CIRCUIT_FILENAME, SHA1_CIRCUIT_INPUT_FILENAME, SHA1_CIRCUIT_CHEATING_RECOVERY, SHA1_BUCKETS_PREFIX_MAIN, SHA1_BUCKETS_PREFIX_CR, N1_32, B1_32, s1_32, p1_32, N2_32, B2_32, s2_32, p2_32);
//		sha.run(SHA1_CIRCUIT_FILENAME, SHA1_CIRCUIT_INPUT_FILENAME, SHA1_CIRCUIT_CHEATING_RECOVERY, SHA1_BUCKETS_PREFIX_MAIN, SHA1_BUCKETS_PREFIX_CR, N1_128, B1_128, s1_128, p1_128, N2_128, B2_128, s2_128, p2_128);
//		sha.run(SHA1_CIRCUIT_FILENAME, SHA1_CIRCUIT_INPUT_FILENAME, SHA1_CIRCUIT_CHEATING_RECOVERY, SHA1_BUCKETS_PREFIX_MAIN, SHA1_BUCKETS_PREFIX_CR, N1_1024, B1_1024, s1_1024, p1_1024, N2_1024, B2_1024, s2_1024, p2_1024);

	}
}
