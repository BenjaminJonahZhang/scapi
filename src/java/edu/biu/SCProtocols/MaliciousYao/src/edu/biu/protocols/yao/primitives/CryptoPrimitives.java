package edu.biu.protocols.yao.primitives;

import java.security.SecureRandom;

import edu.biu.scapi.circuits.encryption.AESFixedKeyMultiKeyEncryption;
import edu.biu.scapi.circuits.encryption.MultiKeyEncryptionScheme;
import edu.biu.scapi.exceptions.FactoriesException;
import edu.biu.scapi.primitives.dlog.DlogGroup;
import edu.biu.scapi.primitives.hash.CryptographicHash;
import edu.biu.scapi.primitives.kdf.KeyDerivationFunction;
import edu.biu.scapi.tools.Factories.CryptographicHashFactory;
import edu.biu.scapi.tools.Factories.DlogGroupFactory;
import edu.biu.scapi.tools.Factories.KdfFactory;

/**
 * This class defines some primitives objects to use in the protocol. <p>
 * 
 * THere are two possibilities to create these primitives object: <P>
 * 1. The user sets the primitives he wants using the inner builder class. <P>
 * 2. In case the user do not want to create a specific implementation of some primitives, he should 
 * call the defaultPrimitives() function that creates default implementations for the primitives.
 * Obviously, we define here the most efficient implementations. <P>
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class CryptoPrimitives {
	
	/*
	 * The following members are the primitives objects which we give a default values.
	 */
	private final DlogGroup dlog;
	private final KeyDerivationFunction kdf;
	private final MultiKeyEncryptionScheme mes;
	private final CryptographicHash hash;
	private final SecureRandom random;
	private final int statisticalParameter;
	private final int numOfThreads;
	
	/**
	 * A constructor that gets a builder and sets the initial members.
	 * @param builder
	 */
	private CryptoPrimitives(Builder builder) {
		// Gets the default values from the builder and set it this class members.
		this.dlog = builder.dlog;
		this.kdf = builder.kdf;
		this.mes = builder.mes;
		this.hash = builder.hash;
		this.random = builder.random;
		this.statisticalParameter = builder.statisticalParameter;
		this.numOfThreads = builder.numOfThreads;
	}
	
	/**
	 * Returns the default Dlog group.
	 */
	public DlogGroup getDiscreteLogGroup() {
		return dlog;
	}
	
	/**
	 * Returns the default KDF.
	 */
	public KeyDerivationFunction getKeyDerivationFunction() {
		return kdf;
	}
	
	/**
	 * Returns the default MultiKeyEncryptionScheme.
	 */
	public MultiKeyEncryptionScheme getMultiKeyEncryptionScheme() {
		return mes;
	}
	
	/**
	 * Returns the default CryptographicHash.
	 */
	public CryptographicHash getCryptographicHash() {
		return hash;
	}
	
	/**
	 * Returns the default secure random object.
	 */
	public SecureRandom getSecureRandom() {
		return random;
	}
	
	/**
	 * Returns the default statistical parameter.
	 */
	public int getStatisticalParameter() {
		return statisticalParameter;
	}
	
	/**
	 * Returns the default number of threads.
	 */
	public int getNumOfThreads() {
		return numOfThreads;
	}

	/**
	 * Inner class that builds the default primitives.
	 * 
	 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
	 *
	 */
	public static class Builder {
		private DlogGroup dlog = null;
		private KeyDerivationFunction kdf = null;
		private MultiKeyEncryptionScheme mes = null;
		private CryptographicHash hash = null;
		private SecureRandom random = null;
		private int statisticalParameter = 0;
		private int numOfThreads;

		/**
		 * Sets the given Dlog group.
		 */
		public Builder dlog(DlogGroup dlog) {
			this.dlog = dlog;
			return this;
		}

		/**
		 * Sets the given kdf.
		 */
		public Builder kdf(KeyDerivationFunction kdf) {
			this.kdf = kdf;
			return this;
		}

		/**
		 * Sets the given MultiKeyEncryptionScheme.
		 */
		public Builder mes(MultiKeyEncryptionScheme mes) {
			this.mes = mes;
			return this;
		}

		/**
		 * Sets the given CryptographicHash.
		 */
		public Builder hash(CryptographicHash hash) {
			this.hash = hash;
			return this;
		}

		/**
		 * Sets the given random.
		 */
		public Builder random(SecureRandom random) {
			this.random = random;
			return this;
		}
		
		/**
		 * Sets the given statistical parameter.
		 */
		public Builder statisticalParameter(int statisticalParameter) {
			this.statisticalParameter = statisticalParameter;
			return this;
		}
		
		/**
		 * Sets the given number of threads.
		 */
		public Builder numOfThreads(int numOfThreads) {
			this.numOfThreads = numOfThreads;
			return this;
		}

		/**
		 * Created a CryptoPrimitives object using this builder instance.
		 * @return
		 */
		public CryptoPrimitives build() {
			return new CryptoPrimitives(this);
		}
	}
	
	/**
	 * Creates a CryptoPrimitives object using default primitives.
	 */
	public static CryptoPrimitives defaultPrimitives() {
		// Initialize mathematical entities required for protocol.
		DlogGroup dlog = null;
		CryptographicHash hash = null;
		KeyDerivationFunction kdf = null;
		MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
		SecureRandom random = new SecureRandom();
		
		try {
			//Use the K-233 koblitz curve, SHA-1 and KdfISO18033.
			dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(K-233)", "Miracl");
			//hash = CryptographicHashFactory.getInstance().getObject("SHA-1", "OpenSSL");
			hash = CryptographicHashFactory.getInstance().getObject("SHA-1", "CryptoPP");
			kdf = KdfFactory.getInstance().getObject("KdfISO18033(SHA-1)");
		} catch (FactoriesException e) {
			e.printStackTrace();
		}

		//Create a CryptoPrimitives object with the created primitives, when statistical parameter = 40 and number of thread = 0. 
		return new CryptoPrimitives.Builder()
			.dlog(dlog)
			.kdf(kdf)
			.mes(mes)
			.hash(hash)
			.random(random)
			.statisticalParameter(40)
			.numOfThreads(0)
			.build();
	}
	
	/**
	 * Creates a CryptoPrimitives object using default primitives.
	 * @param numThreads The nuber of threads to use in the protocol.
	 */
	public static CryptoPrimitives defaultPrimitives(int numThreads) {
		// Initialize mathematical entities required for protocol.
		DlogGroup dlog = null;
		CryptographicHash hash = null;
		KeyDerivationFunction kdf = null;
		MultiKeyEncryptionScheme mes = new AESFixedKeyMultiKeyEncryption();
		SecureRandom random = new SecureRandom();
		
		try {
			//Use the K-233 koblitz curve, SHA-1 and KdfISO18033.
			dlog = DlogGroupFactory.getInstance().getObject("DlogECF2m(K-233)", "Miracl");
			//hash = CryptographicHashFactory.getInstance().getObject("SHA-1", "OpenSSL");
			hash = CryptographicHashFactory.getInstance().getObject("SHA-1", "CryptoPP");
			kdf = KdfFactory.getInstance().getObject("KdfISO18033(SHA-1)");
		} catch (FactoriesException e) {
			e.printStackTrace();
		}
		
		//Create a CryptoPrimitives object with the created primitives, when statistical parameter = 40 and the given number of threads. 
		return new CryptoPrimitives.Builder()
			.dlog(dlog)
			.kdf(kdf)
			.mes(mes)
			.hash(hash)
			.random(random)
			.statisticalParameter(40)
			.numOfThreads(numThreads)
			.build();
	}
}
