package edu.biu.protocols.yao.primitives;

import java.io.IOException;
import java.io.Serializable;

import edu.biu.scapi.comm.Channel;
import edu.biu.scapi.exceptions.CheatAttemptException;

/**
 * This class initialized with an expected class and has a receive function that receive an object of this expected class.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Asaf Cohen)
 *
 */
public class Expector {
	private Channel channel;				//The channel to use in order to receive.
	private Class<?> expectedType;			//The expected class to receive.

	/**
	 * Initializes the object with the channel and the expected class.
	 * @param channel The channel to use in order to receive.
	 * @param expectedType The expected class to receive.
	 */
	public Expector(Channel channel, Class<?> expectedType) {
		this.channel = channel;
		this.expectedType = expectedType;
	}
	
	/**
	 * Receives an object of the expected class.
	 * @return The received object.
	 * @throws CheatAttemptException if the received object is not the expected.
	 * @throws IOException In case of a problem during receiving the object.
	 */
	public Object receive() throws CheatAttemptException, IOException {
		// Get the next message
		Serializable message;
		try {
			message = channel.receive();
		} catch (ClassNotFoundException e) {
			throw new IOException(e);
		}
		
		//Check if the received message is the expected type.
		if (!expectedType.isAssignableFrom(message.getClass())) {
			throw new CheatAttemptException(String.format("Expected message of type %s, but got %s.", 
							expectedType.getName(), message.getClass().getName()));
		}
		
		//Cast the message to the expected one and return it.
		return expectedType.cast(message);
	}
}
