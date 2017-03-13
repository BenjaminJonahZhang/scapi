package edu.biu.SCProtocols.YaoProtocol.src;

import java.util.Date;
import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchSender;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTSemiHonestExtensionSender;

/**
 * This application runs party one of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class App1 extends YaoAppsBase{
	
	/**
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		try {
			init(1, args[0]);
			
			Date start = new Date();
			OTBatchSender otSender = new OTSemiHonestExtensionSender(partySender, 163, 1);
			System.out.println("init ot " + (new Date().getTime() - start.getTime()) + " milis");
			
			FastGarbledBooleanCircuit circuit = create_circuit();

			// get the inputs of P1.
			byte[] ungarbledInput = readInputsAsArray(yao_config.input_file_1);

			// create Party one with the previous created objects.
			PartyOne p1 = new PartyOne(channel, otSender, circuit);
			
			// run the protocol multiple times.
			start = new Date();
			for(int i=0; i<yao_config.number_of_iterations;i++)
				p1.run(ungarbledInput, yao_config.print_output);
			double time = (new Date().getTime() - start.getTime())/ (double) yao_config.number_of_iterations;
			System.out.println("Yao's protocol party 1 took " + time + " milis");
			
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
