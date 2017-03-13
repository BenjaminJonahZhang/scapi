package edu.biu.SCProtocols.YaoProtocol.src;

import java.util.Date;

import edu.biu.scapi.circuits.fastGarbledCircuit.FastGarbledBooleanCircuit;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.OTBatchReceiver;
import edu.biu.scapi.interactiveMidProtocols.ot.otBatch.otExtension.OTSemiHonestExtensionReceiver;

/**
 * This application runs party two of Yao protocol.
 * 
 * @author Cryptography and Computer Security Research Group Department of Computer Science Bar-Ilan University (Moriya Farbstein)
 *
 */
public class App2 extends YaoAppsBase{
	
	
	/**
	 * @param args no arguments should be passed
	 */
	public static void main(String[] args) {
		try {
			System.out.println(args[0]);
			init(2, args[0]);
			
			// create the OT receiver.
			Date start = new Date();
			OTBatchReceiver otReceiver = new OTSemiHonestExtensionReceiver(partySender, 163, 1);
			System.out.println("init ot " + (new Date().getTime() - start.getTime()) + " milis");
			
			// create a fast garbling circuit based on native c++
			FastGarbledBooleanCircuit circuit = create_circuit();
			

			// init the P2 yao protocol
			PartyTwo p2 = new PartyTwo(channel, otReceiver, circuit);
			
			// read input and run the protocol multiple times.
			byte[] ungarbledInput = readInputsAsArray(yao_config.input_file_2);
			start = new Date();
			for(int i=0; i<yao_config.number_of_iterations;i++)
				p2.run(ungarbledInput, yao_config.print_output);
			double time = (new Date().getTime() - start.getTime())/ (double) yao_config.number_of_iterations;
			System.out.println("Yao's protocol party 2 took " + time + " milis");
			
		} catch (Exception e) {
			e.printStackTrace();
		}		
	}
}
