package edu.biu.SCProtocols.YaoProtocol.src;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class YaoConfig {
	public int number_of_iterations;
	public boolean print_output;
	public String circuit_type;
	public String circuit_file;
	public String  input_file_1;
	public String  input_file_2;
	public String party_1_net_config;
	public String party_2_net_config;
	public YaoConfig(String n_iter, String print_output, String circuit_type, 
			String circuit_file, String input_file_1, String input_file_2, String party_1_net_config,
			String party_2_net_config)
	{
		this.number_of_iterations=Integer.valueOf(n_iter);
		this.print_output = Boolean.valueOf(print_output);
		this.circuit_type = circuit_type;
		this.circuit_file = circuit_file;
		this.input_file_1 = input_file_1;
		this.input_file_2 = input_file_2;
		this.party_1_net_config = party_1_net_config;
		this.party_2_net_config = party_2_net_config;
	}
	
	public static YaoConfig readYaoConfiguration(String config_file_name) {
		Properties prop = new Properties();
		InputStream input = null;
		YaoConfig yc = null;
		try {
			input = new FileInputStream(config_file_name);
			// load a properties file
			prop.load(input);
			String input_section = prop.getProperty("input_section") + ".";
			yc = new YaoConfig(prop.getProperty("number_of_iterations"), prop.getProperty("print_output"),
					prop.getProperty("circuit_type"), prop.getProperty(input_section + "circuit_file"),
					prop.getProperty(input_section + "input_file_party_1"), 
					prop.getProperty(input_section + "input_file_party_2"),
					prop.getProperty("party_1_net_config"), 
					prop.getProperty("party_2_net_config"));

		} catch (IOException ex) {
			ex.printStackTrace();
		} finally {
			if (input != null) {
				try {
					input.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}
		return yc;
	}		
 
}
