package com.securemetric;

import java.io.Console;
import java.io.IOException;
import java.security.MessageDigest;
import java.util.Base64;

import CryptoServerAPI.*;
import CryptoServerCXI.*;
import CryptoServerCXI.CryptoServerCXI.Key;
import CryptoServerCXI.CryptoServerCXI.KeyAttributes;

public class FindKey {

	static final String algoStrings [] = new String [] { "RAW", "DES", "AES", "RSA", "ECDSA", "DSA", "ECDH", "DH", "Unknown", "X509" };
	static private final String getTypeString(int type){
	    switch (type)    
	    {
	      case CryptoServerCXI.KEY_TYPE_PUBLIC: return "public";
	      case CryptoServerCXI.KEY_TYPE_SECRET: return "secret";
	      case CryptoServerCXI.KEY_TYPE_PRIVATE_ONLY: return "prv";
	      case CryptoServerCXI.KEY_TYPE_PRIVATE: return "prv+pub";
	      case CryptoServerCXI.KEY_TYPE_PRIVATEF: return "prv-full";      
	      case CryptoServerCXI.KEY_TYPE_DATA: return "data";
	      case CryptoServerCXI.KEY_TYPE_CERT: return "cert";
	      case CryptoServerCXI.KEY_TYPE_DOMAIN_PARAMETER: return "dp";      
	      case CryptoServerCXI.KEY_TYPE_CONFIG: return "conf";
	      default:
	        return ("TYPE_" + type);
	    }
	  };
	
	public static void main(String[] args) throws Exception, IOException, CryptoServerException {
		System.out.println("\n--- CryptoServer CXI Demo ---\n");
		// connect to CryptoServer with a connection timeout of 3 seconds
		CryptoServerCXI cxi = new CryptoServerCXI("3001@127.0.0.1", 3000);
		// set command timeout to 60 seconds
		cxi.setTimeout(60000);
		// logon user '' with password ''
		cxi.logonPassword("USR_0000", "12345678");
		// prevent session from expiring after 15 minutes
		cxi.keepSessionAlive();

		CryptoServerCXI.KeyAttributes keyTemplate = new CryptoServerCXI.KeyAttributes();
		// keyTemplate = cxi.getKeyAttributes(rsaKey, true);
		// keyTemplate.setName("test");
//		keyTemplate.setName("RSA_EXT_KEY_1");
//		keyTemplate.setGroup("SLOT_0000");
//		keyTemplate.setUsage(CryptoServerCXI.KEY_USAGE_SIGN);
//		keyTemplate.setUsage(CryptoServerCXI.KEY_USAGE_VERIFY);
//		keyTemplate.setAlgo(CryptoServerCXI.KEY_ALGO_RSA);
//		keyTemplate.setSize(2048);
		// keyTemplate.setSpecifier(3);
		// CryptoServerCXI.Key rsaKey = cxi.findKey(keyTemplate);

//		KeyAttributes[] listKeys = cxi.listKeys();
//		for (KeyAttributes item : listKeys) {
//			System.out.println("keysize: " + item.getSize() + "| keySpec: " + item.getSpecifier() + "| keyName: "
//					+ item.getName() + "| keyType: " + item.getType() + "| keyLabel: " + item.getLabel());
//			if ("rsa_1".equals(item.getLabel())) {
//				keyTemplate = item;
//				break;
//			}
//		}

		// Key rsaKey = cxi.findKey(keyTemplate);
		// System.out.println(rsaKey);

		System.out.println("==============================================");
		
		// list key
	      System.out.println("List key by Label");
	      CryptoServerCXI.KeyAttributes attr = new CryptoServerCXI.KeyAttributes();
	      attr.setGroup("SLOT_0000");
	      //attr.setLabel("rsa_2-privateKey");
	     
	      CryptoServerCXI.KeyAttributes [] keyList = cxi.listKeys(attr);
	      
	      System.out.printf("\n%1$-6s %2$-8s %3$-5s %4$-24s %5$-32s %6$s\n", "algo", "type", "size", "group", "name", "modulus");
	      System.out.println("-----------------------------------------------------------------------------------------");
	      
	      
	      for (CryptoServerCXI.KeyAttributes att : keyList)
	      {
	    	  //System.out.printf("%f\n", att.getModulus());
	        System.out.printf("%1$-6s %2$-8s %3$-5d %4$-24s %5$-32s %6$d\n", algoStrings[att.getAlgo()],
	                                                                         getTypeString(att.getType()),
	                                                                         att.getSize(),
	                                                                         att.getGroup(), 
	                                                                         att.getName(),
	                                                                         att.getModulus());
	                                                                         //att.getLabel());                                                           
	      } 
		
		System.out.println("\nclosing connection");
		if (cxi != null) {
			cxi.logoff();
			cxi.close();
		}
		System.out.println("Done");
	}
}
