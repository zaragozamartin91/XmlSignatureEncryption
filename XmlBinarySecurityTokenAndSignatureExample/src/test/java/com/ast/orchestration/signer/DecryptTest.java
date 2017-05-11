package com.ast.orchestration.signer;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyStore;
import java.security.cert.Certificate;
import java.util.Properties;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.junit.BeforeClass;
import org.junit.Test;

import com.ast.orchestration.aes.DecryptEncryptException;
import com.ast.orchestration.aes.EncryptionUtils;
import com.ast.orchestration.util.Constant;

public class DecryptTest {
	static SecurityData securityData;
	static Crypto crypto;

	@BeforeClass
	public static void beforeClass() throws IOException, WSSecurityException, URISyntaxException {
		// File sigbabanelcoPropertiesFile = new File("src/test/resources/sigbabanelco.properties");
		File sigbabanelcoPropertiesFile = new File(AcceptedBenefitsQueryRHTest.class.getClassLoader().getResource("sigbabanelco.properties").toURI());
		Properties sigbabanelcoProperties = new Properties();
		sigbabanelcoProperties.load(new FileInputStream(sigbabanelcoPropertiesFile));

		securityData = new SecurityData("JKS", sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PATH),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PASS), sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS_PASS), "https://wssba.prismamp.com/INetworkService/AcceptedBenefitsQueryRH",
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_ADDRESS), sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TO),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TIMESTAMP_EXPIRATION),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_KEY_INFO));

		crypto = CryptoFactory.getInstance("crypto.properties");
	}

	@Test
	public void decryptKeys() throws DecryptEncryptException {
		System.out.printf("Storepass de %s es: %s%n", "SRVSBAWB01-PROD2.jks", EncryptionUtils.desencriptadorAES("00f00e462d997f905a1da5266438eba4"));
		System.out.printf("Keypass de %s::%s es: %s%n", "SRVSBAWB01-PROD2.jks", "srvsbawb01-prod",
				EncryptionUtils.desencriptadorAES("1930ea1a50e29506ea9cdc204e228fd5"));
		System.out.printf("Storepass de %s es: %s%n", "macro02-test.jks", EncryptionUtils.desencriptadorAES("27cf4c44eab0c8a33466ae8b7dcd04f0"));
		System.out.printf("Keypass de %s::%s es: %s%n", "macro02-test.jks", "macro-test",
				EncryptionUtils.desencriptadorAES("27cf4c44eab0c8a33466ae8b7dcd04f0"));

	}

	@Test
	public void encryptKeys() throws DecryptEncryptException {
		System.out.println("clave password encirptada:" + EncryptionUtils.encriptadorAES("password"));
	}

	@Test
	public void decode() throws Exception {
		KeyStore keyStore = getKeystore();
		Certificate certificate = keyStore.getCertificate(securityData.getAlias());
		System.out.printf("Certificado %s::%s es: %s%n%n", securityData.getKeystorefilePath(), securityData.getAlias(), certificate.toString());
	}

	private KeyStore getKeystore() throws Exception {
		FileInputStream input = new FileInputStream(securityData.getKeystorefilePath());
		KeyStore keyStore = KeyStore.getInstance(securityData.getKeystoreType());
		keyStore.load(input, EncryptionUtils.desencriptadorAES(securityData.getKeystorePass()).toCharArray());
		input.close();
		return keyStore;
	}
}
