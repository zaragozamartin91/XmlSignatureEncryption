package com.ast.orchestration.signer;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Properties;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.scheme.Scheme;
import org.apache.http.conn.scheme.SchemeRegistry;
import org.apache.http.conn.ssl.SSLSocketFactory;
import org.apache.http.conn.ssl.X509HostnameVerifier;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.util.EntityUtils;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

import com.ast.orchestration.aes.DecryptEncryptException;
import com.ast.orchestration.aes.EncryptionUtils;
import com.ast.orchestration.util.Constant;

public class XMLSignerAndSenderTest {
	static SecurityData securityData;
	static Crypto crypto;

	@BeforeClass
	public static void beforeClass() throws IOException, WSSecurityException {
		File sigbabanelcoPropertiesFile = new File("src/test/resources/sigbabanelco.properties");
		Properties sigbabanelcoProperties = new Properties();
		sigbabanelcoProperties.load(new FileInputStream(sigbabanelcoPropertiesFile));

		securityData = new SecurityData("JKS", sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PATH),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PASS),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS_PASS),
				"https://wssba.prismamp.com/INetworkService/Verify",
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_ADDRESS),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TO),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TIMESTAMP_EXPIRATION),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_KEY_INFO));

		crypto = CryptoFactory.getInstance("crypto.properties");
	}

	@Test
	public void testSignAndSend() throws Exception {
		XMLSigner xmlSigner = new XMLSigner();
		String request = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header/><s:Body><ns2:Verify xmlns:ns2=\"https://wssba.prismamp.com\" xmlns:ns3=\"https://wssba.prismamp.com/entities\" xmlns:ns4=\"http://schemas.datacontract.org/2004/07/Com.Gyf.Sba.Common.Entities.Monitoring\" xmlns:ns5=\"http://schemas.microsoft.com/2003/10/Serialization/\"><ns2:request><ns3:Document><ns3:DocumentNumber>27317040283</ns3:DocumentNumber><ns3:Nationality>ARG</ns3:Nationality><ns3:TypeId>CUIL</ns3:TypeId></ns3:Document><ns3:Fingers><ns3:FingerDto><ns3:FingerType>UNKNOWN</ns3:FingerType><ns3:FingerprintType>LiveScanPlain</ns3:FingerprintType><ns3:IsAmputation>false</ns3:IsAmputation><ns3:Template>Rk1SACAyMAAC9gA1CgEAAAFgAiAAxQDFAQAAAAAZQLcBJoQAQLIBPIIAQP4A7Y0AQRMBUokAQKsAr2wAQPYAoZsAQHIBwRgAQL8B3BsAQKkAUGMAQLoBEIYAQI0BOX8AgMAAyaIAgN0BiYEAgGUBfCEAgMUAlKcAgLEB0h8AgJkB2xkAgKcBMYEAgQYBFjIAgRoBJosAgHwAwxUAgRUBgIcAgKwBvnUAgIYAeg0AgHwAcWwAAkABAQJASUMCASArAQI4JcgJALdIel/CwWwKAKVQccH/b8BmCADjX5DCwJ3CDQEXkJ5qwYTDwnwOASOvpnTBwcGEnQgAcnJpcMF7CgB3emZpwMHBUR0BL9etwMF4b8DCkcHBwXDBwcH/wVULAHyDZGp7wFsiETcStGXC/4N4hpHAw8DBwMFwWGclES9AusFbZ3RpjYCJdG3BWsBVEhErWrdSU8DBwXDBwYAaER98umI+e8LAwv+LwsLAxJLCDAD5pCBBR8BSHBEIq8ZrwMFSWMGEZ8HDwMXBwpYRAKawZGKHVsBkZSoQ/rvGVlxYb8D//5PBw8LBxsTBZsHB/8HB/sL/wMFEKxDxy8x7wf97wMB0wMFxwcLDw6lxwHJa/2taDABzzVZWZcHAZBcQ49fQwXJtwMBzwv6Fw8GPEwC2yWbAwnRqVlJEFwDJ0RwpO2RFSkIrKxC16+R6g2tiW8CLkcLJw8Jxwf52wFk+GxDef8PAwVpZwcPCwsfHwcDCwcDAwMDBwP8gELrL1sHBZMJkYnTFwcfJdVhkwMADAP/xN8ASELPI02rAeMDBWsHBqhAQrQVXwHfBNsBDRA8QvwIt/yv/XT5KEBCzCU9OZcBDRP4OELcaVpT/VcE1wBIQfNvtiXzBWW3B/8QQELwhOjbBL1Q7/wYRGiw6wMDC/g0QpzVJ/8BTVEsOELY6QDhXVCsKEIxATExKVwsQsURGRFgrAxETVT3AAxBghlP/CRDYkklLPf0HEN6TRv9G/gQQo8Za//w=</ns3:Template><ns3:TemplateFormat>ANSI378</ns3:TemplateFormat><ns3:Wsq xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:nil=\"true\"/></ns3:FingerDto></ns3:Fingers><ns3:Request><ns3:Entity>30517948205</ns3:Entity><ns3:Metadata/><ns3:Terminal>8239</ns3:Terminal></ns3:Request></ns2:request></ns2:Verify></s:Body></s:Envelope>";
		// String request = "<s:Envelope
		// xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\"><s:Header/><s:Body><ns2:Verify
		// xmlns:ns2=\"https://wssba.prismamp.com\"
		// xmlns:ns3=\"https://wssba.prismamp.com/entities\"
		// xmlns:ns4=\"http://schemas.datacontract.org/2004/07/Com.Gyf.Sba.Common.Entities.Monitoring\"
		// xmlns:ns5=\"http://schemas.microsoft.com/2003/10/Serialization/\"><ns2:request><ns3:Document><ns3:DocumentNumber>27317040283</ns3:DocumentNumber><ns3:Nationality>ARG</ns3:Nationality><ns3:TypeId>CUIL</ns3:TypeId></ns3:Document><ns3:Fingers><ns3:FingerDto><ns3:FingerType>UNKNOWN</ns3:FingerType><ns3:FingerprintType>LiveScanPlain</ns3:FingerprintType><ns3:IsAmputation>false</ns3:IsAmputation><ns3:TemplateFormat>ANSI378</ns3:TemplateFormat><ns3:Wsq
		// xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\"
		// xsi:nil=\"true\"/></ns3:FingerDto></ns3:Fingers><ns3:Request><ns3:Entity>30517948205</ns3:Entity><ns3:Metadata/><ns3:Terminal>8239</ns3:Terminal></ns3:Request></ns2:request></ns2:Verify></s:Body></s:Envelope>";
		String signedRequest = xmlSigner.sign(request, securityData);

		// String signatureUser = "067";
		// String password = "changeme";
		// String encUser = "prismakey";

		String endpointWS = "https://wssba.prismamp.com/NetworkService/Service.svc?wsdl";

		DefaultHttpClient httpClient = new DefaultHttpClient();
		HttpResponse httpresponse = null;
		HttpEntity resEntity = null;
		HttpPost post = null;

		configureSecurity(httpClient);

		post = new HttpPost(endpointWS);
		// post.setHeader("SOAPAction",
		// "http://erad.visa.com/getLiquidaciones");
		post.setHeader("SOAPAction", "");
		StringEntity entity;

		Document doc = DocumentUtils.createDocument(signedRequest);

		System.out.println();
		System.out.println("Sending: " + DocumentUtils.documentToString(doc));

		entity = new StringEntity(DocumentUtils.documentToString(doc), "utf-8");
		entity.setContentType("application/soap+xml");
		post.setEntity(entity);

		// post.setHeader("Content-Type", "text/xml; charset=utf-8");
		post.setHeader("Content-Type", "application/soap+xml;charset=UTF-8;");

		httpresponse = httpClient.execute(post);
		resEntity = httpresponse.getEntity();
		String stringXmlResponse = EntityUtils.toString(resEntity);

		System.out.println();
		System.out.println("Response from server: " + stringXmlResponse);

		System.out.printf("%nMensaje firmado: %s%n%n", signedRequest);
		assertTrue(true);
	}

	private static void configureSecurity(DefaultHttpClient httpClient)
			throws NoSuchAlgorithmException, KeyManagementException, FileNotFoundException, IOException {

		Security.setProperty("ssl.SocketFactory.provider", "com.ibm.jsse2.SSLSocketFactoryImpl");
		Security.setProperty("ssl.ServerSocketFactory.provider", "com.ibm.jsse2.SSLServerSocketFactoryImpl");

		String trustStorePath = "resources/truststore_app_ext_cts_cis.jks";
		String trustStorePassword = "changeit";
		System.setProperty("javax.net.ssl.trustStore", trustStorePath);
		System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

		// System.setProperty("javax.net.ssl.trustStore",
		// "cert/SRVSBAWB01-PROD2.jks");
		// System.setProperty("javax.net.ssl.trustStorePassword", "macro");

		SSLContext ctx = SSLContext.getInstance("TLS");
		X509TrustManager tm = new X509TrustManager() {

			public void checkClientTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			}

			public void checkServerTrusted(X509Certificate[] xcs, String string) throws CertificateException {
			}

			public X509Certificate[] getAcceptedIssuers() {
				return null;
			}
		};
		X509HostnameVerifier verifier = new X509HostnameVerifier() {

			public void verify(String string, SSLSocket ssls) throws IOException {
			}

			public void verify(String string, X509Certificate xc) throws SSLException {
			}

			public void verify(String string, String[] strings, String[] strings1) throws SSLException {
			}

			public boolean verify(String string, SSLSession ssls) {
				return true;
			}
		};
		ctx.init(null, new TrustManager[] { tm }, null);
		SSLSocketFactory ssf = new SSLSocketFactory(ctx);
		ssf.setHostnameVerifier(verifier);
		ClientConnectionManager ccm = httpClient.getConnectionManager();
		SchemeRegistry sr = ccm.getSchemeRegistry();
		sr.register(new Scheme("https", ssf, 443));

	}

	@Test
	public void decryptKeys() throws DecryptEncryptException {
		System.out.printf("Storepass de %s es: %s%n", "SRVSBAWB01-PROD2.jks",
				EncryptionUtils.desencriptadorAES("00f00e462d997f905a1da5266438eba4"));
		System.out.printf("Keypass de %s::%s es: %s%n", "SRVSBAWB01-PROD2.jks", "srvsbawb01-prod",
				EncryptionUtils.desencriptadorAES("1930ea1a50e29506ea9cdc204e228fd5"));
		System.out.printf("Storepass de %s es: %s%n", "macro02-test.jks",
				EncryptionUtils.desencriptadorAES("27cf4c44eab0c8a33466ae8b7dcd04f0"));
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
		System.out.printf("Certificado %s::%s es: %s%n%n", securityData.getKeystorefilePath(), securityData.getAlias(),
				certificate.toString());
	}

	private KeyStore getKeystore() throws Exception {
		FileInputStream input = new FileInputStream(securityData.getKeystorefilePath());
		KeyStore keyStore = KeyStore.getInstance(securityData.getKeystoreType());
		keyStore.load(input, EncryptionUtils.desencriptadorAES(securityData.getKeystorePass()).toCharArray());
		input.close();
		return keyStore;
	}
}
