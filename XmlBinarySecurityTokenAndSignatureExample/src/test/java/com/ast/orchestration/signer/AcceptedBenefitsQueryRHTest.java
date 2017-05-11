package com.ast.orchestration.signer;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
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
import org.junit.BeforeClass;
import org.junit.Test;
import org.w3c.dom.Document;

import com.ast.orchestration.util.Constant;

public class AcceptedBenefitsQueryRHTest {
	private static SecurityData securityData;

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

	}

	@Test
	public void testSignAndSend() throws Exception {
		XMLSigner xmlSigner = new XMLSigner();
		String request = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header/><s:Body><wss:AcceptedBenefitsQueryRH><wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><ent:Document><ent:DocumentNumber>6</ent:DocumentNumber><ent:Nationality>7</ent:Nationality><ent:TypeId>8</ent:TypeId></ent:Document><ent:Request><ent:Entity>2</ent:Entity><ent:Metadata><ent:MetadataDto><ent:Name>3</ent:Name><ent:Value>4</ent:Value></ent:MetadataDto></ent:Metadata><ent:Terminal>5</ent:Terminal></ent:Request><ent:NroBeneficio>1</ent:NroBeneficio></wss:request></wss:AcceptedBenefitsQueryRH></s:Body></s:Envelope>";
		String signedRequest = xmlSigner.sign(request, securityData);

		String endpointWS = "https://wssba.prismamp.com/NetworkService/Service.svc?singleWsdl";

		DefaultHttpClient httpClient = new DefaultHttpClient();
		HttpResponse httpresponse = null;
		HttpEntity resEntity = null;
		HttpPost post = null;

		configureSecurity(httpClient);

		post = new HttpPost(endpointWS);
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

		// String trustStorePath = "resources/truststore_app_ext_cts_cis.jks";
		// String trustStorePassword = "changeit";
		// System.setProperty("javax.net.ssl.trustStore", trustStorePath);
		// System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

		String trustStorePath = "resources/SRVSBAWB01-PROD2.jks";
		String trustStorePassword = "macro";
		System.setProperty("javax.net.ssl.trustStore", trustStorePath);
		System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

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
}
