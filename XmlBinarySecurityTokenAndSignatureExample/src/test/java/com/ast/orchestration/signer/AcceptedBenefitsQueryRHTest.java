package com.ast.orchestration.signer;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.net.URISyntaxException;
import java.nio.charset.Charset;
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
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.TransformerException;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.ClientProtocolException;
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
import org.junit.Ignore;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.ast.orchestration.util.Constant;

public class AcceptedBenefitsQueryRHTest {
	private static SecurityData securityData;

	@BeforeClass
	public static void beforeClass() throws IOException, WSSecurityException, URISyntaxException {
		Properties sigbabanelcoProperties = new Properties();
		sigbabanelcoProperties.load(AcceptedBenefitsQueryRHTest.class.getClassLoader().getResourceAsStream("sigbabanelco.properties"));

		securityData = new SecurityData("JKS", sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PATH),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PASS), sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS_PASS), "https://wssba.prismamp.com/INetworkService/AcceptedBenefitsQueryRH",
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_ADDRESS), sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TO),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TIMESTAMP_EXPIRATION),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_KEY_INFO));

	//macro-02.jks certificado	
		//para firmar el msj qe va
		System.out.println("seguridad: " + securityData);

		System.out.println("file.encoding:" + System.getProperty("file.encoding"));
		System.out.println("Charset.defaultCharset():" + Charset.defaultCharset());
		System.out.println("defaultCharacterEncoding by code: " + getDefaultCharEncoding());

		System.out.println();
	}

	@Test
	@Ignore
	public void signAlterAndSend() throws Exception {
		System.out.println("signAlterAndSend:");
		XMLSigner xmlSigner = new XMLSigner();
		String request = "<s:Envelope   	xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header/><s:Body>MENSAJE</s:Body></s:Envelope>";
		String signedRequest = xmlSigner.sign(request, securityData);
		signedRequest = signedRequest.replace("MENSAJE",
				"<wss:AcceptedBenefitsQueryRH><wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">     <ent:Document><ent:DocumentNumber>6</ent:DocumentNumber><ent:Nationality>7</ent:Nationality><ent:TypeId>8</ent:TypeId></ent:Document><ent:Request><ent:Entity>2</ent:Entity><ent:Metadata><ent:MetadataDto><ent:Name>3</ent:Name><ent:Value>4</ent:Value>	</ent:MetadataDto></ent:Metadata><ent:Terminal>5</ent:Terminal>    	</ent:Request><ent:NroBeneficio>1</ent:NroBeneficio></wss:request></wss:AcceptedBenefitsQueryRH>");
		String endpointWS = "https://200.59.131.174/NetworkService/Service.svc?wsdl"; // URL DE PRODUCCION

		send(signedRequest, endpointWS);
	}

	@Test
	public void signAndSend() throws Exception {
		System.out.println("signAndSend:");
		XMLSigner xmlSigner = new XMLSigner();
		
		//trama sin firmar
		String request = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header/><s:Body><wss:AcceptedBenefitsQueryRH><wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><ent:Document><ent:DocumentNumber>6</ent:DocumentNumber><ent:Nationality>7</ent:Nationality><ent:TypeId>8</ent:TypeId></ent:Document><ent:Request><ent:Entity>2</ent:Entity><ent:Metadata><ent:MetadataDto><ent:Name>3</ent:Name><ent:Value>4</ent:Value></ent:MetadataDto></ent:Metadata><ent:Terminal>5</ent:Terminal></ent:Request><ent:NroBeneficio>1</ent:NroBeneficio></wss:request></wss:AcceptedBenefitsQueryRH></s:Body></s:Envelope>";
		
		String signedRequest = xmlSigner.sign(request, securityData);
		String endpointWS = "https://200.59.131.174/NetworkService/Service.svc?wsdl"; // URL DE PRODUCCION
//		String endpointWS = "https://200.59.131.173/NetworkService/Service.svc?wsdl"; // URL DE CERTIFICACION
		// String endpointWS = "https://200.59.131.174/NetworkService/Service.svc?singleWsdl"; // IP DE PRODUCCION
		// String endpointWS = "https://172.18.22.37/networkservice/service.svc?wsdl"; // IP DATAPOWER SSL

		send(signedRequest, endpointWS);
	}

	@Test
	public void justSend() throws Exception {
		System.out.println("justSend:");
		/* MANDA UN MENSAJE CON EL TIMESTAMP VENCIDO */
		String signedRequest = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header><a:Action>https://wssba.prismamp.com/INetworkService/GetAgreementRH</a:Action><a:MessageID>urn:uuid:c2312e0c-35a5-47df-a11b-d2df32e46c35</a:MessageID><a:ReplyTo><a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address></a:ReplyTo><a:To u:Id=\"_1\">https://wssba.prismamp.com/NetworkService/Service.svc</a:To><o:Security s:mustUnderstand=\"1\"><u:Timestamp u:Id=\"_0\"><u:Created>2017-05-24T14:56:52.052Z</u:Created><u:Expires>2017-05-24T15:01:52.052Z</u:Expires></u:Timestamp><o:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" u:Id=\"uuid:9bfaa06f-97a7-46b4-9e77-84500c7ebbc6\">MIICFDCCAYGgAwIBAgIQB0A5MI1Tu5FMl4Szb4BgJDAJBgUrDgMCHQUAMCExHzAdBgNVBAMTFlByaXNtYVNiYVRlc3RpbmdSb290Q0EwHhcNMTUwNTIyMTMyMjQ3WhcNMzkxMjMxMjM1OTU5WjAgMR4wHAYDVQQDExV3c3NiYWNlci5wcmlzbWFtcC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMKtAVI7eN+ClEO5FByQckYfAUnoLmN3M6sjHGbMz9wx1/hUhto2P9yXarkbJavGH5dlh0xL24C345//qQ72DqNv0jq3FrRWJjrcPtbWgMBuwEDXo+2NeDzr2WbCdHnJSjvRJpZj7F08cKnvGq/qwWR5VFptdT+Y0i2WBuF22TnTAgMBAAGjVjBUMFIGA1UdAQRLMEmAEKPZTKfOJF2t4EXAE7RCbbGhIzAhMR8wHQYDVQQDExZQcmlzbWFTYmFUZXN0aW5nUm9vdENBghBcDUs87GMErEQHfnd+eAOZMAkGBSsOAwIdBQADgYEADzvM2eXf/NJrndDr/TghKC6tdpXNSwQ4WTMpv+sS6BUv1TfGTW+RUiEWpTbEODzb8Q8Ti42HXX/c3czOAVxbbAv2n4oFBCIll+rXbSuKgTTF6SOgNzqJCzd0+0lMysI+MWd0ej1qvLkudq4oRiGJHcJ7iupUx56hkyJugDnAvmY=</o:BinarySecurityToken><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><Reference URI=\"#_0\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>GiQQ2ziysfdGVfTwCJGzcGQUWH8=</DigestValue></Reference><Reference URI=\"#_1\"><Transforms><Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></Transforms><DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><DigestValue>8X9cZFtQRXZnhwx5Fzt9r2pkxvg=</DigestValue></Reference></SignedInfo><SignatureValue>ifUZ047GyaiGQibrxq3vRsnvcq8paw10A/q8oAnhkFyYJQdWJqK/J1LFl+CHoq1JOyOd46ng/wjLZ7WRWv6GU/zohLKxCArJ2uE/gqKXHsgTMhNRpo48GL+SfLk0OOPTYj5SYBte5Wyt1AVOugMhbu+IKegm1VXvF/AlUFr6W7w=</SignatureValue><KeyInfo><o:SecurityTokenReference><o:Reference URI=\"#uuid:9bfaa06f-97a7-46b4-9e77-84500c7ebbc6\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></o:SecurityTokenReference></KeyInfo></Signature></o:Security></s:Header><s:Body><wss:GetAgreementRH><wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"> <ent:Document><ent:DocumentNumber>6</ent:DocumentNumber> <ent:Nationality>7</ent:Nationality> <ent:TypeId>8</ent:TypeId></ent:Document> <ent:NroBeneficio>1</ent:NroBeneficio>  <ent:Request><ent:Entity>2</ent:Entity> <ent:Metadata><ent:MetadataDto><ent:Name>3</ent:Name><ent:Value>4</ent:Value></ent:MetadataDto></ent:Metadata> <ent:Terminal>5</ent:Terminal></ent:Request></wss:request></wss:GetAgreementRH></s:Body></s:Envelope>";
		String endpointWS = "https://200.59.131.174/NetworkService/Service.svc?wsdl"; // URL DE PRODUCCION

		send(signedRequest, endpointWS);
	}

	private void send(String message, String endpointWS) throws ParserConfigurationException, SAXException, IOException, NoSuchAlgorithmException,
			KeyManagementException, FileNotFoundException, TransformerException, UnsupportedEncodingException, ClientProtocolException {
		Document doc = DocumentUtils.createDocument(message);

		DefaultHttpClient httpClient = new DefaultHttpClient();
		configureSecurity(httpClient);

		System.out.println("Sending: " + DocumentUtils.documentToString(doc));

		StringEntity entity = new StringEntity(DocumentUtils.documentToString(doc), "utf-8");
		entity.setContentType("application/soap+xml");

		HttpPost post = new HttpPost(endpointWS);
		post.setHeader("SOAPAction", "");
		post.setEntity(entity);
		// post.setHeader("Content-Type", "text/xml; charset=utf-8");
		post.setHeader("Content-Type", "application/soap+xml;charset=UTF-8;");

		HttpResponse httpresponse = httpClient.execute(post);
		System.out.printf("httpresponse:%n%s%n", httpresponse.toString());
		HttpEntity resEntity = httpresponse.getEntity();
		String stringXmlResponse = EntityUtils.toString(resEntity);

		System.out.printf("Response from server: %s%n%n", stringXmlResponse);

		assertTrue(true);
	}

	private static void configureSecurity(DefaultHttpClient httpClient)
			throws NoSuchAlgorithmException, KeyManagementException, FileNotFoundException, IOException {

		Security.setProperty("ssl.SocketFactory.provider", "com.ibm.jsse2.SSLSocketFactoryImpl");
		Security.setProperty("ssl.ServerSocketFactory.provider", "com.ibm.jsse2.SSLServerSocketFactoryImpl");

		 String trustStorePath = "resources/SRVSBAWB01-PROD2.jks";
		 String trustStorePassword = "macro";

		// String trustStorePath = "resources/macro02-test.jks";
		// String trustStorePassword = "macro02";

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

	public static String getDefaultCharEncoding() {
		byte[] bArray = { 'w' };
		InputStream is = new ByteArrayInputStream(bArray);
		InputStreamReader reader = new InputStreamReader(is);
		String defaultCharacterEncoding = reader.getEncoding();
		return defaultCharacterEncoding;
	}

}
