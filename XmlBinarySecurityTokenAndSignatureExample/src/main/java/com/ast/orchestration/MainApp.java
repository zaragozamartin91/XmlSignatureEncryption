package com.ast.orchestration;

import java.io.ByteArrayInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
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
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import com.ast.orchestration.signer.DocumentUtils;
import com.ast.orchestration.signer.SecurityData;
import com.ast.orchestration.signer.XMLSigner;
import com.ast.orchestration.util.Constant;

public class MainApp {
	SecurityData securityData;
	String request;

	public MainApp(SecurityData securityData, String request) {
		this.securityData = securityData;
		this.request = request;
	}

	static {
		System.out.println("file.encoding:" + System.getProperty("file.encoding"));
		System.out.println("Charset.defaultCharset():" + Charset.defaultCharset());
		System.out.println("defaultCharacterEncoding by code: " + getDefaultCharEncoding());

		System.out.println();
	}

	public static void main(String[] args) throws Exception {
		SecurityData securityData = args.length > 0 ? buildSecurityDataFromArgs(args) : buildSecurityDataFromProperties();

		System.out.println("securityData: " + securityData);

		MainApp mainApp = new MainApp(securityData,
				"<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header/><s:Body><wss:AcceptedBenefitsQueryRH><wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><ent:Document><ent:DocumentNumber>6</ent:DocumentNumber><ent:Nationality>7</ent:Nationality><ent:TypeId>8</ent:TypeId></ent:Document><ent:Request><ent:Entity>2</ent:Entity><ent:Metadata><ent:MetadataDto><ent:Name>3</ent:Name><ent:Value>4</ent:Value></ent:MetadataDto></ent:Metadata><ent:Terminal>5</ent:Terminal></ent:Request><ent:NroBeneficio>1</ent:NroBeneficio></wss:request></wss:AcceptedBenefitsQueryRH></s:Body></s:Envelope>");
		mainApp.signAndSend();
	}

	private static SecurityData buildSecurityDataFromProperties() throws IOException {
		Properties sigbabanelcoProperties = new Properties();
		sigbabanelcoProperties.load(MainApp.class.getClassLoader().getResourceAsStream("sigbabanelco.properties"));

		return new SecurityData("JKS", sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PATH),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_JKS_PASS), sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_ALIAS_PASS), "https://wssba.prismamp.com/INetworkService/AcceptedBenefitsQueryRH",
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_ADDRESS), sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TO),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_TIMESTAMP_EXPIRATION),
				sigbabanelcoProperties.getProperty(Constant.ORCHESTRATION_HEADER_KEY_INFO));
	}

	private static SecurityData buildSecurityDataFromArgs(String[] args) {
		return new SecurityData(args[0], args[1], args[2], args[3], args[4], args[5], args[6], args[7], args[8], args[9]);
	}

	public void signAndSend() throws Exception {
		System.out.println("signAndSend:");
		XMLSigner xmlSigner = new XMLSigner();
		String request = "<s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><s:Header/><s:Body><wss:AcceptedBenefitsQueryRH><wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\"><ent:Document><ent:DocumentNumber>6</ent:DocumentNumber><ent:Nationality>7</ent:Nationality><ent:TypeId>8</ent:TypeId></ent:Document><ent:Request><ent:Entity>2</ent:Entity><ent:Metadata><ent:MetadataDto><ent:Name>3</ent:Name><ent:Value>4</ent:Value></ent:MetadataDto></ent:Metadata><ent:Terminal>5</ent:Terminal></ent:Request><ent:NroBeneficio>1</ent:NroBeneficio></wss:request></wss:AcceptedBenefitsQueryRH></s:Body></s:Envelope>";
		String signedRequest = xmlSigner.sign(request, securityData);
		String endpointWS = "https://200.59.131.174/NetworkService/Service.svc?wsdl"; // URL DE PRODUCCION
		// String endpointWS = "https://200.59.131.174/NetworkService/Service.svc?singleWsdl"; // IP DE PRODUCCION
		// String endpointWS = "https://172.18.22.37/networkservice/service.svc?wsdl"; // IP DATAPOWER SSL

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
	}

	private static void configureSecurity(DefaultHttpClient httpClient)
			throws NoSuchAlgorithmException, KeyManagementException, FileNotFoundException, IOException {

		Security.setProperty("ssl.SocketFactory.provider", "com.ibm.jsse2.SSLSocketFactoryImpl");
		Security.setProperty("ssl.ServerSocketFactory.provider", "com.ibm.jsse2.SSLServerSocketFactoryImpl");

		// String trustStorePath = "resources/SRVSBAWB01-PROD2.jks";
		// String trustStorePassword = "macro";

		// String trustStorePath = "resources/macro02-test.jks";
		// String trustStorePassword = "macro02";
		//
		// System.setProperty("javax.net.ssl.trustStore", trustStorePath);
		// System.setProperty("javax.net.ssl.trustStorePassword", trustStorePassword);

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
