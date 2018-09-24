package ast.ws.security.caller;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

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
import org.apache.ws.security.components.crypto.Crypto;
import org.w3c.dom.Document;

import ast.ws.security.caller.crypto.CryptoBuilder;
import ast.ws.security.caller.doc.AstSoapDocument;
import ast.ws.security.caller.injector.timestamp.TimestampInjector;
import ast.ws.security.util.DocumentUtils;
import ast.ws.security.decoder.WsSecurityMessageDecoder;

public class FullSecurityWsTest {
	private Crypto crypto;
	private String stringXmlResponse;

	public FullSecurityWsTest() {
		crypto = CryptoBuilder.build().fromProperties("crypto.properties");
	}

	public void run() throws Exception {
		File xmlFile = new File("xml/testXml.xml");

		String actor = null;
		boolean mustUnderstand = true;

		int timeToLive = 300;
		String tsPrefix = TimestampInjector.DEFAULT_TIMESTAMP_PREFIX;

		String sigAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
		String signatureUser = "067";
		String password = "changeme";

		String encSymmAlgo = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
		String encKeyTransport = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
		String encUser = "prismakey";

		AstSoapDocument astSoapDocument = AstSoapDocument.createFromFile(xmlFile);
		astSoapDocument.withEncCrypto(crypto);
		astSoapDocument.withSigCrypto(crypto);
		astSoapDocument.insertSecurityHeader(actor, mustUnderstand);
//		astSoapDocument.insertUsernameToken("clara");
		astSoapDocument.insertTimestamp(timeToLive, tsPrefix);
		astSoapDocument.signTimestamp(sigAlgorithm, signatureUser, password);
		astSoapDocument.signBody(sigAlgorithm, signatureUser, password);
		astSoapDocument.encryptBodyAndSignature(encSymmAlgo, encKeyTransport, encUser);

		Document doc = astSoapDocument.getDoc();

		send(doc);

		decode();
	}

	public String getStringXmlResponse() {
		return stringXmlResponse;
	}

	private void decode() throws Exception {
		new WsSecurityMessageDecoder(stringXmlResponse).run();
	}

	private String send(Document doc) throws Exception {
		String endpointWS = "https://200.47.32.160/wserad/services/liquidacionWS?wsdl";
		// String endpointWS =
		// "http://172.18.16.228:1230/resumenes/services/liquidacionWS?wsdl";

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

		System.out.println();
		System.out.println("Sending: " + DocumentUtils.documentToString(doc));

		entity = new StringEntity(DocumentUtils.documentToString(doc), "utf-8");
		entity.setContentType("application/soap+xml");
		post.setEntity(entity);

		// post.setHeader("Content-Type", "text/xml; charset=utf-8");
		post.setHeader("Content-Type", "application/soap+xml;charset=UTF-8;");

		httpresponse = httpClient.execute(post);
		resEntity = httpresponse.getEntity();
		stringXmlResponse = EntityUtils.toString(resEntity);

		System.out.println();
		System.out.println("Response from server: " + stringXmlResponse);
		return stringXmlResponse;

	}

	private static void configureSecurity(DefaultHttpClient httpClient)
			throws NoSuchAlgorithmException, KeyManagementException, FileNotFoundException, IOException {

		Security.setProperty("ssl.SocketFactory.provider", "com.ibm.jsse2.SSLSocketFactoryImpl");
		Security.setProperty("ssl.ServerSocketFactory.provider", "com.ibm.jsse2.SSLServerSocketFactoryImpl");

		String trustStorePath = "resources/truststore_app_ext_cts_cis.jks";
		String trustStorePassword = "changeit";

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

	public static void main(String[] args) {
		try {
			FullSecurityWsTest fullSecurityWsTest = new FullSecurityWsTest();
			fullSecurityWsTest.run();

			WsSecurityMessageDecoder wsSecurityMessageDecoder = new WsSecurityMessageDecoder(fullSecurityWsTest.getStringXmlResponse());
			wsSecurityMessageDecoder.run();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
