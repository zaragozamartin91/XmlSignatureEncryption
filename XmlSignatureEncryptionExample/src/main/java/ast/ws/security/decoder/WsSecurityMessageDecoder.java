package ast.ws.security.decoder;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPMessage;
import javax.xml.transform.dom.DOMSource;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.components.crypto.Crypto;
import org.w3c.dom.Document;

import ast.ws.security.caller.crypto.CryptoBuilder;
import ast.ws.security.caller.soap.SoapDocumentBuilder;
import ast.ws.security.caller.util.SoapUtil;
import ast.ws.security.decoder.algorithm.AlgorithmSuiteBuilder;
import ast.ws.security.decoder.callback.DummyCallbackHandlerFactory;
import ast.ws.security.decoder.processor.SecurityHeaderProcessor;
import ast.ws.security.util.DocumentUtils;

public class WsSecurityMessageDecoder {
	public static final QName TIMESTAMP = new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN);

	private Document doc;
	private Crypto crypto = CryptoBuilder.build().fromProperties("crypto.properties");
	private SOAPMessage soapMessage;

	private String actor = null;

	public WsSecurityMessageDecoder(String xmlInput) throws Exception {
		doc = SoapDocumentBuilder.build().fromString(xmlInput);
		soapMessage = SoapUtil.toSoapMessage(doc);
	}

	public WsSecurityMessageDecoder(Document doc) throws Exception {
		this.doc = doc;
		soapMessage = SoapUtil.toSoapMessage(doc);
	}

	public void run() throws Exception {
		buildAlgorithSuite();

		processHeader();
	}

	private void processHeader() throws Exception {
		// Element elem =
		// WSSecurityUtil.getSecurityHeader(soapMessage.getSOAPPart(), actor);
//		CallbackHandler callbackHandler = new ClientKeystorePasswordCallback();
		CallbackHandler callbackHandler = DummyCallbackHandlerFactory.newInstance().addKeyPassPair("067", "changeme").getNewHandler();

//		engine.processSecurityHeader(doc, actor, callbackHandler, crypto,crypto);
		SecurityHeaderProcessor.prepare(actor, callbackHandler, crypto, crypto).process(doc);
		
		updateSOAPMessage(doc, soapMessage);

		System.out.println();
		System.out.println("Decoded Message: " + DocumentUtils.documentToString(doc));
	}

	private static SOAPMessage updateSOAPMessage(Document doc, SOAPMessage message) throws SOAPException {
		DOMSource domSource = new DOMSource(doc);
		message.getSOAPPart().setContent(domSource);

		return message;
	}

	private void buildAlgorithSuite() {
//		String signatureAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
//		String transportAlgorithm = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";

//		algorithmSuite = AlgorithmSuiteBuilder.build().withSignatureAlgorithm(signatureAlgorithm)
//				.withTransportAlgorithm(transportAlgorithm).get();
		
		AlgorithmSuiteBuilder.build().fromDocument(doc).get();
	}

	public Document getDoc() {
		return doc;
	}
}
