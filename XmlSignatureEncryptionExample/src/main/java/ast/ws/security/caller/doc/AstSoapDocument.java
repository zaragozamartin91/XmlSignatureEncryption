package ast.ws.security.caller.doc;

import java.io.File;
import java.io.IOException;
import java.util.List;

import javax.xml.parsers.ParserConfigurationException;

import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import ast.ws.security.caller.encryptor.SoapEncryptor;
import ast.ws.security.caller.injector.header.SecurityHeaderInjector;
import ast.ws.security.caller.injector.timestamp.TimestampInjector;
import ast.ws.security.caller.signer.SoapSigner;
import ast.ws.security.caller.soap.SoapDocumentBuilder;

/**
 * Facilita la construccion de un documento Soap, su firma y encriptacion.
 * 
 * @author martin.zaragoza
 *
 */
public class AstSoapDocument {
	private Document doc;
	private WSSecHeader secHeader;
	private Timestamp ts;
	private Crypto sigCrypto;
	private Crypto encCrypto;

	public AstSoapDocument(Document doc) {
		this.doc = doc;
	}

	public static AstSoapDocument createFromString(String stringXml) {
		return new AstSoapDocument(SoapDocumentBuilder.build().fromString(stringXml));
	}

	public static AstSoapDocument createFromFile(File xmlFile) {
		return new AstSoapDocument(SoapDocumentBuilder.build().fromFile(xmlFile));
	}

	public AstSoapDocument insertSecurityHeader(String actor, boolean mustUnderstand) {
		this.secHeader = SecurityHeaderInjector.inject(actor, mustUnderstand).into(doc).getSecHeader();
		return this;
	}

	public AstSoapDocument insertUsernameToken(String username) throws ParserConfigurationException, SAXException, IOException, WSSecurityException {
		try {
			String wsSecurityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

			Element usernameTokenElement = doc.createElementNS(wsSecurityNamespace, "wsse:UsernameToken");
			Element usernameElement = doc.createElementNS(wsSecurityNamespace, "wsse:Username");
			Element passwordElement = doc.createElementNS(wsSecurityNamespace, "wsse:Password");
			usernameElement.setTextContent(username);
			passwordElement.setAttribute("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
			usernameTokenElement.appendChild(usernameElement);
			usernameTokenElement.appendChild(passwordElement);
			secHeader.getSecurityHeader().appendChild(usernameTokenElement);
		} catch (Exception e) {
			e.printStackTrace();
		}
		return this;
	}

	public AstSoapDocument insertTimestamp(int timeToLive, String tsPrefix) {
		TimestampInjector.inject(timeToLive, tsPrefix).into(doc, secHeader.getSecurityHeader());
		return this;
	}

	public AstSoapDocument withSigCrypto(Crypto sigCrypto) {
		this.sigCrypto = sigCrypto;
		return this;
	}

	public AstSoapDocument withEncCrypto(Crypto encCrypto) {
		this.encCrypto = encCrypto;
		return this;
	}

	public AstSoapDocument signBody(String sigAlgorithm, String signatureUser, String password) {
		SoapSigner.prepare(sigAlgorithm, signatureUser, password, sigCrypto).signBody(doc, secHeader);
		return this;
	}

	public AstSoapDocument signTimestamp(String sigAlgorithm, String signatureUser, String password) {
		SoapSigner.prepare(sigAlgorithm, signatureUser, password, sigCrypto).signTimestamp(doc, secHeader);
		return this;
	}

	public AstSoapDocument sign(String sigAlgorithm, String signatureUser, String password, List<WSEncryptionPart> signatureParts) {
		SoapSigner.prepare(sigAlgorithm, signatureUser, password, sigCrypto).sign(doc, secHeader, signatureParts);
		return this;
	}

	public AstSoapDocument encryptBody(String encSymmAlgo, String encKeyTransport, String encUser) {
		SoapEncryptor.prepare(encSymmAlgo, encKeyTransport, encUser, encCrypto).encryptBody(doc, secHeader);
		return this;
	}

	public AstSoapDocument encryptSignature(String encSymmAlgo, String encKeyTransport, String encUser) {
		SoapEncryptor.prepare(encSymmAlgo, encKeyTransport, encUser, encCrypto).encryptSignature(doc, secHeader);
		return this;
	}

	public AstSoapDocument encryptBodyAndSignature(String encSymmAlgo, String encKeyTransport, String encUser) {
		SoapEncryptor.prepare(encSymmAlgo, encKeyTransport, encUser, encCrypto).encryptBodyAndSignature(doc, secHeader);
		return this;
	}

	public AstSoapDocument encrypt(String encSymmAlgo, String encKeyTransport, String encUser, List<WSEncryptionPart> encryptParts) {
		SoapEncryptor.prepare(encSymmAlgo, encKeyTransport, encUser, encCrypto).encrypt(doc, secHeader, encryptParts);
		return this;
	}

	public Document getDoc() {
		return doc;
	}

	public WSSecHeader getSecHeader() {
		return secHeader;
	}

	public Timestamp getTs() {
		return ts;
	}

	public Crypto getSigCrypto() {
		return sigCrypto;
	}

	public Crypto getEncCrypto() {
		return encCrypto;
	}
}
