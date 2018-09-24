package ast.ws.security.caller.doc;

import ast.ws.security.caller.encryptor.SoapEncryptor;
import ast.ws.security.caller.injector.addressing.AddressingInjector;
import ast.ws.security.caller.injector.header.SecurityHeaderInjector;
import ast.ws.security.caller.injector.timestamp.TimestampInjector;
import ast.ws.security.caller.signer.SoapSigner;
import ast.ws.security.caller.soap.SoapDocumentBuilder;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.Timestamp;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.ParserConfigurationException;
import java.io.File;
import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * Facilita la construccion de un documento Soap, su firma y encriptacion.
 *
 * @author martin.zaragoza
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

    public AstSoapDocument insertSecurityHeader() {
        this.secHeader = SecurityHeaderInjector.inject(null, true).into(doc).getSecHeader();
        return this;
    }

    public AstSoapDocument insertSecurityHeader(String actor, boolean mustUnderstand) {
        this.secHeader = SecurityHeaderInjector.inject(actor, mustUnderstand).into(doc).getSecHeader();
        return this;
    }

    public AstSoapDocument insertAction(String action) {
        Element soapHeader = getSoapHeader();
        AddressingInjector.fromDocument(doc).injectAction(action, soapHeader);
        return this;
    }

    public AstSoapDocument insertMessageId(String msgId) {
        AddressingInjector.fromDocument(doc).injectMessageId(msgId, getSoapHeader());
        return this;
    }

    public AstSoapDocument insertRandomMessageId() {
        AddressingInjector.fromDocument(doc).injectRandomMessageId(getSoapHeader());
        return this;
    }

    public AstSoapDocument insertTo(String value) {
        AddressingInjector.fromDocument(doc).injectTo(value, getSoapHeader());
        return this;
    }

    public AstSoapDocument insertReplyToAddress(String value) {
        AddressingInjector.fromDocument(doc).injectReplyToAddress(value, getSoapHeader());
        return this;
    }

    private Element getSoapHeader() {
        NodeList nodeList = doc.getElementsByTagNameNS("http://schemas.xmlsoap.org/soap/envelope/", "Header");
        if (nodeList.getLength() == 0) {
            throw new RuntimeException("No se encontro el elemento Header");
        }
        return (Element) nodeList.item(0);
    }

    public AstSoapDocument insertUsernameToken(String username, String password)
            throws ParserConfigurationException, SAXException, IOException, WSSecurityException {
        try {
            String wsSecurityNamespace = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";

            Element usernameTokenElement = doc.createElementNS(wsSecurityNamespace, "wsse:UsernameToken");
            usernameTokenElement.setAttributeNS(
                    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd",
                    "wsu:Id",
                    "UsernameToken-" + UUID.randomUUID());

            Element usernameElement = doc.createElementNS(wsSecurityNamespace, "wsse:Username");
            Element passwordElement = doc.createElementNS(wsSecurityNamespace, "wsse:Password");
            usernameElement.setTextContent(username);
            passwordElement.setTextContent(password);
            passwordElement.setAttribute("Type", "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText");
            usernameTokenElement.appendChild(usernameElement);
            usernameTokenElement.appendChild(passwordElement);
            secHeader.getSecurityHeader().appendChild(usernameTokenElement);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return this;
    }

    public AstSoapDocument insertUsernameToken(String username) throws ParserConfigurationException, SAXException, IOException, WSSecurityException {
        return insertUsernameToken(username, "");
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
