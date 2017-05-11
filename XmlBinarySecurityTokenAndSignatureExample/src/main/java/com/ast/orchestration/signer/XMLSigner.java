package com.ast.orchestration.signer;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.StringWriter;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.LinkedList;
import java.util.List;
import java.util.UUID;

import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.crypto.dsig.DigestMethod;
import javax.xml.crypto.dsig.Reference;
import javax.xml.crypto.dsig.SignatureMethod;
import javax.xml.crypto.dsig.SignedInfo;
import javax.xml.crypto.dsig.Transform;
import javax.xml.crypto.dsig.XMLSignature;
import javax.xml.crypto.dsig.XMLSignatureFactory;
import javax.xml.crypto.dsig.dom.DOMSignContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.crypto.dsig.spec.TransformParameterSpec;
import javax.xml.namespace.QName;
import javax.xml.soap.MessageFactory;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPConstants;
import javax.xml.soap.SOAPElement;
import javax.xml.soap.SOAPEnvelope;
import javax.xml.soap.SOAPException;
import javax.xml.soap.SOAPHeader;
import javax.xml.soap.SOAPHeaderElement;
import javax.xml.soap.SOAPMessage;
import javax.xml.soap.SOAPPart;
import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.TransformerFactoryConfigurationError;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import org.apache.ws.security.util.Base64;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import com.ast.orchestration.aes.EncryptionUtils;
import com.sun.jmx.snmp.Timestamp;
import com.sun.org.apache.xml.internal.security.c14n.Canonicalizer;

public class XMLSigner {
	

	private static final String WS_SECURITY_UTILITY_PREFIX = "u";
	private static final String WS_SECURITY_UTILITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	private static final String WS_SECURITY_PREFIX = "o";
	private static final String WS_SECURITY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	private static final String WS_ADDRESSING_PREFIX = "a";
	private static final String WS_ADDRESSING_NAMESPACE = "http://www.w3.org/2005/08/addressing";
	private static final String WS_SECURITY_BASE64BINARY_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary";
	private static final String WS_TOKEN_X509_V3_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
	private static final String WS_TOKEN_X509_SUBJECTKEYINDENTIFIER_NAMESPACE= "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509SubjectKeyIdentifier";
	private static final String SOAP_ENVELOPE_PREFIX = "s";
	private static final String SOAP_ENVELOPE_NAMESPACE = "http://www.w3.org/2003/05/soap-envelope";
	private static final String MUSTUNDERSTAND_VALUE = "1";
	private static final String DATE_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.sss'Z'";
	private static final String ID_ELEMENT_TO = "_1";
	private static final String ID_ELEMENT_TIMESTAMP = "_0";
	
	@SuppressWarnings({ "static-access", "restriction" })
	public String sign(String request, SecurityData securityData) throws Exception {

		
		SOAPMessage soapMessage = MessageFactory.newInstance(SOAPConstants.SOAP_1_2_PROTOCOL).createMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
	
		
		
		byte[] reqBytes = request.getBytes("UTF-8");
		reqBytes = new String(reqBytes, "ISO8859-1").getBytes("ISO-8859-1");
		ByteArrayInputStream bis = new ByteArrayInputStream(reqBytes);
		StreamSource streamSource = new StreamSource(bis);
		soapPart.setContent(streamSource);
		KeyStore keyStore = getKeystore(securityData);
		
		
		
		SOAPEnvelope soapEnvelope = soapPart.getEnvelope();
		SOAPHeader soapHeader = soapEnvelope.getHeader();

//		SOAPBody soapBody = soapEnvelope.getBody();

		soapEnvelope.addNamespaceDeclaration(WS_ADDRESSING_PREFIX, WS_ADDRESSING_NAMESPACE);
		soapEnvelope.addNamespaceDeclaration(WS_SECURITY_UTILITY_PREFIX, WS_SECURITY_UTILITY_NAMESPACE);
		soapEnvelope.addNamespaceDeclaration(WS_SECURITY_PREFIX, WS_SECURITY_NAMESPACE);


		// ACTION
		QName action = soapEnvelope.createQName("Action", WS_ADDRESSING_PREFIX);
		
		SOAPHeaderElement actionElement = soapHeader.addHeaderElement(action);
		actionElement.addAttribute(soapEnvelope.createName("mustUnderstand", SOAP_ENVELOPE_PREFIX, SOAP_ENVELOPE_NAMESPACE), MUSTUNDERSTAND_VALUE);
		actionElement.addTextNode(securityData.getHeaderAction());

		
		// MESSAGEID
		QName messageID = soapEnvelope.createQName("MessageID", WS_ADDRESSING_PREFIX);
		SOAPHeaderElement messageId = soapHeader.addHeaderElement(messageID);
		messageId.addTextNode("urn:uuid:" + UUID.randomUUID().toString());

		
		// REPLYTO
		QName replyTo = soapEnvelope.createQName("ReplyTo", WS_ADDRESSING_PREFIX);
		SOAPHeaderElement replyToElement = soapHeader.addHeaderElement(replyTo);

		
		// REPLYTO-ADDRESS
		QName address = soapEnvelope.createQName("Address", WS_ADDRESSING_PREFIX);
		SOAPElement addressElement = replyToElement.addChildElement(address);
		addressElement.addTextNode(securityData.getHeaderAddress());

		
		// TO
		QName to = soapEnvelope.createQName("To", WS_ADDRESSING_PREFIX);
		SOAPHeaderElement toElement = soapHeader.addHeaderElement(to);
		toElement.addTextNode(securityData.getHeaderTo());
//		toElement.addAttribute(soapEnvelope.createName("mustUnderstand", SOAP_ENVELOPE_PREFIX, WS_SECURITY_UTILITY_NAMESPACE), MUSTUNDERSTAND_VALUE);
		toElement.addAttribute(soapEnvelope.createName("mustUnderstand", SOAP_ENVELOPE_PREFIX, SOAP_ENVELOPE_NAMESPACE), MUSTUNDERSTAND_VALUE);
		toElement.addAttribute(soapEnvelope.createName("Id", WS_SECURITY_UTILITY_PREFIX, WS_SECURITY_UTILITY_NAMESPACE), ID_ELEMENT_TO);

		// SECURITY
		QName security = soapEnvelope.createQName("Security", WS_SECURITY_PREFIX);
		SOAPHeaderElement securityElement = soapHeader.addHeaderElement(security);
//		securityElement.addAttribute(soapEnvelope.createName("mustUnderstand", SOAP_ENVELOPE_PREFIX, WS_SECURITY_UTILITY_NAMESPACE), MUSTUNDERSTAND_VALUE);
		securityElement.addAttribute(soapEnvelope.createName("mustUnderstand", SOAP_ENVELOPE_PREFIX, SOAP_ENVELOPE_NAMESPACE), MUSTUNDERSTAND_VALUE);

		
		// SECURITY-TIMESTAMP
		QName timestamp = soapEnvelope.createQName("Timestamp", WS_SECURITY_UTILITY_PREFIX);
		SOAPElement timestampElement = securityElement.addChildElement(timestamp);
		SimpleDateFormat timeFormat = new SimpleDateFormat(DATE_FORMAT);
		Timestamp time = new Timestamp();
		
		// SECURITY-TIMESTAMP-CREATED
		QName created = soapEnvelope.createQName("Created", WS_SECURITY_UTILITY_PREFIX);
		SOAPElement createdElement = timestampElement.addChildElement(created);	

		Calendar calendarCreated = Calendar.getInstance();
		calendarCreated.setTime(time.getDate());
		calendarCreated.add(Calendar.HOUR_OF_DAY, 3);
		String date = timeFormat.format(calendarCreated.getTime());
//		timeFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		createdElement.addTextNode(date);

		
		// SECURITY-TIMESTAMP-EXPIRES
		QName expires = soapEnvelope.createQName("Expires", WS_SECURITY_UTILITY_PREFIX);
		SOAPElement expiresElement = timestampElement.addChildElement(expires);
		
		Calendar calendarExpires = Calendar.getInstance();
		calendarExpires.setTime(time.getDate());
		calendarExpires.add(Calendar.HOUR_OF_DAY, 3);
		calendarExpires.add(Calendar.MINUTE, Integer.parseInt(securityData.getHeaderTimestampExpiration()));
		String expiredTime = timeFormat.format(calendarExpires.getTime());
//		timeFormat.setTimeZone(TimeZone.getTimeZone("GMT"));
		expiresElement.addTextNode(expiredTime);

		timestampElement.addAttribute(soapEnvelope.createName("Id", WS_SECURITY_UTILITY_PREFIX, WS_SECURITY_UTILITY_NAMESPACE), ID_ELEMENT_TIMESTAMP);
		securityElement.addChildElement(timestampElement);

		// SECURITY-BINARY SECURITY TOKEN
		String binaryTokenId = "uuid:" + UUID.randomUUID().toString();
		SOAPElement binarySecurityTokenElement = getBinarySecurityToken(securityData, soapEnvelope, securityElement, binaryTokenId, keyStore);
		securityElement.addChildElement(binarySecurityTokenElement);

		// SECURITY-SIGNATURE
		XMLSignatureFactory sigFactory = XMLSignatureFactory.getInstance();

		// SECURITY-SIGNATURE-SIGNED INFO
		SignedInfo signedInfo = getSignedInfo(sigFactory);
		PrivateKey privateKey = (PrivateKey) keyStore.getKey(securityData.getAlias(), EncryptionUtils.desencriptadorAES(securityData.getAliasPass()).toCharArray());
		
		DOMSignContext signerContext = new DOMSignContext(privateKey, securityElement);
		signerContext.putNamespacePrefix(XMLSignature.XMLNS, "");
		signerContext.setIdAttributeNS(toElement, WS_SECURITY_UTILITY_NAMESPACE, "Id");
		signerContext.setIdAttributeNS(timestampElement, WS_SECURITY_UTILITY_NAMESPACE, "Id");

		// SECURITY-SIGNATURE-KEY INFO
		KeyInfo keyInfo = null;
		XMLSignature signer = sigFactory.getInstance().newXMLSignature(signedInfo, keyInfo);
		signer.sign(signerContext);

		// RKEY = BinarySecurityToken y Key Info referenciando a BinarySecurityToken 
		// IKEY = BinarySecurityToken y Key Info identificador a Certificado
		if ("RKEY".equals(securityData.getHeaderKeyInfo())){
			addKeyInfoBST(soapEnvelope, soapHeader, binaryTokenId);
			
		}else if("IKEY".equals(securityData.getHeaderKeyInfo())){				    
		    X509Certificate cert = (X509Certificate) keyStore.getCertificate(securityData.getAlias());    
		    addKeyInfoBST(soapEnvelope, soapHeader, binaryTokenId, cert);	    
		}
		
		// XMLSOAP TO STRING
		String strResult = soapPartToString(soapPart);

		return strResult;
	}

	@SuppressWarnings("restriction")
	private String soapPartToString(SOAPPart soapPart) throws SOAPException, TransformerFactoryConfigurationError,
			TransformerConfigurationException, TransformerException {
		Source source = soapPart.getContent();
		StringWriter writer = new StringWriter();
		StreamResult result = new StreamResult(writer);
		TransformerFactory tFactory = TransformerFactory.newInstance();
		Transformer transformer = tFactory.newTransformer();
		transformer.transform(source, result);
		String strResult = writer.toString();
		return strResult;
	}
	
	/** Retorna un objeto Keystore generado con la configuracion del properties **/
	
	private KeyStore getKeystore(SecurityData securityData) throws Exception { 
		FileInputStream input = new FileInputStream(securityData.getKeystorefilePath());
	    KeyStore keyStore = KeyStore.getInstance(securityData.getKeystoreType());
	    keyStore.load(input, EncryptionUtils.desencriptadorAES(securityData.getKeystorePass()).toCharArray());
	    input.close();	    
	    return keyStore;
	}	
	
	/** Retorna un objeto Element correspondiente al BinarySecurityToken **/
	
	@SuppressWarnings("restriction")
	private SOAPElement getBinarySecurityToken(SecurityData securityData, SOAPEnvelope soapEnvelope, 
					 SOAPHeaderElement securityElement,String binaryTokenId, KeyStore keyStore) throws Exception {
		QName binarySecurityToken = soapEnvelope.createQName("BinarySecurityToken", WS_SECURITY_PREFIX);
		SOAPElement binarySecurityTokenElement = securityElement.addChildElement(binarySecurityToken);
		
//		binarySecurityTokenElement.addAttribute(soapEnvelope.createName("Id"), binaryTokenId);
		binarySecurityTokenElement.addAttribute(soapEnvelope.createName("Id", WS_SECURITY_UTILITY_PREFIX, WS_SECURITY_UTILITY_NAMESPACE), binaryTokenId);
		binarySecurityTokenElement.addTextNode(Base64.encode(keyStore.getCertificate(securityData.getAlias()).getEncoded()));
		binarySecurityTokenElement.addAttribute(soapEnvelope.createName("ValueType"),WS_TOKEN_X509_V3_NAMESPACE);
		binarySecurityTokenElement.addAttribute(soapEnvelope.createName("EncodingType"),WS_SECURITY_BASE64BINARY_NAMESPACE);
		return binarySecurityTokenElement;
	}
	
	/** Retorna un objeto SignedInfo con los elementos TImestamp y To firmados mendiante
  	Signature Algorithm, Signature Canonicalization y Digest Algorithm **/

	@SuppressWarnings("restriction")
	private SignedInfo getSignedInfo(XMLSignatureFactory signFactory) throws Exception { 
		TransformParameterSpec transformSpec = null;
		List<Transform> transforms = new LinkedList<Transform>();
		Transform envTransform = signFactory.newTransform(Canonicalizer.ALGO_ID_C14N_EXCL_OMIT_COMMENTS, transformSpec);
		transforms.add(envTransform);
		Reference referenceTimestamp = signFactory.newReference("#"+ID_ELEMENT_TIMESTAMP, signFactory.newDigestMethod(DigestMethod.SHA1, null), transforms, null, null);
		Reference referenceTo = signFactory.newReference("#"+ID_ELEMENT_TO, signFactory.newDigestMethod(DigestMethod.SHA1, null), transforms, null, null);
		
		List<Reference> lista = new LinkedList<Reference>();
		lista.add(referenceTimestamp);
		lista.add(referenceTo);
		SignedInfo signedInfo = signFactory.newSignedInfo(
				signFactory.newCanonicalizationMethod(CanonicalizationMethod.EXCLUSIVE, (C14NMethodParameterSpec) null),
				signFactory.newSignatureMethod(SignatureMethod.RSA_SHA1, null), lista);
		
		return signedInfo;
	}
	
	/** Agrega un objeto Element correspondiente al Key Info **/
	
	@SuppressWarnings("restriction")
	private void addKeyInfoBST(SOAPEnvelope soapEnvelope, SOAPHeader soapHeader, String binaryTokenId) throws Exception {
		addKeyInfoBST(soapEnvelope,soapHeader,binaryTokenId,null);
	}
	
	/** Agrega un objeto Element correspondiente al Key Info **/
	
	@SuppressWarnings("restriction")
	private void addKeyInfoBST(SOAPEnvelope soapEnvelope, SOAPHeader soapHeader, String binaryTokenId, X509Certificate certificate) throws Exception {
		Node node = getSignatureValue(soapHeader);
		SOAPElement signatureElement = (SOAPElement) node;
		SOAPElement keyInfoElement = signatureElement.addChildElement(soapEnvelope.createName("KeyInfo"));
		
		// Con algunas JDKs agrega un namespace vacio. Se agrega un remove por si acaso.
		keyInfoElement.removeNamespaceDeclaration("");

		SOAPElement securityTokenReferenceElement = keyInfoElement.addChildElement(soapEnvelope.createQName("SecurityTokenReference",WS_SECURITY_PREFIX));
		SOAPElement sTReferenceElement = null;
		if (certificate == null){
			sTReferenceElement = securityTokenReferenceElement.addChildElement(soapEnvelope.createQName("Reference", WS_SECURITY_PREFIX));
			sTReferenceElement.addAttribute(soapEnvelope.createName("ValueType"),WS_TOKEN_X509_V3_NAMESPACE);
			sTReferenceElement.addAttribute(soapEnvelope.createName("URI"), "#" + binaryTokenId);				
		} else {		
			sTReferenceElement = securityTokenReferenceElement.addChildElement(soapEnvelope.createQName("KeyIdentifier", WS_SECURITY_PREFIX));
			sTReferenceElement.addAttribute(soapEnvelope.createName("ValueType"),WS_TOKEN_X509_SUBJECTKEYINDENTIFIER_NAMESPACE);
			sTReferenceElement.addAttribute(soapEnvelope.createName("URI"), "#" + binaryTokenId);		
			sTReferenceElement.addTextNode(Base64.encode(certificate.getEncoded()));	
		}	
		securityTokenReferenceElement.addChildElement(sTReferenceElement);
	}
	
	/**	Retorna el nodo Signature del Header.
	   	Por problemas de incompatibilidad con diferentes JDKs se devuelve un nodo ubicado en una 
	   	posicion determinada. Si cambia el orden de los nodos es probable que haya que modificar este metodo. **/
	
	private Node getSignatureValue(SOAPHeader soapHeader) throws Exception{
		// NodeList list = soapHeader.getElementsByTagName("Signature");
		// Node node = list.item(0);
		return soapHeader.getChildNodes().item(4).getChildNodes().item(2);
	}

	/** Retorna un objeto Element correspondiente al Nodo referenciado**/
	
	public Element getNextSiblingElement(Node node) {
		Node sibling = node.getNextSibling();
		while ((sibling != null) && (sibling.getNodeType() != Node.ELEMENT_NODE)) {
			sibling = sibling.getNextSibling();
		}	
		return (Element) sibling;
	}

}