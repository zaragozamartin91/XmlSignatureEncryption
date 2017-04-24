package ast.ws.security.caller.signer;

import java.util.List;

import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WsuIdAllocator;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.WSSecSignature;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Entidad encargada de firmar un documento Xml.
 * 
 * @author martin.zaragoza
 *
 */
public class SoapSigner {
	private String sigAlgorithm = "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	private String signatureUser = "067";
	private String password = "changeme";
	private Crypto sigCrypto;
	private WsuIdAllocator idAllocator = WSSConfig.DEFAULT_ID_ALLOCATOR;
	private WSSConfig wssConfig;

	/**
	 * Construye una nueva entidad firmadora.
	 * 
	 * @param sigAlgorithm
	 *            - Algoritmo de firma a usar. Ej:
	 *            "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	 * @param signatureUser
	 *            - Usuario de clave privada.
	 * @param password
	 *            - Password de clave privada.
	 * @param sigCrypto
	 *            - KeyStore con clave privada.
	 */
	public SoapSigner(String sigAlgorithm, String signatureUser, String password, Crypto sigCrypto) {
		super();
		this.sigAlgorithm = sigAlgorithm;
		this.signatureUser = signatureUser;
		this.password = password;
		this.sigCrypto = sigCrypto;

		wssConfig = WSSConfig.getNewInstance();
		wssConfig.setIdAllocator(idAllocator);
	}

	/**
	 * Construye una nueva entidad firmadora.
	 * 
	 * @param sigAlgorithm
	 *            - Algoritmo de firma a usar. Ej:
	 *            "http://www.w3.org/2000/09/xmldsig#rsa-sha1";
	 * @param signatureUser
	 *            - Usuario de clave privada.
	 * @param password
	 *            - Password de clave privada.
	 * @param sigCrypto
	 *            - KeyStore con clave privada.
	 */
	public static SoapSigner prepare(String sigAlgorithm, String signatureUser, String password, Crypto sigCrypto) {
		return new SoapSigner(sigAlgorithm, signatureUser, password, sigCrypto);
	}

	/**
	 * Firma determinadas partes de un documento.
	 * 
	 * @param doc
	 *            - Documento a firmar.
	 * @param secHeader
	 *            - Encabezado de seguridad del documento.
	 * @param signatureParts
	 *            - Partes del documento a firmar (ver
	 *            {@link SignaturePartsBuilder}.
	 * @return this.
	 */
	public SoapSigner sign(Document doc, WSSecHeader secHeader, List<WSEncryptionPart> signatureParts) {
		boolean useSingleCert = true;
		// List<WSEncryptionPart> signatureParts = buildSignatureParts();

		System.out.println();

		WSSecSignature wsSign = new WSSecSignature(wssConfig);

		wsSign.setSignatureAlgorithm(sigAlgorithm);

		/*
		 * TODO : EL PASSWORD SE DEBERIA ESTABLECER A PARTIR DE UN Callback. X ejemplo
		 * ClientKeystorePasswordCallback
		 */
		wsSign.setUserInfo(signatureUser, password);
		wsSign.setUseSingleCertificate(useSingleCert);
		wsSign.setParts(signatureParts);

		try {
			wsSign.prepare(doc, sigCrypto, secHeader);

			Element siblingElementToPrepend = null;

			List<javax.xml.crypto.dsig.Reference> referenceList = wsSign.addReferencesToSign(signatureParts, secHeader);

			/* AQUI SE AGREGA LA FIRMA */
			wsSign.computeSignature(referenceList, true, siblingElementToPrepend);

			wsSign.prependBSTElementToHeader(secHeader);
			// reqData.getSignatureValues().add(wsSign.getSignatureValue());
		} catch (WSSecurityException e) {
			throw new SoapSignerException(e);
		}

		return this;
	}

	/**
	 * Firma el contenido del cuerpo de un documento.
	 * 
	 * @param doc
	 *            - Documento a firmar.
	 * @param secHeader
	 *            - Encabezado de seguridad del documento.
	 * @return this.
	 */
	public SoapSigner signBody(Document doc, WSSecHeader secHeader) {
		List<WSEncryptionPart> signatureParts = SignaturePartsBuilder.build().body().getParts();
		return this.sign(doc, secHeader, signatureParts);
	}

	/**
	 * Firma el timestamp de un documento.
	 * 
	 * @param doc
	 *            - Documento a firmar.
	 * @param secHeader
	 *            - Encabezado de seguridad del documento.
	 * @return this.
	 */
	public SoapSigner signTimestamp(Document doc, WSSecHeader secHeader) {
		List<WSEncryptionPart> signatureParts = SignaturePartsBuilder.build().timestamp().getParts();
		return this.sign(doc, secHeader, signatureParts);
	}

	/**
	 * Firma el contenido del cuerpo y el timestamp de un documento.
	 * 
	 * @param doc
	 *            - Documento a firmar.
	 * @param secHeader
	 *            - Encabezado de seguridad del documento.
	 * @return this.
	 */
	public SoapSigner signBodyAndTimestamp(Document doc, WSSecHeader secHeader) {
		List<WSEncryptionPart> signatureParts = SignaturePartsBuilder.build().timestamp().body().getParts();
		return this.sign(doc, secHeader, signatureParts);
	}

	public WSSConfig getWssConfig() {
		return wssConfig;
	}
}
