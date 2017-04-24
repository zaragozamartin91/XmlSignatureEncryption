package ast.ws.security.caller.encryptor;

import java.security.cert.X509Certificate;
import java.util.List;

import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WsuIdAllocator;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecEncrypt;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

/**
 * Encriptador de documentos.
 * 
 * @author martin.zaragoza
 *
 */
public class SoapEncryptor {
	private String encSymmAlgo = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
	private String encKeyTransport = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
	private String encUser = "prismakey";
	private Crypto encCrypto;
	private WsuIdAllocator idAllocator = WSSConfig.DEFAULT_ID_ALLOCATOR;
	private WSSConfig wssConfig;

	public SoapEncryptor(String encSymmAlgo, String encKeyTransport, String encUser, Crypto encCrypto) {
		super();
		this.encSymmAlgo = encSymmAlgo;
		this.encKeyTransport = encKeyTransport;
		this.encUser = encUser;
		this.encCrypto = encCrypto;
		
		wssConfig = WSSConfig.getNewInstance();
		wssConfig.setIdAllocator(idAllocator);
	}

	public static SoapEncryptor prepare(String encSymmAlgo, String encKeyTransport, String encUser, Crypto encCrypto) {
		return new SoapEncryptor(encSymmAlgo, encKeyTransport, encUser, encCrypto);
	}

	public SoapEncryptor encrypt(Document doc, WSSecHeader secHeader, List<WSEncryptionPart> encryptParts) {
		X509Certificate encCert = null;
		WSSecEncrypt wsEncrypt = new WSSecEncrypt(wssConfig);

		wsEncrypt.setSymmetricEncAlgorithm(encSymmAlgo);
		wsEncrypt.setKeyEnc(encKeyTransport);

		wsEncrypt.setUserInfo(encUser);
		wsEncrypt.setUseThisCert(encCert);

		wsEncrypt.setParts(encryptParts);

		try {
			wsEncrypt.build(doc, encCrypto, secHeader);
		} catch (WSSecurityException e) {
			throw new SoapEncryptorException(e);
		}

		return this;
	}

	public SoapEncryptor encryptBody(Document doc, WSSecHeader secHeader) {
		return this.encrypt(doc, secHeader, EncryptPartsBuilder.build().body().getParts());
	}

	public SoapEncryptor encryptSignature(Document doc, WSSecHeader secHeader) {
		return this.encrypt(doc, secHeader, EncryptPartsBuilder.build().signature().getParts());
	}
	
	public SoapEncryptor encryptBodyAndSignature(Document doc, WSSecHeader secHeader) {
		return this.encrypt(doc, secHeader, EncryptPartsBuilder.build().signature().body().getParts());
	}
}
