package ast.ws.security.caller.signer;

import java.util.ArrayList;
import java.util.List;

import org.apache.ws.security.WSEncryptionPart;

public class SignaturePartsBuilder {
	/*Regarding the modifier ("Content" or "Element") refer to the W3C XML Encryption specification. */
	public static final String ENCRYPTION_MODIFIER_ELEMENT = "Element";
	public static final String ENCRYPTION_MODIFIER_CONTENT = "Content";
	
	private List<WSEncryptionPart> signatureParts = new ArrayList<WSEncryptionPart>();

	private SignaturePartsBuilder() {
	}

	public static SignaturePartsBuilder build() {
		return new SignaturePartsBuilder();
	}
	
	public SignaturePartsBuilder to() {
		signatureParts.add(new WSEncryptionPart("To", "http://www.w3.org/2005/08/addressing", ENCRYPTION_MODIFIER_ELEMENT));
		return this;
	}

	public SignaturePartsBuilder body() {
		signatureParts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", ENCRYPTION_MODIFIER_ELEMENT));
		return this;
	}

	public SignaturePartsBuilder timestamp() {
		signatureParts.add(new WSEncryptionPart("Timestamp",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", ENCRYPTION_MODIFIER_ELEMENT));
		return this;
	}

	public List<WSEncryptionPart> getParts() {
		return new ArrayList<WSEncryptionPart>(signatureParts);
	}
}
