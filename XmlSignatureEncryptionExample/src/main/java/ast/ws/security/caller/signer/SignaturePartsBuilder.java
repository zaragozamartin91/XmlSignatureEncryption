package ast.ws.security.caller.signer;

import java.util.ArrayList;
import java.util.List;

import org.apache.ws.security.WSEncryptionPart;

public class SignaturePartsBuilder {
	protected List<WSEncryptionPart> signatureParts = new ArrayList<WSEncryptionPart>();

	private SignaturePartsBuilder() {
	}

	public static SignaturePartsBuilder build() {
		return new SignaturePartsBuilder();
	}

	public SignaturePartsBuilder body() {
		signatureParts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Element"));
		return this;
	}

	public SignaturePartsBuilder timestamp() {
		signatureParts.add(new WSEncryptionPart("Timestamp",
				"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd", "Element"));
		return this;
	}

	public List<WSEncryptionPart> getParts() {
		return new ArrayList<WSEncryptionPart>(signatureParts);
	}
}
