package ast.ws.security.caller.encryptor;

import java.util.ArrayList;
import java.util.List;

import org.apache.ws.security.WSEncryptionPart;

public class EncryptPartsBuilder {
	protected List<WSEncryptionPart> encryptParts = new ArrayList<WSEncryptionPart>();

	private EncryptPartsBuilder() {
	}

	public static EncryptPartsBuilder build() {
		return new EncryptPartsBuilder();
	}

	public EncryptPartsBuilder signature() {
		encryptParts.add(new WSEncryptionPart("Signature", "http://www.w3.org/2000/09/xmldsig#", "Element"));
		return this;
	}

	public EncryptPartsBuilder body() {
		encryptParts.add(new WSEncryptionPart("Body", "http://schemas.xmlsoap.org/soap/envelope/", "Content"));
		return this;
	}

	public List<WSEncryptionPart> getParts() {
		return new ArrayList<WSEncryptionPart>(encryptParts);
	}
}
