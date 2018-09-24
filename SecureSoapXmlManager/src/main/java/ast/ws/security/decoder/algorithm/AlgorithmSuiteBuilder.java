package ast.ws.security.decoder.algorithm;

import org.apache.ws.security.components.crypto.AlgorithmSuite;
import org.w3c.dom.Document;

import ast.ws.security.util.DocumentUtils;

public class AlgorithmSuiteBuilder {
	private String signatureAlgorithm;
	private String signatureDigestAlgorithm;
	private String encrAlgorithm;
	private String transportAlgorithm;

	private AlgorithmSuiteBuilder() {
	}

	public static AlgorithmSuiteBuilder build() {
		return new AlgorithmSuiteBuilder();
	}

	public AlgorithmSuiteBuilder withSignatureAlgorithm(String signatureAlgorithm) {
		this.signatureAlgorithm = signatureAlgorithm;
		return this;
	}

	public AlgorithmSuiteBuilder withSignatureDigestAlgorithm(String signatureDigestAlgorithm) {
		this.signatureDigestAlgorithm = signatureDigestAlgorithm;
		return this;
	}

	public AlgorithmSuiteBuilder withEncrAlgorithm(String encrAlgorithm) {
		this.encrAlgorithm = encrAlgorithm;
		return this;
	}

	public AlgorithmSuiteBuilder withTransportAlgorithm(String transportAlgorithm) {
		this.transportAlgorithm = transportAlgorithm;
		return this;
	}

	public AlgorithmSuiteBuilder fromDocument(Document document) {
		signatureAlgorithm = DocumentUtils.getAttributeValue(document, "SignatureMethod", "Algorithm",
				"http://www.w3.org/2000/09/xmldsig#", 0, signatureAlgorithm);
		transportAlgorithm = DocumentUtils.getAttributeValue(document, "EncryptionMethod", "Algorithm",
				"http://www.w3.org/2001/04/xmlenc#", 0, transportAlgorithm);

		return this;
	}

	public String getSignatureAlgorithm() {
		return signatureAlgorithm;
	}

	public String getSignatureDigestAlgorithm() {
		return signatureDigestAlgorithm;
	}

	public String getEncrAlgorithm() {
		return encrAlgorithm;
	}

	public String getTransportAlgorithm() {
		return transportAlgorithm;
	}

	public AlgorithmSuite get() {
		AlgorithmSuite algorithmSuite = new AlgorithmSuite();

		if (signatureAlgorithm != null && !"".equals(signatureAlgorithm)) {
			algorithmSuite.addSignatureMethod(signatureAlgorithm);
		}

		// String signatureAlgorithm = getString(WSHandlerConstants.SIG_ALGO,
		// mc);
		if (signatureDigestAlgorithm != null && !"".equals(signatureDigestAlgorithm)) {
			algorithmSuite.addDigestAlgorithm(signatureDigestAlgorithm);
		}

		// String encrAlgorithm = getString(WSHandlerConstants.ENC_SYM_ALGO,
		// mc);
		if (encrAlgorithm != null && !"".equals(encrAlgorithm)) {
			algorithmSuite.addEncryptionMethod(encrAlgorithm);
		}

		if (transportAlgorithm != null && !"".equals(transportAlgorithm)) {
			algorithmSuite.addKeyWrapAlgorithm(transportAlgorithm);
		}

		return algorithmSuite;
	}
}
