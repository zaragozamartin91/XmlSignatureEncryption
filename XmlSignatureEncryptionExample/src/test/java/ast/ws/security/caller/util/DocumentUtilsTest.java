package ast.ws.security.caller.util;

import static org.junit.Assert.*;

import java.io.IOException;

import javax.xml.parsers.ParserConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;

import ast.ws.security.caller.soap.SoapDocumentBuilder;
import ast.ws.security.util.DocumentUtils;

public class DocumentUtilsTest {
	String xmlString = "<soap:Envelope xmlns:soap=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\"><soap:Header><wsse:Security xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" soap:mustUnderstand=\"1\"><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EncKeyId-15F7C51F42619207421457372853212803\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-1_5\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><ds:X509Data><ds:X509IssuerSerial><ds:X509IssuerName>CN=067</ds:X509IssuerName><ds:X509SerialNumber>1741810916</ds:X509SerialNumber></ds:X509IssuerSerial></ds:X509Data></wsse:SecurityTokenReference></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>aXuJBWWwswbfVvfO3RxW8nf5brLSiRuqaOt7DuI9+PokSy5dZcU2o19lky3Jg3iZ4yWu588eHur74X/rmP9pAusgh1MjJZXy+B0I+h3qbA+JghyudU/d2uQmwmBzvmuEzhdpjN82L5FPXWX5Wrv6rdslEFNEu2b+nwxgA/3xIcIDiiMSX4VlY1eifD4A8tOYeOVOyjZgSLO1iJ7ZFLWQVzjGDa0dycezQoT0qLVqnT3PKnexVQTSLujjbiEbopbhbswoqflE5ik44Ko+9yGN/kCfycKxhIE4YHCr/9fSXaDK4r3WugE81+fIv6XRZH8Ax3zlyY6N9s3dMh8o1Kw8jw==</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#EncDataId-802\"/><xenc:DataReference URI=\"#EncDataId-803\"/></xenc:ReferenceList></xenc:EncryptedKey><wsse:BinarySecurityToken xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" wsu:Id=\"CertId-15F7C51F42619207421457372853196799\">MIIC2TCCAcGgAwIBAgIEYynwcjANBgkqhkiG9w0BAQsFADAdMRswGQYDVQQDExJQcmlzbWFNZWRpb3NEZVBhZ28wHhcNMTYwMTI5MDEzMDU3WhcNMTgwMTI4MDEzMDU3WjAdMRswGQYDVQQDExJQcmlzbWFNZWRpb3NEZVBhZ28wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDNiOk5M1SSQRfgM2IpYEn6FLNaEO2YwaBtGO9XtHP3sxw4li0qglEvjeCZnSN5wvHZ/Ak//qCSTmFPZa3jbeppTC2Z9RodS+6+vE43kKnZs8p/EYSUywlNqG5jYj45lTxJsF1pht4qCFypbUperhR6Gk5plrn8zj9QI0aIdBQoTDB5jreIKaSv3Fe0QIW16manz8q4luFH3AUCy/DrPO7mbq05OwLySvodJp5P50kwN/XUwWpC/SxVhFL01DoIaJ9ofH8YVAy/92Ec5udKzCH+4pGo8gAktztMib8WtwGpw4g2YaTuExmiyF/MreKemUZztG2jAojRIOiHVqL+QlDbAgMBAAGjITAfMB0GA1UdDgQWBBTIqwOuRHsFQ/+z0M3IlrETG+rObjANBgkqhkiG9w0BAQsFAAOCAQEASgmISTvOQanxfw3afWTULhYFGEGvDqwtG3DDlpQbN2s63D3l6TyFgGI+xmZ/8JKqTcWt2plkfnkx1ACAzalE9Jv12t7qAhG7mT0NE4Jdgg6dpHI0+o+AcaS0DGBt6ZVD/CFGWk3cURcDphzGVJzlyA4GruNDClM74wKTdy82mNviOtrxsZsUXnbgT/KyDz+4GkR3Pfdzg908jqLtXm5Jr3q7t9JJ+Y/eMxfpaa7LoLm4298E6FAHu2F00hiwe7qDIzcHzIEkWR7GxZVUbcJRKToryFBfIzpSI1UfAQgEerLqeOZScLDZ8fXTCyFj/CTcVwa8jJSv4RQeHLV992z1+Q==</wsse:BinarySecurityToken><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\" Id=\"Signature-800\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#Timestamp-799\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>dkHRx3DK6x8342nclBoVCmndEm0=</ds:DigestValue></ds:Reference><ds:Reference URI=\"#id-801\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>8uqLDfjbCEmwQhGYP2jnPgkYahU=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>egwycPv+wBgpECoF5YcZHrxXvLDpCA18n1zbTFoakKih/p+/Z/TnCltzgQCU3Rn5sDRRm2QUnZKjhXvM66ia/eUe0/JMAmjJxn5TdYz+8XBGF2V2lwBeec6cCeYg+P0+GjPbEwIdRRy/ui2Jd0fiF71J2ZehzbGBfs/ufJaoAwa8B8U6iMvFAc8iIm3h/M2Bq/f3DO+nUf5onXDgsto85njGqmNxS+TzrGjzsRxoqBxNX1WMh37AhUXdjntw0yN8cNGXW6ZnKwvEb5D5dMyX1DORnYoE/5JsYcMZEVgPplEAryDiQoOcy/+g7NxJubZ2MpLCU8J0vwYt8sO6QPvFqg==</ds:SignatureValue><ds:KeyInfo Id=\"KeyId-15F7C51F42619207421457372853196800\"><wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"STRId-15F7C51F42619207421457372853196801\"><wsse:Reference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" URI=\"#CertId-15F7C51F42619207421457372853196799\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/></wsse:SecurityTokenReference></ds:KeyInfo></ds:Signature><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EncDataId-802\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><wsse:Reference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" URI=\"#EncKeyId-15F7C51F42619207421457372853212803\"/></wsse:SecurityTokenReference></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>QnuypvqxxCbOxng507J/LkLniOmGAgXBpQDI8yzB+zt7s7uFi9fMcaW+YldB0Ul+yLEAeOpVLvIaWH29KprPb9dSluVLYuWUct0GAVoRtSBSXvnGm4vftCuSiik4+nktpPgPgHgZmznRNpYECErRjgClA6nMwAZ+C1ClA/kdcI31b3vV3PPYmCQ0FQZNh91Wakts77avR0AA9ctDiS/Gs44a4qMFiaa+NIjsFs3kTfTtZ/oawAvL2A7nXN+dfM5h9Tngf/hkMwReLesJ7NVsWwg3ucgS1GB065vSRvKcE10vRmIc0knx8BcPq0OvRs3Y5eAnRg+8U1b05SspUxnpwSZbFSWuIzMnli6DD9+ctM5n+kHs1RG9UkDD9TSy9ZK4hv1iaAAbXgkjkoOECLJopGvGEHBc7n+vbxpjmdBN7asGNFpouq7c3AreH1p1mIQkG5gIB/W7F6Lc6Nj7RBinPWOr2f6KLCWOuEBcCqPpPtrUPYOd+2MAU1Wb5rjRmhdJJP+hfqdtp+lCvl9Dbui68q3TnmLl0Dpbdz12H5Os6EvDDAGJmrs6yg7EVRXItmp0w9rs0kxFi+rjGY1u9pBgLP9n6xlzxYVqG5uVPndsdFzT+zYNn9tpbIgwhfiGNSaP</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></wsse:Security></soap:Header><soap:Body xmlns:wsu=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" wsu:Id=\"id-801\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"EncDataId-803\" Type=\"http://www.w3.org/2001/04/xmlenc#Content\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes128-cbc\"/><ds:KeyInfo xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><wsse:SecurityTokenReference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\"><wsse:Reference xmlns:wsse=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\" URI=\"#EncKeyId-15F7C51F42619207421457372853212803\"/></wsse:SecurityTokenReference></ds:KeyInfo><xenc:CipherData><xenc:CipherValue>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</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData></soap:Body></soap:Envelope>";
	private Document document;

	@Test
	public void testCreateDocument() throws ParserConfigurationException, SAXException, IOException {
		DocumentUtils.createDocument(xmlString);
	}

	@Before
	public void init() {
		document = SoapDocumentBuilder.build().fromString(xmlString);
	}

	@Test
	public void testGetAttributeValue() {
		{
			String attributeValue = DocumentUtils.getAttributeValue(document, "SignatureMethod", "Algorithm", "*", 0);
			assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", attributeValue);
		}

		{
			String attributeValue = DocumentUtils.getAttributeValue(document, "EncryptionMethod", "Algorithm", "*", 0);
			assertEquals("http://www.w3.org/2001/04/xmlenc#rsa-1_5", attributeValue);
		}

		{
			String attributeValue = DocumentUtils.getAttributeValue(document, "SignatureMethod", "Algorithm",
					"http://www.w3.org/2000/09/xmldsig#", 0);
			assertEquals("http://www.w3.org/2000/09/xmldsig#rsa-sha1", attributeValue);
		}

		{
			String attributeValue = DocumentUtils.getAttributeValue(document, "EncryptionMethod", "Algorithm",
					"http://www.w3.org/2001/04/xmlenc#", 0);
			assertEquals("http://www.w3.org/2001/04/xmlenc#rsa-1_5", attributeValue);
		}
	}

	@Test
	public void testGetDefaultAttributeValue() {
		String unknownNode = "asdads";
		String unknownAttributeName = "asdasd";

		{
			String attributeValue = DocumentUtils.getAttributeValue(document, unknownNode, unknownAttributeName,
					"http://www.w3.org/2001/04/xmlenc#", 0, "Attribute");
			assertEquals("Attribute", attributeValue);
		}
		
		{
			String attributeValue = DocumentUtils.getAttributeValue(document, "EncryptionMethod", unknownAttributeName,
					"http://www.w3.org/2001/04/xmlenc#", 0, "Attribute");
			assertEquals("Attribute", attributeValue);
		}
		
		{
			String attributeValue = DocumentUtils.getAttributeValue(document, "EncryptionMethod", "Algorithm",
					"http://www.w3.org/2001/04/xmlenc#", 0, "Attribute");
			assertEquals("http://www.w3.org/2001/04/xmlenc#rsa-1_5", attributeValue);
		}
	}
}
