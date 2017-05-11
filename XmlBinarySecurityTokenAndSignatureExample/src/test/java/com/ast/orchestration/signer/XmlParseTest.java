package com.ast.orchestration.signer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import javax.xml.transform.Source;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.stream.StreamResult;
import javax.xml.transform.stream.StreamSource;

import javax.xml.soap.*;

import org.junit.Test;

@SuppressWarnings("restriction")
public class XmlParseTest {

	@Test
	public void test() throws Exception {
		String xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?><s:Envelope xmlns:s=\"http://www.w3.org/2003/05/soap-envelope\" xmlns:wss=\"https://wssba.prismamp.com\" xmlns:ent=\"https://wssba.prismamp.com/entities\" xmlns:a=\"http://www.w3.org/2005/08/addressing\" xmlns:u=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd\" xmlns:o=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd\">                <s:Header>                               <a:Action s:mustUnderstand=\"1\">https://wssba.prismamp.com/INetworkService/AcceptedBenefitsQueryRH</a:Action>                               <a:MessageID>urn:uuid:48aad908-766a-4b61-a582-b44597c86dfe</a:MessageID>                               <a:ReplyTo>                                               <a:Address>http://www.w3.org/2005/08/addressing/anonymous</a:Address>                               </a:ReplyTo>                               <a:To s:mustUnderstand=\"1\" u:Id=\"_1\">https://wssba.prismamp.com/NetworkService/Service.svc</a:To>                               <o:Security s:mustUnderstand=\"1\">                                               <u:Timestamp u:Id=\"_0\">                                                               <u:Created>2017-05-09T13:52:46.046Z</u:Created>                                                               <u:Expires>2017-05-09T13:57:46.046Z</u:Expires>                                               </u:Timestamp>                                               <o:BinarySecurityToken EncodingType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0#Base64Binary\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\" u:Id=\"uuid:6759db2a-059c-4ebb-8d3c-46ddfcdd1571\">MIICFDCCAYGgAwIBAgIQB0A5MI1Tu5FMl4Szb4BgJDAJBgUrDgMCHQUAMCExHzAdBgNVBAMTFlByaXNtYVNiYVRlc3RpbmdSb290Q0EwHhcNMTUwNTIyMTMyMjQ3WhcNMzkxMjMxMjM1OTU5WjAgMR4wHAYDVQQDExV3c3NiYWNlci5wcmlzbWFtcC5jb20wgZ8wDQYJKoZIhvcNAQEBBQADgY0AMIGJAoGBAMKtAVI7eN+ClEO5FByQckYfAUnoLmN3M6sjHGbMz9wx1/hUhto2P9yXarkbJavGH5dlh0xL24C345//qQ72DqNv0jq3FrRWJjrcPtbWgMBuwEDXo+2NeDzr2WbCdHnJSjvRJpZj7F08cKnvGq/qwWR5VFptdT+Y0i2WBuF22TnTAgMBAAGjVjBUMFIGA1UdAQRLMEmAEKPZTKfOJF2t4EXAE7RCbbGhIzAhMR8wHQYDVQQDExZQcmlzbWFTYmFUZXN0aW5nUm9vdENBghBcDUs87GMErEQHfnd+eAOZMAkGBSsOAwIdBQADgYEADzvM2eXf/NJrndDr/TghKC6tdpXNSwQ4WTMpv+sS6BUv1TfGTW+RUiEWpTbEODzb8Q8Ti42HXX/c3czOAVxbbAv2n4oFBCIll+rXbSuKgTTF6SOgNzqJCzd0+0lMysI+MWd0ej1qvLkudq4oRiGJHcJ7iupUx56hkyJugDnAvmY=</o:BinarySecurityToken>                                               <Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\">                                                               <SignedInfo>                                                                               <CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>                                                                               <SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/>                                                                               <Reference URI=\"#_0\">                                                                                              <Transforms>                                                                                                              <Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>                                                                                              </Transforms>                                                                                              <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>                                                                                              <DigestValue>z0kQnIfxcfIlBL1Ga0W7BwBDdGE=</DigestValue>                                                                              </Reference>                                                                               <Reference URI=\"#_1\">                                                                                              <Transforms>                                                                                                              <Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/>                                                                                              </Transforms>                                                                                              <DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/>                                                                                              <DigestValue>8mVINgpquZachbFLFkUuAKHBkN8=</DigestValue>                                                                               </Reference>                                                               </SignedInfo>                                               <SignatureValue>Xxl88I1pU0nCbW4+5UbeAfGMZnpLzykUdET8rfIO5D8ja0xcYoeinZtnxPKqjAWgGjpF/71wDYlUsd6GB3safqJ8KYgN363iVXK5OWxKRUlqFBS7sFUNrXG700JkHzDETEcvUJfc0G2FRti2Q6/yBLXNcFRMXRJSJP5YF6mbAbY=</SignatureValue>                                                               <KeyInfo>                                                                               <o:SecurityTokenReference>                                                                                              <o:Reference URI=\"#uuid:6759db2a-059c-4ebb-8d3c-46ddfcdd1571\" ValueType=\"http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3\"/>                                                                               </o:SecurityTokenReference>                                                               </KeyInfo>                                               </Signature>                               </o:Security>                </s:Header>                <s:Body>                               <wss:AcceptedBenefitsQueryRH>                                               <wss:request xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">                                                               <ent:Document>                                                                               <ent:DocumentNumber>6</ent:DocumentNumber>                                                                               <ent:Nationality>7</ent:Nationality>                                                                               <ent:TypeId>8</ent:TypeId>                                                               </ent:Document>                                                               <ent:Request>                                                                               <ent:Entity>2</ent:Entity>                                                                               <ent:Metadata>                                                                                              <ent:MetadataDto>                                                                                                              <ent:Name>3</ent:Name>                                                                                                              <ent:Value>4</ent:Value>                                                                                              </ent:MetadataDto>                                                                               </ent:Metadata>                                                                               <ent:Terminal>5</ent:Terminal>                                                               </ent:Request>                                                               <ent:NroBeneficio>1</ent:NroBeneficio>                                               </wss:request>                               </wss:AcceptedBenefitsQueryRH>                </s:Body></s:Envelope>";

		SOAPMessage soapResponse = createSOAPRequest(xml, "https://wssba.prismamp.com/INetworkService/AcceptedBenefitsQueryRHResponse");
		String responseString = createSOAPResponseString(soapResponse);
		
		System.out.println(responseString);
	}

	/**
	 * Transforma la respuesta soap en un String
	 */
	private static String createSOAPResponseString(SOAPMessage soapResponse) throws Exception {
		TransformerFactory transformerFactory = TransformerFactory.newInstance();
		Transformer transformer = transformerFactory.newTransformer();
		Source sourceContent = soapResponse.getSOAPPart().getContent();
		ByteArrayOutputStream os = new ByteArrayOutputStream();
		StreamResult result = new StreamResult(os);
		transformer.transform(sourceContent, result);
		return os.toString();
	}

	/**
	 * Crea el mensaje soap para enviarlo al proveedor
	 * 
	 * @param soap_request
	 * @param action
	 * @return
	 * @throws Exception
	 */
	private static SOAPMessage createSOAPRequest(String soap_request, String action) throws Exception {
		byte[] reqBytes = soap_request.getBytes("UTF-8");
		reqBytes = new String(reqBytes, "ISO8859-1").getBytes("ISO-8859-1");
		ByteArrayInputStream bis = new ByteArrayInputStream(reqBytes);
		StreamSource streamSource = new StreamSource(bis);
		MessageFactory messageFactory = MessageFactory.newInstance();
		SOAPMessage soapMessage = messageFactory.createMessage();
		SOAPPart soapPart = soapMessage.getSOAPPart();
		soapPart.setContent(streamSource);
		MimeHeaders headers = soapMessage.getMimeHeaders();
		headers.setHeader("SOAPAction", action);
		soapMessage.saveChanges();
		return soapMessage;
	}

}
