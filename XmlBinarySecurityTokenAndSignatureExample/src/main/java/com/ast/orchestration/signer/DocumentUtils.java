package com.ast.orchestration.signer;

import java.io.IOException;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.soap.SOAPException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactoryConfigurationError;

import org.w3c.dom.Document;
import org.w3c.dom.Node;
import org.xml.sax.InputSource;
import org.xml.sax.SAXException;


public class DocumentUtils {
	public static Document createDocument(String xmlString) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder;
		builder = factory.newDocumentBuilder();
		Document document = builder.parse(new InputSource(new StringReader(xmlString)));
		return document;
	}

	public static String documentToString(Document doc) throws TransformerException {
		javax.xml.transform.dom.DOMSource domSource = new javax.xml.transform.dom.DOMSource(doc);
		java.io.StringWriter writer = new java.io.StringWriter();
		javax.xml.transform.stream.StreamResult result = new javax.xml.transform.stream.StreamResult(writer);
		javax.xml.transform.TransformerFactory tf = javax.xml.transform.TransformerFactory.newInstance();

		javax.xml.transform.Transformer transformer = tf.newTransformer();
		transformer.transform(domSource, result);

		return writer.toString();
	}

	public static String nodeToString(Node node) throws TransformerFactoryConfigurationError, TransformerException {
		java.io.StringWriter sw = new java.io.StringWriter();
		javax.xml.transform.Transformer t = javax.xml.transform.TransformerFactory.newInstance().newTransformer();
		t.setOutputProperty(javax.xml.transform.OutputKeys.OMIT_XML_DECLARATION, "yes");
		t.setOutputProperty(javax.xml.transform.OutputKeys.INDENT, "yes");
		t.transform(new javax.xml.transform.dom.DOMSource(node), new javax.xml.transform.stream.StreamResult(sw));
		return sw.toString();
	}

	public static String soapMessageToString(javax.xml.soap.SOAPMessage soapMessage) throws SOAPException, IOException {
		java.io.ByteArrayOutputStream stream = new java.io.ByteArrayOutputStream();
		String message = null;
		soapMessage.writeTo(stream);
		message = new String(stream.toByteArray(), "utf-8");

		return message;
	}

	/**
	 * Obtiene el valor de un atributo dentro de un documento.
	 * 
	 * @param document
	 *            - Documento a analizar.
	 * @param nodeName
	 *            - Nombre (local) de nodo a buscar.
	 * @param attributeName
	 *            - Nombre de atributo.
	 * @param namespace
	 *            - URI de namespace al cual el nodo pertenece. Null si se desea buscar en todos los namespaces.
	 * @param nodeIndex
	 *            - Indice de nodo a buscar el atributo.
	 * @return Valor del atributo.
	 */
	public static String getAttributeValue(Document document, String nodeName, String attributeName, String namespace, int nodeIndex) {
		namespace = namespace == null ? "*" : namespace;
		org.w3c.dom.NodeList nodeList = document.getElementsByTagNameNS(namespace, nodeName);

		Node attribute = nodeList.item(nodeIndex).getAttributes().getNamedItem(attributeName);
		return attribute.getNodeValue();
	}

	/**
	 * Obtiene el valor de un atributo dentro de un documento o retorna un valor por defecto en caso de no encontrarlo.
	 * 
	 * @param document
	 *            - Documento a analizar.
	 * @param nodeName
	 *            - Nombre (local) de nodo a buscar.
	 * @param attributeName
	 *            - Nombre de atributo.
	 * @param namespace
	 *            - URI de namespace al cual el nodo pertenece. Null si se desea buscar en todos los namespaces.
	 * @param nodeIndex
	 *            - Indice de nodo a buscar el atributo.
	 * @param defaultValue
	 *            - Valor por defecto a retornar en caso de no encontrar el atributo.
	 * @return Valor del atributo.
	 */
	public static String getAttributeValue(Document document, String nodeName, String attributeName, String namespace, int nodeIndex, String defaultValue) {
		try {
			String value = getAttributeValue(document, nodeName, attributeName, namespace, nodeIndex);
			return value == null || value.equals("") ? defaultValue : value;
		} catch (Exception e) {
			return defaultValue;
		}
	}

	public static String setAttributeValue(Document document, String nodeName, String attributeName, String namespace, int nodeIndex, String value) {
		namespace = namespace == null ? "*" : namespace;
		org.w3c.dom.NodeList nodeList = document.getElementsByTagNameNS(namespace, nodeName);

		Node attribute = nodeList.item(nodeIndex).getAttributes().getNamedItem(attributeName);
		attribute.setTextContent(value);
		return attribute.getNodeValue();
	}

}
