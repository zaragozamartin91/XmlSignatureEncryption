package ast.ws.security.caller.soap;

import java.io.File;
import java.io.StringReader;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.w3c.dom.Document;
import org.xml.sax.InputSource;

/**
 * Constructor de documentos Soap.
 * 
 * @author martin.zaragoza
 *
 */
public class SoapDocumentBuilder {
	private SoapDocumentBuilder() {
	}

	public Document fromFilePath(String filePath) {
		File xmlFile = new File(filePath);
		return this.fromFile(xmlFile);
	}

	public Document fromFile(File fXmlFile) {
		DocumentBuilderFactory dbFactory = DocumentBuilderFactory.newInstance();
		dbFactory.setNamespaceAware(true);
		try {
			DocumentBuilder dBuilder = dbFactory.newDocumentBuilder();
			return dBuilder.parse(fXmlFile);
		} catch (Exception e) {
			throw new SoapDocumentBuilderException(e);
		}
	}

	public Document fromString(String xmlString) {
		DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
		factory.setNamespaceAware(true);
		DocumentBuilder builder;
		try {
			builder = factory.newDocumentBuilder();
			Document document = builder.parse(new InputSource(new StringReader(xmlString)));
			return document;
		} catch (Exception e) {
			throw new SoapDocumentBuilderException(e);
		}
	}

	public static SoapDocumentBuilder build() {
		return new SoapDocumentBuilder();
	}
}
