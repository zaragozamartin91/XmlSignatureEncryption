package ast.ws.security.caller.injector.header;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.message.WSSecHeader;
import org.w3c.dom.Document;

public class SecurityHeaderInjector {
	private WSSecHeader secHeader;

	public SecurityHeaderInjector() {
		this(null, true);
	}

	/**
	 * Constructor.
	 * 
	 * @param actor
	 *            The actor name of the wsse:Security header
	 * @param mustUnderstand
	 *            Set mustUnderstand to true or false
	 */
	public SecurityHeaderInjector(String actor, boolean mustUnderstand) {
		secHeader = new WSSecHeader(actor, mustUnderstand);
	}

	/**
	 * Retorna el objeto encabezado inyectado.
	 * 
	 * @return objeto encabezado inyectado.
	 */
	public WSSecHeader getSecHeader() {
		return secHeader;
	}

	/**
	 * @param actor
	 *            The actor name of the wsse:Security header
	 * @param mustUnderstand
	 *            Set mustUnderstand to true or false
	 * 
	 * */
	public static SecurityHeaderInjector inject(String actor, boolean mustUnderstand) {
		return new SecurityHeaderInjector(actor, mustUnderstand);
	}

	/**
	 * Inyecta el encabezado de securidad en un documento.
	 * 
	 * @param doc
	 *            - Documento a inyectar el encabezado.
	 * @return this.
	 */
	public SecurityHeaderInjector into(Document doc) {
		try {
			secHeader.insertSecurityHeader(doc);
			return this;
		} catch (WSSecurityException e) {
			throw new SecurityHeaderInjectorException(e);
		}
	}
}
