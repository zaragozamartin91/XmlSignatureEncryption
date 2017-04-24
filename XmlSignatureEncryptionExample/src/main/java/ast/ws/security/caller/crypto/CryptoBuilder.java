package ast.ws.security.caller.crypto;

import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;

/**
 * Construye instancias de crypto.
 * 
 * @author martin.zaragoza
 *
 */
public class CryptoBuilder {
	/**
	 * Obtiene una instancia de crypto a partir de un archivo .properties que se encuentre en Classpath.
	 * 
	 * @param propertiesFileName - Nombre de archivo de propiedades.
	 * @return instancia de crypto a partir de un archivo .properties que se encuentre en Classpath.
	 */
	public Crypto fromProperties(String propertiesFileName) {
		try {
			return CryptoFactory.getInstance(propertiesFileName);
		} catch (WSSecurityException e) {
			throw new CryptoBuilderException(e);
		}
	}

	/**
	 * Obtiene una instancia de crypto a partir del archivo 'crypto.properties' en classpath.
	 * 
	 * @return instancia de crypto a partir del archivo 'crypto.properties' en classpath.
	 */
	public Crypto fromDefaultConfig() {
		try {
			return CryptoFactory.getInstance();
		} catch (WSSecurityException e) {
			throw new CryptoBuilderException(e);
		}
	}

	private CryptoBuilder() {
		super();
	}

	public static CryptoBuilder build() {
		return new CryptoBuilder();
	}
}
