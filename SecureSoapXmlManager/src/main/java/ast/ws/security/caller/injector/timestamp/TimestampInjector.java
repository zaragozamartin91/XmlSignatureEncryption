package ast.ws.security.caller.injector.timestamp;

import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WsuIdAllocator;
import org.apache.ws.security.message.WSSecHeader;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSCurrentTimeSource;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.util.WSTimeSource;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class TimestampInjector {
	private int timeToLive;
	private String timestampPrefix;
	private WsuIdAllocator idAllocator = WSSConfig.DEFAULT_ID_ALLOCATOR;
	public static final String DEFAULT_TIMESTAMP_PREFIX = "TS-";

	/**
	 * Crea un inyectador de timestamps.
	 * 
	 * @param timeToLive
	 *            - Tiempo de vida del timestamp.
	 * @param timestampPrefix
	 *            - Prefijo de id de timestamp. Ej: si el prefijo es 'TS-',
	 *            entonces el id de timestamp sera del estilo
	 *            'wsu:Id="TS-1E3D7275E9FAA5974014568588953231"'
	 */
	public TimestampInjector(int timeToLive, String timestampPrefix) {
		super();
		this.timeToLive = timeToLive;
		this.timestampPrefix = timestampPrefix;
	}

	/**
	 * Crea un inyectador de timestamps.
	 * 
	 * @param timeToLive
	 *            - Tiempo de vida del timestamp.
	 * @param timestampPrefix
	 *            - Prefijo de id de timestamp. Ej: si el prefijo es 'TS-',
	 *            entonces el id de timestamp sera del estilo
	 *            'wsu:Id="TS-1E3D7275E9FAA5974014568588953231"'
	 */
	public static TimestampInjector inject(int timeToLive, String timestampPrefix) {
		return new TimestampInjector(timeToLive, timestampPrefix);
	}

	/**
	 * Crea un inyectador de timestamps con prefijo de id por defecto
	 * {@link TimestampInjector#DEFAULT_TIMESTAMP_PREFIX}.
	 * 
	 * @param timeToLive
	 *            - Tiempo de vida del timestamp.
	 */
	public static TimestampInjector injectWithDefaultPrefix(int timeToLive) {
		return inject(timeToLive, DEFAULT_TIMESTAMP_PREFIX);
	}

	/**
	 * Inserta un timestamp en un documento.
	 * 
	 * @param doc
	 *            - Documento a insertar timestamp.
	 * @param parentElement
	 *            - Elemento padre dentro del documento sobre el cual insertar
	 *            el timestamp (suele ser el encabezado de seguridad).
	 * @return this.
	 */
	public TimestampInjector into(Document doc, Element parentElement) {
		WSTimeSource currentTime = new WSCurrentTimeSource();
		boolean precisionInMilliSeconds = true;

		Timestamp ts = new Timestamp(precisionInMilliSeconds, doc, currentTime, timeToLive);
		String tsId = idAllocator.createId(timestampPrefix, ts);
		ts.setID(tsId);

		// WSSecurityUtil.prependChildElement(secHeader.getSecurityHeader(),
		// ts.getElement());
		WSSecurityUtil.prependChildElement(parentElement, ts.getElement());

		return this;
	}

	/**
	 * Inserta un timestamp en un documento.
	 * 
	 * @param doc
	 *            - Documento a insertar timestamp.
	 * @param secHeader
	 *            - Encabezado de seguridad del documento sobre el cual insertar
	 *            el timestamp.
	 * @return this.
	 */
	public TimestampInjector into(Document doc, WSSecHeader secHeader) {
		return into(doc, secHeader.getSecurityHeader());
	}
}
