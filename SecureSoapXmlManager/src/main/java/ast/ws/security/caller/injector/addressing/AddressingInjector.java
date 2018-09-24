package ast.ws.security.caller.injector.addressing;

import ast.ws.security.util.DocumentUtils;
import org.apache.ws.security.util.WSSecurityUtil;
import org.opensaml.ws.wsaddressing.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.util.UUID;

/**
 * Inyector de campos Addressing.
 * <p>
 * namespace: http://www.w3.org/2005/08/addressing
 */
public class AddressingInjector {
    public static final String ADDRESSING_NAMESPACE = WSAddressingConstants.WSA_NS;
    public static final String ADDRESSING_PREFIX = WSAddressingConstants.WSA_PREFIX;

    private Document doc;

    private AddressingInjector(Document doc) {
        this.doc = doc;
    }

    /**
     * Crea un inyector de Addressing a partir de un documento.
     *
     * @param doc Documento al cual inyectar campos.
     * @return Nuevo inyector de Addressing.
     */
    public static AddressingInjector fromDocument(Document doc) {
        return new AddressingInjector(doc);
    }

    /**
     * Inyecta wsa:Action a un elemento.
     *
     * @param actionStr     Valor de elemento wsa:Action.
     * @param parentElement Elemento al cual agregar wsa:Action.
     * @return this.
     */
    public AddressingInjector injectAction(String actionStr, Element parentElement) {
        Element action = buildAction(actionStr);
        WSSecurityUtil.prependChildElement(parentElement, action);
        return this;
    }

    /**
     * Inyecta un wsa:MessageID con valor generado aleatoriamente como un random UUID.
     *
     * @param parentElement Elemento al cual agregar el wsa:MessageID.
     * @return this.
     */
    public AddressingInjector injectRandomMessageId(Element parentElement) {
        UUID uuid = UUID.randomUUID();
        return injectMessageId("urn:uuid:" + uuid, parentElement);
    }

    /**
     * Inyecta un wsa:MessageID.
     *
     * @param msgId         Contenido del wsa:MessageID.
     * @param parentElement Elemento al cual agregar el wsa:MessageID.
     * @return this.
     */
    public AddressingInjector injectMessageId(String msgId, Element parentElement) {
        Element messageId = buildMessageId(msgId);
        WSSecurityUtil.prependChildElement(parentElement, messageId);
        return this;
    }

    /**
     * Inyecta un wsa:To.
     *
     * @param value         Contenido del wsa:To.
     * @param parentElement Elemento al cual agregar el wsa:To.
     * @return this.
     */
    public AddressingInjector injectTo(String value, Element parentElement) {
        Element element = buildTo(value);
        WSSecurityUtil.prependChildElement(parentElement, element);
        return this;
    }

    /**
     * Inyecta el elemento complejo: <br/>
     * &lt;wsa:ReplyTo xmlns:wsa="http://www.w3.org/2005/08/addressing" &gt; <br/>
     * &lt;wsa:Address&gt; VALUE &lt;/wsa:Address&gt; <br/>
     * &lt;/wsa:ReplyTo&gt;
     * <p>
     * <strong>Nota: este metodo solo debe llamarse si el elemento padre no contiene un wsa:ReplyTo</strong>
     *
     * @param value         Contenido del wsa:Address.
     * @param parentElement Elemento al cual agregar el wsa:ReplyTo.
     * @return this.
     */
    public AddressingInjector injectReplyToAddress(String value, Element parentElement) {
        Element replyTo = buildReplyTo();
        WSSecurityUtil.prependChildElement(parentElement, replyTo);
        Element address = buildAddress(value);
        WSSecurityUtil.prependChildElement(replyTo, address);
        return this;
    }

    private Element buildAction(String action) {
        Element element = DocumentUtils.createElementNs(doc, ADDRESSING_NAMESPACE, ADDRESSING_PREFIX, Action.ELEMENT_LOCAL_NAME);
        element.setTextContent(action);
        return element;
    }

    private Element buildMessageId(String msgId) {
        Element element = DocumentUtils.createElementNs(doc, ADDRESSING_NAMESPACE, ADDRESSING_PREFIX, MessageID.ELEMENT_LOCAL_NAME);
        element.setTextContent(msgId);
        return element;
    }

    private Element buildTo(String value) {
        Element element = DocumentUtils.createElementNs(doc, ADDRESSING_NAMESPACE, ADDRESSING_PREFIX, To.ELEMENT_LOCAL_NAME);
        element.setTextContent(value);
        return element;
    }

    private Element buildReplyTo() {
        return DocumentUtils.createElementNs(doc, ADDRESSING_NAMESPACE, ADDRESSING_PREFIX, ReplyTo.ELEMENT_LOCAL_NAME);
    }

    private Element buildAddress(String value) {
        Element element = DocumentUtils.createElementNs(doc, ADDRESSING_NAMESPACE, ADDRESSING_PREFIX, Address.ELEMENT_LOCAL_NAME);
        element.setTextContent(value);
        return element;
    }
}
