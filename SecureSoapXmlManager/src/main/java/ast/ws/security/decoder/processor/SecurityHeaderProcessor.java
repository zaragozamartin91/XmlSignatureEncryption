package ast.ws.security.decoder.processor;

import javax.security.auth.callback.CallbackHandler;

import org.apache.ws.security.WSSecurityEngine;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.w3c.dom.Document;

import ast.ws.security.decoder.callback.DummyCallbackHandlerFactory;

public class SecurityHeaderProcessor {
	private String actor;
	private CallbackHandler callbackHandler;
	private Crypto sigCrypto;
	private Crypto encCrypto;
	private WSSecurityEngine engine = new WSSecurityEngine();
	
	public SecurityHeaderProcessor(String actor, CallbackHandler callbackHandler, Crypto sigCrypto, Crypto encCrypto) {
		super();
		this.actor = actor;
		this.callbackHandler = callbackHandler;
		this.sigCrypto = sigCrypto;
		this.encCrypto = encCrypto;
	}
	
	public static SecurityHeaderProcessor prepare(String actor, CallbackHandler callbackHandler, Crypto sigCrypto, Crypto encCrypto){
		return new SecurityHeaderProcessor(actor, callbackHandler, sigCrypto, encCrypto);
	}
	
	public static SecurityHeaderProcessor prepare(String actor, String key,String password , Crypto sigCrypto, Crypto encCrypto){
		CallbackHandler callbackHandler = DummyCallbackHandlerFactory.newInstance().addKeyPassPair(key, password).getNewHandler();
		return new SecurityHeaderProcessor(actor, callbackHandler, sigCrypto, encCrypto);
	}
	
	public void process(Document doc){
		try {
			engine.processSecurityHeader(doc, actor, callbackHandler, sigCrypto,encCrypto);
		} catch (WSSecurityException e) {
			throw new SecurityHeaderProcessorException(e);
		}
	}
}
