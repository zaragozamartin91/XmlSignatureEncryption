package ast.ws.security.decoder.callback;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.ws.security.WSPasswordCallback;

public class DummyCallbackHandlerFactory {
	private final Map<String, String> passwords = new HashMap<String, String>();

	public DummyCallbackHandlerFactory() {
	}
	
	public static DummyCallbackHandlerFactory newInstance(){
		return new DummyCallbackHandlerFactory();
	}

	public DummyCallbackHandlerFactory addKeyPassPair(String key, String password) {
		passwords.put(key, password);
		return this;
	}

	public CallbackHandler getNewHandler() {
		return new CallbackHandler() {
			public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
				for (int i = 0; i < callbacks.length; i++) {
					WSPasswordCallback pc = (WSPasswordCallback) callbacks[i];

					String pass = passwords.get(pc.getIdentifier());
					if (pass != null) {
						pc.setPassword(pass);
						return;
					}
				}
			}
		};
	}// newHandler
}
