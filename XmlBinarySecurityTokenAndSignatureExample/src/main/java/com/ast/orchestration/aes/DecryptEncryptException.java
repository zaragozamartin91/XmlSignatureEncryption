package com.ast.orchestration.aes;

public class DecryptEncryptException extends Exception {

	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	String message;

	public DecryptEncryptException() {
		super();
	}

	public DecryptEncryptException(String message) {
		super(message);
		this.message = message;
	}

	public String getMessage() {
		return message;
	}

	public void setMessage(String message) {
		this.message = message;
	}

}
