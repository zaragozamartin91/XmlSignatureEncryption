package com.ast.orchestration.aes;

public class EncryptionUtils {
	public static String desencriptadorAES(String claveEncriptada) throws DecryptEncryptException {
		String desencriptado = "";
		try {
			AESKey aesKey = new AESKey();
			AESEncriptacion tmp = new AESEncriptacion(aesKey);
			aesKey = tmp.generaKey();
			AESEncriptacion ejemplo = new AESEncriptacion(aesKey);

			desencriptado = ejemplo.desencriptar(claveEncriptada);

		} catch (Exception e) {
			throw new DecryptEncryptException(e.getMessage());
		}
		return desencriptado;
	}

	// TODO : NO SE USA
	public static String encriptadorAES(String clave_a_encriptar) throws DecryptEncryptException {
		String encriptado = "";
		try {
			AESKey aesKey = new AESKey();

			AESEncriptacion tmp = new AESEncriptacion(aesKey);
			aesKey = tmp.generaKey();
			AESEncriptacion ejemplo = new AESEncriptacion(aesKey);

			encriptado = ejemplo.encripta(clave_a_encriptar);

		} catch (Exception e) {
			throw new DecryptEncryptException(e.getMessage());
		}
		return encriptado;
	}

}
