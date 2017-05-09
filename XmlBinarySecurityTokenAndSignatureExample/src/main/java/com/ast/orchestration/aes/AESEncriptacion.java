package com.ast.orchestration.aes;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

public class AESEncriptacion {

	private final String ALGORITMO = "AES";// algoritmo (si cambia la
											// imprementacion tambien)
	private final int LONGITUD = 128;// longitud de la llave ()
	private final String CODIFICACION = "UTF-8";// como se convertira a byte,
												// esto sera mas adelante
	private AESKey aesKey;

	public AESEncriptacion(AESKey aesKey) {
		this.aesKey = aesKey;
	}

	public AESKey generaKey() throws DecryptEncryptException{	
		try{
			aesKey = new AESKey();
			aesKey.setEncoded("0123456789abcdef0123456789abcdef");			
		}catch(Exception e){
			throw new DecryptEncryptException(e.getMessage());	
		}
		return aesKey;
	}

	public String encripta(String cadena)  throws DecryptEncryptException{
		String encriptado = null;
		try {
			byte[] raw = StringToHex(aesKey.getEncoded());
			SecretKeySpec skeySpec = new SecretKeySpec(raw, ALGORITMO);
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
			byte[] encrypted = cipher.doFinal(cadena.getBytes(CODIFICACION));
			encriptado = HexToString(encrypted);

		} catch (Exception e) {
			throw new DecryptEncryptException(e.getMessage());	
		} 
		return encriptado;
	}

	private String HexToString(byte[] arregloEncriptado) throws DecryptEncryptException{
		String textoEncriptado = "";	
		try{
			for (int i = 0; i < arregloEncriptado.length; i++) {
				int aux = arregloEncriptado[i] & 0xff;
				if (aux < 16) {
					textoEncriptado = textoEncriptado.concat("0");
				}
				textoEncriptado = textoEncriptado.concat(Integer.toHexString(aux));
			}
		}catch(Exception e){	
			throw new DecryptEncryptException(e.getMessage());
		}	
		return textoEncriptado;
	}

	private byte[] StringToHex(String encriptado) throws DecryptEncryptException{
		byte[] enBytes = null;
		try{
			enBytes = new byte[encriptado.length() / 2];
			for (int i = 0; i < enBytes.length; i++) {
				int index = i * 2;
				String aux = encriptado.substring(index, index + 2);
				int v = Integer.parseInt(aux, 16);
				enBytes[i] = (byte) v;
			}	
		}catch(Exception e){
			throw new DecryptEncryptException(e.getMessage());
		}
		return enBytes;
	}

	public String desencriptar(String encriptado) throws DecryptEncryptException{
		String originalString = null;
		try {
			byte[] raw = StringToHex(aesKey.getEncoded());
			SecretKeySpec skeySpec = new SecretKeySpec(raw, ALGORITMO);
			Cipher cipher = Cipher.getInstance(ALGORITMO);
			cipher.init(Cipher.DECRYPT_MODE, skeySpec);
			byte[] original = cipher.doFinal(StringToHex(encriptado));
			originalString = new String(original);

		} catch (Exception e) {
			throw new DecryptEncryptException(e.getMessage());			
		} 
		return originalString;
	}
}