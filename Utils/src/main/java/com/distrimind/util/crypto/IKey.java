package com.distrimind.util.crypto;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.5.0
 */
public interface IKey {
	Object toGnuKey()
			throws InvalidKeySpecException, NoSuchAlgorithmException;

	java.security.Key toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	org.bouncycastle.crypto.Key toBouncyCastleKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

	byte[] encode(boolean includeTimeExpiration);
	void zeroize();

	byte[] getKeyBytes();

	boolean isPostQuantumKey();

}
