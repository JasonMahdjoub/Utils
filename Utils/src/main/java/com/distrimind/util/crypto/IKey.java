package com.distrimind.util.crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.5.0
 */
public interface IKey {
	Object toGnuKey()
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException;

	java.security.Key toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	org.bouncycastle.crypto.Key toBouncyCastleKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

	byte[] encode();
	void zeroize();

	byte[] getKeyBytes();

	boolean isPostQuantumKey();

	boolean useEncryptionAlgorithm();

	boolean useAuthenticatedSignatureAlgorithm();


}
