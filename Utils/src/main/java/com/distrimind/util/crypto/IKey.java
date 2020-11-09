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
	int MAX_SIZE_IN_BYTES_OF_KEY_FOR_SIGNATURE=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE;
	int MAX_SIZE_IN_BYTES_OF_KEY_FOR_ENCRYPTION=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION;
	int MAX_SIZE_IN_BYTES_OF_KEY=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY;

	Object toGnuKey()
			throws InvalidKeySpecException, NoSuchAlgorithmException, IOException;

	java.security.Key toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException;

	com.distrimind.bcfips.crypto.Key toBouncyCastleKey() throws NoSuchAlgorithmException, InvalidKeySpecException;

	byte[] encode();
	void zeroize();

	byte[] getKeyBytes();

	boolean isPostQuantumKey();

	boolean useEncryptionAlgorithm();

	boolean useAuthenticatedSignatureAlgorithm();


}
