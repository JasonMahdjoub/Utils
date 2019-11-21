package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since MaDKitLanEdition 4.5.0
 */
public interface IASymmetricPrivateKey extends IKey {
	boolean useEncryptionAlgorithm();

	boolean useAuthenticatedSignatureAlgorithm();

	ASymmetricPrivateKey getNonPQCPrivateKey();



	/*ASymmetricEncryptionType getEncryptionAlgorithmType() ;

	ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() ;*/
}
