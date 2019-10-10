package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.5.0
 */
public interface IASymmetricPublicKey extends IKey {
	/*ASymmetricEncryptionType getEncryptionAlgorithmType() ;

	ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() ;*/

	long getTimeExpirationUTC() ;

}
