package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since MaDKitLanEdition 4.5.0
 */
public interface IASymmetricPublicKey extends IKey {
	/*ASymmetricEncryptionType getEncryptionAlgorithmType() ;

	ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() ;*/

	long getTimeExpirationUTC() ;
	byte[] encode(boolean includeTimeExpiration);



	ASymmetricPublicKey getNonPQCPublicKey();

}
