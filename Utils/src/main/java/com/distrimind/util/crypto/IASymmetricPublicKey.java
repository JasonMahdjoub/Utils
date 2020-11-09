package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since MaDKitLanEdition 4.5.0
 */
public interface IASymmetricPublicKey extends IKey {
	int MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE;
	int MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE;
	int MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY_FOR_SIGNATURE=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;

	int MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION;
	int MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY_FOR_ENCRYPTION=HybridASymmetricPublicKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;

	int MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY=MAX_SIZE_IN_BYTES_OF_PUBLIC_KEY_FOR_ENCRYPTION;

	/*ASymmetricEncryptionType getEncryptionAlgorithmType() ;

	ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() ;*/

	long getTimeExpirationUTC() ;
	byte[] encode(boolean includeTimeExpiration);



	ASymmetricPublicKey getNonPQCPublicKey();

}
