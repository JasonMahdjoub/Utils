package com.distrimind.util.crypto;

import com.distrimind.util.data_buffers.WrappedData;

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
	int TIME_COMPARISON_TOLERANCE_IN_MS=4*60*60*1000;

	/*ASymmetricEncryptionType getEncryptionAlgorithmType() ;

	ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() ;*/

	long getPublicKeyValidityBeginDateUTC();

	long getTimeExpirationUTC() ;
	WrappedData encode(boolean includeTimes);



	ASymmetricPublicKey getNonPQCPublicKey();

	default boolean areTimesValid()
	{
		long curTime=System.currentTimeMillis();
		return getPublicKeyValidityBeginDateUTC()-TIME_COMPARISON_TOLERANCE_IN_MS<=curTime && getTimeExpirationUTC()>=curTime;
	}

}
