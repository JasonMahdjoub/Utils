package com.distrimind.util.crypto;

import com.distrimind.util.data_buffers.WrappedSecretData;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since MaDKitLanEdition 4.5.0
 */
public interface IASymmetricPrivateKey extends IKey, ISecretDecentralizedValue {
	int MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE=HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE;
	int MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE=HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE;
	int MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_FOR_SIGNATURE=HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_SIGNATURE;

	int MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_WITH_RSA_FOR_ENCRYPTION=HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_ENCRYPTION;
	int MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_FOR_ENCRYPTION=HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;

	int MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY=HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY;

	boolean useEncryptionAlgorithm();

	boolean useAuthenticatedSignatureAlgorithm();

	ASymmetricPrivateKey getNonPQCPrivateKey();

	@Override
	WrappedSecretData encode();

	@Override
	WrappedSecretData getKeyBytes();

}
