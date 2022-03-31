package com.distrimind.util.crypto;

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedEncryptedASymmetricPrivateKey extends WrappedSecretData {
	public static final int MAX_SIZE_IN_BYTES_OF_KEY=Math.max(SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE, ASymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE);
	public WrappedEncryptedASymmetricPrivateKey(byte[] data) {
		super(data);
		if (data.length>MAX_SIZE_IN_BYTES_OF_KEY)
			throw new IllegalArgumentException(""+data.length);
	}

	public WrappedEncryptedASymmetricPrivateKey(WrappedEncryptedASymmetricPrivateKey secretData) {
		super(secretData);
	}
	public WrappedEncryptedASymmetricPrivateKey(WrappedEncryptedASymmetricPrivateKeyString secretData) throws InvalidEncodedValue {
		super(secretData);
	}


	@Override
	public WrappedEncryptedASymmetricPrivateKeyString toWrappedString()
	{
		return new WrappedEncryptedASymmetricPrivateKeyString(this);
	}
}
