package com.distrimind.util.crypto;

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedEncryptedSymmetricSecretKey extends WrappedSecretData {
	public static final int MAX_SIZE_IN_BYTES_OF_KEY=Math.max(SymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE, ASymmetricKeyWrapperType.MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_ASYMMETRIC_HYBRID_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE);
	protected WrappedEncryptedSymmetricSecretKey() {
	}

	public WrappedEncryptedSymmetricSecretKey(byte[] secretData) {
		super(secretData);
		if (getBytes().length>MAX_SIZE_IN_BYTES_OF_KEY)
			throw new IllegalArgumentException(""+getBytes().length);
	}

	public WrappedEncryptedSymmetricSecretKey(WrappedEncryptedSymmetricSecretKeyString secretData) throws InvalidEncodedValue {
		super(secretData);
	}

	public WrappedEncryptedSymmetricSecretKey(WrappedEncryptedSymmetricSecretKey secretData) {
		super(secretData);
	}

	@Override
	public WrappedEncryptedSymmetricSecretKeyString toWrappedString()
	{
		return new WrappedEncryptedSymmetricSecretKeyString(this);
	}
}
