package com.distrimind.util.crypto;

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public final class WrappedHashedPassword extends WrappedSecretData {
	private final static int MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD= MessageDigestType.MAX_HASH_LENGTH_IN_BYTES;
	public final static int MAX_SIZE_IN_BYTES_OF_DATA= MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD+10;
	@SuppressWarnings("ProtectedMemberInFinalClass")
	protected WrappedHashedPassword() {
	}

	public WrappedHashedPassword(byte[] hashedPassword) {
		super(hashedPassword);
	}


	public WrappedHashedPassword(WrappedHashedPassword hashedPassword) {
		super(hashedPassword);
	}
	public WrappedHashedPassword(WrappedHashedPasswordString hashedPassword) throws InvalidEncodedValue {
		super(hashedPassword);
	}

	@Override
	public WrappedHashedPasswordString toWrappedString()
	{
		return new WrappedHashedPasswordString(this);
	}
}
