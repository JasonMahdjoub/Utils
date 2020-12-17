package com.distrimind.util.crypto;

import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.io.SecureExternalizable;
import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import com.distrimind.util.io.SerializationTools;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public final class WrappedHashedPassword extends WrappedSecretData implements SecureExternalizable {
	private final static int MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD= MessageDigestType.MAX_HASH_LENGTH;
	public final static int MAX_SIZE_IN_BYTES_OF_DATA= MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD+10;
	protected WrappedHashedPassword() {
	}

	public WrappedHashedPassword(byte[] hashedPassword) {
		super(hashedPassword);
	}


	public WrappedHashedPassword(WrappedHashedPassword hashedPassword) {
		super(hashedPassword);
	}

	@Override
	public final int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(getBytes(), MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD);
	}

	@Override
	public final void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeBytesArray(getBytes(), false, MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD);
	}

	@Override
	public final void readExternal(SecuredObjectInputStream in) throws IOException {
		setData(in.readBytesArray(false, MAX_SIZE_IN_BYTES_OF_HASHED_PASSWORD));
	}
}
