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
public class WrappedEncryptedSymmetricSecretKey extends WrappedSecretData implements SecureExternalizable {
	static final int MAX_SIZE_IN_BYTES_OF_KEY=SymmetricSecretKey.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_KEY_FOR_SIGNATURE *1024;
	public static final int MAX_SIZE_IN_BYTES_OF_DATA=MAX_SIZE_IN_BYTES_OF_KEY+7;
	protected WrappedEncryptedSymmetricSecretKey() {
	}

	public WrappedEncryptedSymmetricSecretKey(byte[] secretData) {
		super(secretData);
		if (getBytes().length>MAX_SIZE_IN_BYTES_OF_KEY)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedSymmetricSecretKey(WrappedEncryptedSymmetricSecretKeyString secretData) throws IOException {
		super(secretData);
	}

	public WrappedEncryptedSymmetricSecretKey(WrappedEncryptedSymmetricSecretKey secretData) {
		super(secretData);
	}

	@Override
	public final int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(getBytes(), MAX_SIZE_IN_BYTES_OF_KEY);
	}

	@Override
	public final void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeBytesArray(getBytes(), false, MAX_SIZE_IN_BYTES_OF_KEY);
	}

	@Override
	public final void readExternal(SecuredObjectInputStream in) throws IOException {
		setData(in.readBytesArray(false, MAX_SIZE_IN_BYTES_OF_KEY));
	}


}
