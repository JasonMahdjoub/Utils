package com.distrimind.util.crypto;

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretString;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedEncryptedSymmetricSecretKeyString extends WrappedSecretString {
	public static final int MAX_CHARS_NUMBER= WrappedEncryptedSymmetricSecretKey.MAX_SIZE_IN_BYTES_OF_KEY*4/3;
	protected WrappedEncryptedSymmetricSecretKeyString() {
	}

	public WrappedEncryptedSymmetricSecretKeyString(char[] secretData) {
		super(secretData);
		if (secretData.length>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedSymmetricSecretKeyString(String secretData) {
		super(secretData);
		if (secretData.length()>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedSymmetricSecretKeyString(WrappedEncryptedSymmetricSecretKeyString secretDataString) {
		super(secretDataString);
	}

	public WrappedEncryptedSymmetricSecretKeyString(WrappedEncryptedSymmetricSecretKey secretData) {
		super(secretData);
	}


	@Override
	public WrappedEncryptedSymmetricSecretKey toWrappedData() throws InvalidEncodedValue {
		return new WrappedEncryptedSymmetricSecretKey(this);
	}
}
