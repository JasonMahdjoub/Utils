package com.distrimind.util.crypto;

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretString;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedEncryptedASymmetricPrivateKeyString extends WrappedSecretString {
	public static final int MAX_CHARS_NUMBER= WrappedEncryptedASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_KEY*4/3;
	public WrappedEncryptedASymmetricPrivateKeyString() {
	}

	public WrappedEncryptedASymmetricPrivateKeyString(char[] secretData) {
		super(secretData);
		if (secretData.length>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedASymmetricPrivateKeyString(String secretData) {
		super(secretData);
		if (secretData.length()>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedASymmetricPrivateKeyString(WrappedEncryptedASymmetricPrivateKeyString secretDataString) {
		super(secretDataString);
	}

	public WrappedEncryptedASymmetricPrivateKeyString(WrappedEncryptedASymmetricPrivateKey secretData) {
		super(secretData);
	}

	@Override
	public WrappedEncryptedASymmetricPrivateKey toWrappedData() throws InvalidEncodedValue {
		return new WrappedEncryptedASymmetricPrivateKey(this);
	}
}
