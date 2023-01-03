package com.distrimind.util.crypto;

import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretString;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedHashedPasswordString extends WrappedSecretString {
	public static final int MAX_CHARS_NUMBER=WrappedHashedPassword.MAX_SIZE_IN_BYTES_OF_DATA*4/3+7;
	protected WrappedHashedPasswordString() {
	}

	public WrappedHashedPasswordString(char[] secretData) {
		super(secretData);
		if (secretData.length>MAX_CHARS_NUMBER)
			throw new NullPointerException();
	}

	@Deprecated
	public WrappedHashedPasswordString(String secretData) {
		super(secretData);
		if (secretData.length()>MAX_CHARS_NUMBER)
			throw new NullPointerException();
	}
	public WrappedHashedPasswordString(StringBuilder secretData) {
		super(secretData);
		if (secretData.length()>MAX_CHARS_NUMBER)
			throw new NullPointerException();
	}

	public WrappedHashedPasswordString(WrappedHashedPasswordString wrappedSecretString) {
		super(wrappedSecretString);
	}

	public WrappedHashedPasswordString(WrappedHashedPassword wrappedSecretData) {
		super(wrappedSecretData);
	}

	@Override
	public WrappedHashedPassword toWrappedData() throws InvalidEncodedValue {
		return new WrappedHashedPassword(this);
	}
}
