package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class WrappedSymmetricKeyString extends SecretDataString {
	protected WrappedSymmetricKeyString() {
	}

	public WrappedSymmetricKeyString(char[] secretData) {
		super(secretData);
	}

	public WrappedSymmetricKeyString(String secretData) {
		super(secretData);
	}

	public WrappedSymmetricKeyString(WrappedSymmetricKeyString secretDataString) {
		super(secretDataString);
	}

	public WrappedSymmetricKeyString(WrappedSymmetricKey secretData) {
		super(secretData);
	}
}
