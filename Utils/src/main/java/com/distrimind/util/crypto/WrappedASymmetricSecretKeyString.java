package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class WrappedASymmetricSecretKeyString extends SecretDataString{
	public WrappedASymmetricSecretKeyString() {
	}

	public WrappedASymmetricSecretKeyString(char[] secretData) {
		super(secretData);
	}

	public WrappedASymmetricSecretKeyString(String secretData) {
		super(secretData);
	}

	public WrappedASymmetricSecretKeyString(WrappedASymmetricSecretKeyString secretDataString) {
		super(secretDataString);
	}

	public WrappedASymmetricSecretKeyString(WrappedASymmetricSecretKey secretData) {
		super(secretData);
	}
}
