package com.distrimind.util.crypto;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class WrappedASymmetricSecretKey extends SecretData{
	protected WrappedASymmetricSecretKey() {
	}

	public WrappedASymmetricSecretKey(byte[] hashedPassword) {
		super(hashedPassword);
	}

	public WrappedASymmetricSecretKey(SecretDataString secretData) throws IOException {
		super(secretData);
	}

	public WrappedASymmetricSecretKey(WrappedASymmetricSecretKey secretData) {
		super(secretData);
	}
}
