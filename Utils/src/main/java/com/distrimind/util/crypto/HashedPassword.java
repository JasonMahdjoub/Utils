package com.distrimind.util.crypto;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public final class HashedPassword extends SecretData {

	protected HashedPassword() {
	}

	public HashedPassword(byte[] hashedPassword) {
		super(hashedPassword);
	}

	public HashedPassword(Password secretData) throws IOException {
		super(secretData);
	}

	public HashedPassword(HashedPassword hashedPassword) {
		super(hashedPassword);
	}
}
