package com.distrimind.util.crypto;

import com.distrimind.util.Bits;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class WrappedSymmetricKey extends SecretData {
	protected WrappedSymmetricKey() {
	}

	public WrappedSymmetricKey(byte[] secretData) {
		super(secretData);
	}

	public WrappedSymmetricKey(WrappedSymmetricKeyString secretData) throws IOException {
		super(secretData);
	}

	public WrappedSymmetricKey(WrappedSymmetricKey secretData) {
		super(secretData);
	}


}
