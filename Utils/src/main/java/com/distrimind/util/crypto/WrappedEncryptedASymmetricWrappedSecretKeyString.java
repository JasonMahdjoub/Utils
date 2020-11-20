package com.distrimind.util.crypto;

import com.distrimind.util.data_buffers.WrappedSecretString;
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
public class WrappedEncryptedASymmetricWrappedSecretKeyString extends WrappedSecretString implements SecureExternalizable {
	private static final int MAX_CHARS_NUMBER= WrappedEncryptedASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_KEY*4/3;
	public WrappedEncryptedASymmetricWrappedSecretKeyString() {
	}

	public WrappedEncryptedASymmetricWrappedSecretKeyString(char[] secretData) {
		super(secretData);
		if (secretData.length>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedASymmetricWrappedSecretKeyString(String secretData) {
		super(secretData);
		if (secretData.length()>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedEncryptedASymmetricWrappedSecretKeyString(WrappedEncryptedASymmetricWrappedSecretKeyString secretDataString) {
		super(secretDataString);
	}

	public WrappedEncryptedASymmetricWrappedSecretKeyString(WrappedEncryptedASymmetricPrivateKey secretData) {
		super(secretData);
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(getChars(), MAX_CHARS_NUMBER);
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeChars(getChars(), false, MAX_CHARS_NUMBER);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		setChars(in.readChars(false, MAX_CHARS_NUMBER));
	}
}
