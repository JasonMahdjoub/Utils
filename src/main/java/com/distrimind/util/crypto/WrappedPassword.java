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
public final class WrappedPassword extends WrappedSecretString implements SecureExternalizable {
	public static final int MAX_CHARS_NUMBER=1000;
	@SuppressWarnings("unused")
	WrappedPassword() {
	}

	public WrappedPassword(char[] password) {
		super(password);
		if (password.length>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedPassword(String password) {
		super(password);
		if (password.length()>MAX_CHARS_NUMBER)
			throw new IllegalArgumentException();
	}

	public WrappedPassword(WrappedPassword password) {
		super(password);
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
