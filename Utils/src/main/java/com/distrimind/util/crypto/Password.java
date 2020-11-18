package com.distrimind.util.crypto;

import com.distrimind.util.io.SecureExternalizable;
import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import com.distrimind.util.io.SerializationTools;

import java.io.Externalizable;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public final class Password extends SecretDataString {
	protected Password() {
	}

	public Password(char[] password) {
		super(password);
	}

	public Password(String password) {
		super(password);
	}

	public Password(Password password) {
		super(password);
	}
}
