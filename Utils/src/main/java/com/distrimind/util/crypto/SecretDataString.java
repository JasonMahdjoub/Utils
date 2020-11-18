package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import com.distrimind.util.io.SecureExternalizable;
import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import com.distrimind.util.io.SerializationTools;

import java.io.IOException;
import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class SecretDataString implements Zeroizable, SecureExternalizable {
	public static final int MAX_DATA_LENGTH =2000;

	private char[] chars;

	protected SecretDataString()
	{
		chars=null;
	}
	public SecretDataString(char[] secretData) {
		if (secretData==null)
			throw new NullPointerException();
		if( secretData.length>MAX_DATA_LENGTH)
			throw new IllegalArgumentException();
		this.chars =secretData;

	}
	public SecretDataString(String secretData) {
		if (secretData==null)
			throw new NullPointerException();
		if( secretData.length()>MAX_DATA_LENGTH)
			throw new IllegalArgumentException();
		this.chars =secretData.toCharArray();
		zeroizeString(secretData);
	}

	public static void zeroizeString(String secretData)
	{
		try {
			byte[] t=(byte[])valueField.get(secretData);
			Arrays.fill(t, (byte)0);
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}
	}

	public SecretDataString(SecretDataString secretDataString) {

		this.chars =secretDataString.chars.clone();
	}
	public SecretDataString(SecretData secretData) {
		byte[] d= Bits.getByteArrayWithCheckSum(secretData.getBytes());
		String s=Base64.getUrlEncoder().encodeToString(d);
		if( s.length()>MAX_DATA_LENGTH)
			throw new IllegalArgumentException();
		this.chars=s.toCharArray();
		Arrays.fill(d, (byte)0);
		zeroizeString(s);

	}

	public char[] getChars()
	{
		return chars;
	}

	@Override
	public void zeroize()
	{
		Arrays.fill(chars, '0');
	}
	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		zeroize();
	}
	private static final Field valueField;
	static
	{
		Field f=null;
		try {
			final Field f2=String.class.getDeclaredField("value");
			AccessController.doPrivileged((PrivilegedAction<Object>) () -> {
				f2.setAccessible(true);
				return null;
			});
			f=f2;

		} catch (NoSuchFieldException e) {
			e.printStackTrace();
		}
		valueField=f;
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(chars, MAX_DATA_LENGTH);
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeChars(chars, false, MAX_DATA_LENGTH);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		chars=in.readChars(false, MAX_DATA_LENGTH);
	}
}
