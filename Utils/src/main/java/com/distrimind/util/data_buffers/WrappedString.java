package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.10.0
 */
public class WrappedString {
	private char[] chars;
	private transient WrappedSecretString secretString=null;
	private String string;


	protected WrappedString()
	{
		chars=null;
	}
	public WrappedString(char[] data) {
		if (data==null)
			throw new NullPointerException();
		this.chars =data;
		this.string=new String(this.chars);

	}
	WrappedString(char[] data, String dataString) {
		if (data==null)
			throw new NullPointerException();
		if (dataString==null)
			throw new NullPointerException();
		this.chars =data;
		this.string=dataString;

	}
	public WrappedString(String secretData) {
		if (secretData==null)
			throw new NullPointerException();
		this.chars =secretData.toCharArray();
		this.string=secretData;
	}
	protected void setChars(char[] chars)
	{
		this.chars=chars;
		this.string=new String(chars);
		this.secretString=null;
	}

	public WrappedString(WrappedString dataString) {

		this.chars =dataString.chars;
		this.string=dataString.string;
	}
	public WrappedString(WrappedData wrappedSecretData) {
		byte[] d= Bits.getByteArrayWithCheckSum(wrappedSecretData.getBytes());
		this.string= Base64.getUrlEncoder().encodeToString(d);
		this.chars=this.string.toCharArray();
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
	@Override
	public String toString()
	{
		return string;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WrappedString that = (WrappedString) o;
		return string.equals(that.string);
	}

	@Override
	public int hashCode() {
		return Objects.hash(string);
	}
	public WrappedSecretString transformToSecretString()
	{
		if (secretString==null)
			secretString=new WrappedSecretString(chars, string);
		return secretString;
	}
	public char[] getChars()
	{
		return chars;
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

}
