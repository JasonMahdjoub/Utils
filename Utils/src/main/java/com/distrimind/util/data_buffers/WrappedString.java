package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;
import com.distrimind.util.InvalidEncodedValue;

import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 1.1
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
	protected WrappedString(WrappedData wrappedSecretData, boolean zeroiseIntermediateArrays) {
		this.string= Bits.toBase64String(wrappedSecretData.getBytes(), zeroiseIntermediateArrays);
		this.chars=this.string.toCharArray();
	}
	public WrappedString(WrappedData wrappedSecretData) {
		this(wrappedSecretData,false);
	}

	public static void zeroizeString(String secretData)
	{
		/*try {
			byte[] t=(byte[])valueField.get(secretData);
			Arrays.fill(t, (byte)0);
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}*/
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

	public WrappedData toWrappedData() throws InvalidEncodedValue {
		return new WrappedData(this);
	}
	/*private static final Field valueField;
	static
	{
		Field f=null;
		try {
			final Field f2=String.class.getDeclaredField("value");
			f2.setAccessible(true);
			f=f2;

		} catch (NoSuchFieldException e) {
			e.printStackTrace();
		}
		valueField=f;
	}*/

}
