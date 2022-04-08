package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;
import com.distrimind.util.Cleanable;
import com.distrimind.util.InvalidEncodedValue;

import java.util.Arrays;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since MaDKitLanEdition 5.10.0
 */
public class WrappedString {
	protected static class Finalizer extends Cleanable.Cleaner
	{
		private char[] chars;
		private String string;
		protected transient boolean toZeroize;

		protected Finalizer() {
			super(null);
		}

		@Override
		protected void performCleanup() {
			if (toZeroize) {
				Arrays.fill(chars, '0');
				zeroizeString(string);
				toZeroize=false;
			}
		}
	}
	protected final Finalizer finalizer;
	private transient WrappedSecretString secretString=null;



	protected WrappedString()
	{
		finalizer=new Finalizer();
		finalizer.chars=null;
	}
	public WrappedString(char[] data) {
		if (data==null)
			throw new NullPointerException();
		finalizer=new Finalizer();
		this.finalizer.chars =data;
		this.finalizer.string=new String(this.finalizer.chars);

	}
	WrappedString(char[] data, String dataString) {
		if (data==null)
			throw new NullPointerException();
		if (dataString==null)
			throw new NullPointerException();
		finalizer=new Finalizer();
		this.finalizer.chars =data;
		this.finalizer.string=dataString;

	}
	public WrappedString(String secretData) {
		if (secretData==null)
			throw new NullPointerException();
		finalizer=new Finalizer();
		this.finalizer.chars =secretData.toCharArray();
		this.finalizer.string=secretData;
	}
	protected void setChars(char[] chars)
	{
		this.finalizer.chars=chars;
		this.finalizer.string=new String(chars);
		this.secretString=null;
	}

	public WrappedString(WrappedString dataString) {
		finalizer=new Finalizer();
		this.finalizer.chars =dataString.finalizer.chars;
		this.finalizer.string=dataString.finalizer.string;
	}
	protected WrappedString(WrappedData wrappedSecretData, boolean zeroiseIntermediateArrays) {
		finalizer=new Finalizer();
		this.finalizer.string= Bits.toBase64String(wrappedSecretData.getBytes(), zeroiseIntermediateArrays);
		this.finalizer.chars=this.finalizer.string.toCharArray();
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
		return finalizer.string;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WrappedString that = (WrappedString) o;
		return finalizer.string.equals(that.finalizer.string);
	}

	@Override
	public int hashCode() {
		return Objects.hash(finalizer.string);
	}
	public WrappedSecretString transformToSecretString()
	{
		if (secretString==null)
			secretString=new WrappedSecretString(finalizer.chars, finalizer.string);
		return secretString;
	}
	public char[] getChars()
	{
		return finalizer.chars;
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
