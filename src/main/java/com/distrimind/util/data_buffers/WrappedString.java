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
		private StringBuilder string;
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
		this.finalizer.string=new StringBuilder();
		this.finalizer.string.append(this.finalizer.chars);
	}

	WrappedString(char[] data, StringBuilder dataString) {
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
		this.finalizer.string=new StringBuilder();
		this.finalizer.string.append(secretData);
	}
	public WrappedString(StringBuilder secretData) {
		if (secretData==null)
			throw new NullPointerException();
		finalizer=new Finalizer();
		this.finalizer.chars=new char[secretData.length()];
		for (int i=0;i<secretData.length();i++)
			this.finalizer.chars[i]=secretData.charAt(i);
		this.finalizer.string=secretData;
	}
	protected void setChars(char[] chars)
	{
		this.finalizer.chars=chars;
		this.finalizer.string=new StringBuilder();
		this.finalizer.string.append(chars);
		this.secretString=null;
	}

	public WrappedString(WrappedString dataString) {
		finalizer=new Finalizer();
		this.finalizer.chars =dataString.finalizer.chars;
		this.finalizer.string=dataString.finalizer.string;
	}
	protected WrappedString(WrappedData wrappedSecretData, boolean zeroiseIntermediateArrays) {
		finalizer=new Finalizer();
		this.finalizer.string= Bits.toBase64String(wrappedSecretData.getBytes(), true, zeroiseIntermediateArrays);
		this.finalizer.chars=new char[this.finalizer.string.length()];
		for (int i=0;i<this.finalizer.string.length();i++)
			this.finalizer.chars[i]=this.finalizer.string.charAt(i);
	}
	public WrappedString(WrappedData wrappedSecretData) {
		this(wrappedSecretData,false);
	}

	public static void zeroizeString(StringBuilder secretData)
	{
		if (secretData!=null) {
			for (int i = 0; i < secretData.length(); i++)
				secretData.setCharAt(i, '0');
		}
	}
	@Override
	public String toString()
	{
		return finalizer.string.toString();
	}

	public StringBuilder toStringBuilder()
	{
		return finalizer.string;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WrappedString that = (WrappedString) o;
		return Arrays.equals(finalizer.chars, that.finalizer.chars);
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

}
