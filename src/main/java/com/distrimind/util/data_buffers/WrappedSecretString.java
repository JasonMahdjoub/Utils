package com.distrimind.util.data_buffers;

import com.distrimind.util.ISecretValue;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.AutoZeroizable;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedSecretString extends WrappedString implements AutoZeroizable, ISecretValue {


	protected WrappedSecretString()
	{
		super();
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=false;
	}
	public WrappedSecretString(char[] secretData) {
		super(secretData);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;

	}

	WrappedSecretString(char[] data, StringBuilder dataString) {
		super(data, dataString);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;

	}
	@Deprecated
	public WrappedSecretString(String secretData) {
		super(secretData);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;
	}
	public WrappedSecretString(StringBuilder secretData) {
		super(secretData);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;
	}

	@Override
	@Deprecated
	public String toString()
	{
		return super.toString();
	}

	public WrappedSecretString(WrappedString wrappedSecretString) {
		super(wrappedSecretString);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;
	}
	public WrappedSecretString(WrappedData wrappedSecretData) {
		super(wrappedSecretData, true);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;
	}


	protected void setChars(char[] chars) throws InvalidEncodedValue {
		finalizer.performCleanup();
		finalizer.toZeroize=true;
		super.setChars(chars);
	}

	@Override
	public WrappedSecretData toWrappedData() throws InvalidEncodedValue {
		return new WrappedSecretData(this);
	}
	@Override
	public WrappedSecretString transformToSecretString() {
		return this;
	}
	public static boolean constantTimeAreEqual(String expected, String supplied)
	{
		if (expected==null || supplied==null)
			return false;
		//noinspection StringEquality
		if (expected == supplied)
		{
			return true;
		}

		//noinspection ManualMinMaxCalculation
		int len = (expected.length() < supplied.length()) ? expected.length() : supplied.length();

		int nonEqual = expected.length() ^ supplied.length();

		for (int i = 0; i != len; i++)
		{
			nonEqual |= (expected.charAt(i) ^ supplied.charAt(i));
		}
		for (int i = len; i < supplied.length(); i++)
		{
			//noinspection PointlessBitwiseExpression
			nonEqual |= (supplied.charAt(i) ^ ~supplied.charAt(i));
		}

		return nonEqual == 0;
	}
	public static boolean constantTimeAreEqual(char[] expected, char[] supplied)
	{
		if (expected==null || supplied==null)
			return false;
		if (expected == supplied)
		{
			return true;
		}

		//noinspection ManualMinMaxCalculation
		int len = (expected.length < supplied.length) ? expected.length : supplied.length;

		int nonEqual = expected.length ^ supplied.length;

		for (int i = 0; i != len; i++)
		{
			nonEqual |= (expected[i] ^ supplied[i]);
		}
		for (int i = len; i < supplied.length; i++)
		{
			//noinspection PointlessBitwiseExpression
			nonEqual |= (supplied[i] ^ ~supplied[i]);
		}

		return nonEqual == 0;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		return constantTimeAreEqual(getChars(), ((WrappedString) o).getChars());
	}
}
