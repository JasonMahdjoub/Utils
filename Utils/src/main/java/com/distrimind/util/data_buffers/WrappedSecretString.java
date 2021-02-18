package com.distrimind.util.data_buffers;

import com.distrimind.util.crypto.Zeroizable;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class WrappedSecretString extends WrappedString implements Zeroizable {
	private transient boolean toZeroize;

	protected WrappedSecretString()
	{
		super();
		toZeroize=false;
	}
	public WrappedSecretString(char[] secretData) {
		super(secretData);
		toZeroize=true;

	}
	WrappedSecretString(char[] data, String dataString) {
		super(data, dataString);
		toZeroize=true;

	}
	public WrappedSecretString(String secretData) {
		super(secretData);
		toZeroize=true;
	}



	public WrappedSecretString(WrappedString wrappedSecretString) {
		super(wrappedSecretString);
		toZeroize=true;
	}
	public WrappedSecretString(WrappedData wrappedSecretData) {
		super(wrappedSecretData, true);
		toZeroize=true;
	}


	protected void setChars(char[] chars)
	{
		zeroize();
		toZeroize=true;
		super.setChars(chars);
	}
	@Override
	public void zeroize()
	{
		if (toZeroize) {
			Arrays.fill(getChars(), '0');
			zeroizeString(toString());
			toZeroize=false;
		}
	}
	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		zeroize();
	}
	@Override
	public WrappedSecretData toWrappedData() throws IOException {
		return new WrappedSecretData(this);
	}
	@Override
	public WrappedSecretString transformToSecretString() {
		return this;
	}
}
