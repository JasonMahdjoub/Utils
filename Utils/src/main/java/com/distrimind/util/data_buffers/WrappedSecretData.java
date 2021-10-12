package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.crypto.Zeroizable;

import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class WrappedSecretData extends WrappedData implements Zeroizable {

	private transient boolean toZeroize;


	protected WrappedSecretData()
	{
		super();
		toZeroize=false;
	}
	public WrappedSecretData(WrappedString secretData) throws InvalidEncodedValue {
		super();
		setData(Bits.toBytesArrayFromBase64String(secretData.toString(), true));
	}


	public WrappedSecretData(byte[] secretData) {
		super(secretData);
		toZeroize=true;

	}

	public WrappedSecretData(WrappedData wrappedSecretData) {
		super(wrappedSecretData.getBytes().clone());
	}

	protected void setData(byte[] data)
	{
		zeroize();
		toZeroize=true;
		super.setData(data);
	}

	@Override
	public void zeroize()
	{
		if (toZeroize) {
			Arrays.fill(getBytes(), (byte) 0);
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
	public WrappedSecretString toWrappedString()
	{
		return new WrappedSecretString(this);
	}

	@Override
	public WrappedSecretData transformToSecretData() {
		return this;
	}
}
