package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;
import com.distrimind.util.ISecretValue;
import com.distrimind.util.InvalidEncodedValue;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 5.10.0
 */
public class WrappedSecretData extends WrappedData implements ISecretValue {




	protected WrappedSecretData()
	{
		super();
		finalizer.toZeroize=false;
		registerCleanerIfNotDone(finalizer);
	}
	public WrappedSecretData(WrappedString secretData) throws InvalidEncodedValue {
		super();
		registerCleanerIfNotDone(finalizer);
		setData(Bits.toBytesArrayFromBase64String(secretData.toStringBuilder(), true, true));
	}


	public WrappedSecretData(byte[] secretData) {
		super(secretData);
		registerCleanerIfNotDone(finalizer);
		finalizer.toZeroize=true;

	}

	public WrappedSecretData(WrappedData wrappedSecretData) {
		super(wrappedSecretData.getBytes().clone());
		registerCleanerIfNotDone(finalizer);
	}

	@Override
	protected void setData(byte[] data) throws InvalidEncodedValue {
		finalizer.performCleanup();
		finalizer.toZeroize=true;
		super.setData(data);
	}
	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WrappedData that = (WrappedData) o;
		return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(getBytes(), that.getBytes());
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

	public static boolean constantTimeAreEqual(byte[] expected, byte[] supplied)
	{
		return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(expected, supplied);
	}
}
