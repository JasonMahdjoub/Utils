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
		registerCleaner(finalizer);
	}
	public WrappedSecretData(WrappedString secretData) throws InvalidEncodedValue {
		super();
		registerCleaner(finalizer);
		setData(Bits.toBytesArrayFromBase64String(secretData.toString(), true));
	}


	public WrappedSecretData(byte[] secretData) {
		super(secretData);
		registerCleaner(finalizer);
		finalizer.toZeroize=true;

	}

	public WrappedSecretData(WrappedData wrappedSecretData) {
		super(wrappedSecretData.getBytes().clone());
		registerCleaner(finalizer);
	}

	protected void setData(byte[] data)
	{
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
