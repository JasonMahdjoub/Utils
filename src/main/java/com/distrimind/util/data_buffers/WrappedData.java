package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;
import com.distrimind.util.Cleanable;
import com.distrimind.util.InvalidEncodedValue;

import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 5.10.0
 */
public class WrappedData  {
	protected static class Finalizer extends Cleanable.Cleaner
	{
		private byte[] data;
		protected transient boolean toZeroize;

		protected Finalizer() {
			super(null);
		}

		@Override
		protected void performCleanup() {
			if (toZeroize) {
				Arrays.fill(data, (byte) 0);
				toZeroize=false;
			}
		}
	}
	protected final Finalizer finalizer;
	private transient WrappedSecretData secretData=null;
	protected WrappedData()
	{
		this.finalizer=new Finalizer();
		this.finalizer.data=null;
	}
	public WrappedData(byte[] data) {
		if (data ==null)
			throw new NullPointerException();
		this.finalizer=new Finalizer();
		this.finalizer.data = data;
	}
	public WrappedData(WrappedData data) {
		if (data ==null)
			throw new NullPointerException();
		this.finalizer=new Finalizer();
		this.finalizer.data=data.finalizer.data;
	}
	public WrappedData(WrappedString secretData) throws InvalidEncodedValue {
		super();
		finalizer=new Finalizer();
		setData(Bits.toBytesArrayFromBase64String(secretData.toString(), false));
	}
	public byte[] getBytes() {
		return finalizer.data;
	}

	protected void setData(byte[] data)
	{
		if (data==null)
			throw new NullPointerException();
		this.finalizer.data=data;
		this.secretData=null;
	}

	@SuppressWarnings("UnusedReturnValue")
	public WrappedSecretData transformToSecretData()
	{
		if (secretData==null)
			secretData=new WrappedSecretData(finalizer.data);
		return secretData;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WrappedData that = (WrappedData) o;
		return Arrays.equals(finalizer.data, that.finalizer.data);
	}

	public WrappedString toWrappedString()
	{
		return new WrappedString(this);
	}

	public WrappedData toShortData(int bytesNumber)
	{
		if (bytesNumber<=0)
			throw new IllegalArgumentException();
		if (this.finalizer.data==null)
			return this;
		if (bytesNumber>=this.finalizer.data.length)
			return this;
		int step=this.finalizer.data.length/bytesNumber;
		byte[] res=new byte[bytesNumber];
		System.arraycopy(this.finalizer.data, 0, res, 0, res.length);
		for (int i=step;i<this.finalizer.data.length;)
		{
			int s=Math.min(this.finalizer.data.length-i, res.length);
			for (int j=0;j<s;j++)
				res[j]^=this.finalizer.data[i++];
		}
		if (this instanceof WrappedSecretData)
			return new WrappedSecretData(res);
		else
			return new WrappedData(res);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(finalizer.data);
	}
}
