package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 5.10.0
 */
public class WrappedData  {
	private byte[] data;
	private transient WrappedSecretData secretData=null;
	protected WrappedData()
	{
		this.data=null;
	}
	public WrappedData(byte[] data) {
		if (data ==null)
			throw new NullPointerException();
		this.data = data;
	}
	public WrappedData(WrappedData data) {
		if (data ==null)
			throw new NullPointerException();
		this.data=data.data;
	}
	public WrappedData(WrappedString secretData) throws IOException {
		super();

		setData(Bits.toBytesArrayFromBase64String(secretData.toString(), false));
	}
	public byte[] getBytes() {
		return data;
	}

	protected void setData(byte[] data)
	{
		if (data==null)
			throw new NullPointerException();
		this.data=data;
		this.secretData=null;
	}

	@SuppressWarnings("UnusedReturnValue")
	public WrappedSecretData transformToSecretData()
	{
		if (secretData==null)
			secretData=new WrappedSecretData(data);
		return secretData;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		WrappedData that = (WrappedData) o;
		return Arrays.equals(data, that.data);
	}

	public WrappedString toWrappedString()
	{
		return new WrappedString(this);
	}

	public WrappedData toShortData(int bytesNumber)
	{
		if (bytesNumber<=0)
			throw new IllegalArgumentException();
		if (this.data==null)
			return this;
		if (bytesNumber>=this.data.length)
			return this;
		int step=this.data.length/bytesNumber;
		byte[] res=new byte[bytesNumber];
		System.arraycopy(this.data, 0, res, 0, res.length);
		for (int i=step;i<this.data.length;)
		{
			int s=Math.min(this.data.length-i, res.length);
			for (int j=0;j<s;j++)
				res[j]^=this.data[i++];
		}
		if (this instanceof WrappedSecretData)
			return new WrappedSecretData(res);
		else
			return new WrappedData(res);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}
}
