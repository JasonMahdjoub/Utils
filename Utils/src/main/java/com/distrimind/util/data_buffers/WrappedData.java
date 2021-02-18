package com.distrimind.util.data_buffers;

import com.distrimind.util.Bits;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.1
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

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}
}
