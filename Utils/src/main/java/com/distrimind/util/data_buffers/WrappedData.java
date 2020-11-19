package com.distrimind.util.data_buffers;

import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
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

	@Override
	public int hashCode() {
		return Arrays.hashCode(data);
	}
}
