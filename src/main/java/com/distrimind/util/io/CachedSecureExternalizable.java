package com.distrimind.util.io;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.15.0
 */
public class CachedSecureExternalizable<T> implements SecureExternalizable{
	private static final int MAX_CACHE_SIZE=10000000;
	private transient T externalizable;
	private byte[] cache=null;

	public CachedSecureExternalizable(T externalizable) {
		if (externalizable==null)
			throw new NullPointerException();
		this.externalizable = externalizable;
	}

	@SuppressWarnings("unused")
	private CachedSecureExternalizable() {
	}

	public T getExternalizable() throws IOException, ClassNotFoundException {
		if (externalizable==null)
		{
			assert cache!=null;
			try(RandomByteArrayInputStream bais=new RandomByteArrayInputStream(cache))
			{
				externalizable = bais.readObject(false);
			}
		}
		return externalizable;
	}

	@Override
	public int getInternalSerializedSize() {
		if (cache==null) {
			if (externalizable instanceof SecureExternalizable)
				return ((SecureExternalizable)externalizable).getInternalSerializedSize();
			else
				return SerializationTools.getInternalSize(externalizable, Integer.MAX_VALUE);
		}
		else
			return cache.length;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		if (cache==null)
		{
			try(RandomByteArrayOutputStream baos=new RandomByteArrayOutputStream())
			{
				baos.writeObject(externalizable, false);
				baos.flush();
				cache=baos.getBytes();
			}
		}
		out.writeBytesArray(cache, false, MAX_CACHE_SIZE);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		externalizable=null;
		cache=in.readBytesArray(false, MAX_CACHE_SIZE);
	}
}
