package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedString;

import java.util.Arrays;
import java.util.Objects;

/**
 *
 *
 * @author Jason Mahdjoub
 * @version 3.9
 * @since Utils 5.25.0
 */
public final class WrappedHashedValue extends WrappedData {
	public static final int MAX_SIZE_IN_BYTES_OF_HASHED_VALUE=MessageDigestAlgorithmType.MAX_HASH_LENGTH_IN_BYTES+2;
	private MessageDigestAlgorithmType type;
	private byte[] digest;
	private transient StringBuilder base64String=null, base16String=null;
	private transient String toString=null;
	private Integer hashCode=null;
	WrappedHashedValue(MessageDigestAlgorithmType type, byte[] digest, byte[] encoded) {
		super(encoded);
		if (type.getDigestLengthInBytes()!=digest.length)
			throw new IllegalArgumentException();
		assert digest.length<=MessageDigestAlgorithmType.MAX_HASH_LENGTH_IN_BYTES;
		this.type = type;
		this.digest=digest;
		//noinspection ConstantValue
		assert type.ordinal()<256;
	}
	private WrappedHashedValue(MessageDigestAlgorithmType type, byte[] digest) {
		super();
		if (type.getDigestLengthInBytes()!=digest.length)
			throw new IllegalArgumentException();
		assert digest.length<=MessageDigestAlgorithmType.MAX_HASH_LENGTH_IN_BYTES;
		this.type = type;
		this.digest=digest;
		//noinspection ConstantValue
		assert type.ordinal()<256;
	}
	private WrappedHashedValue(byte[] encoded) throws InvalidEncodedValue {
		super();
		setData(encoded);
	}

	@Override
	protected void setData(byte[] data) throws InvalidEncodedValue {
		int o=data[0] & 0xFF;
		for (MessageDigestAlgorithmType t : MessageDigestAlgorithmType.values())
		{
			if (t.ordinal()==o)
			{
				if (type.getDigestLengthInBytes()!=data.length-1)
					throw new InvalidEncodedValue();
				super.setData(data);
				this.type = t;
				this.digest=Arrays.copyOfRange(data, 1, data.length-1);
				this.base16String=null;
				this.base64String=null;
				this.toString=null;
				this.hashCode=null;
				//noinspection ConstantValue
				assert type.ordinal()<256;
				return;
			}
		}
		throw new InvalidEncodedValue("Invalid message digest type ordinal : "+o);


	}

	@Override
	public byte[] getBytes() {
		byte[] r=super.getBytes();
		if (r==null) {
			r=getSerializedArray(type, digest);
			try {
				super.setData(r);
			} catch (InvalidEncodedValue e) {
				throw new RuntimeException(e);
			}
		}
		return r;
	}

	public static WrappedHashedValue fromEncodedArray(byte[] e) throws InvalidEncodedValue {
		return new WrappedHashedValue(e);
	}


	WrappedHashedValue(WrappedHashedValueInBase64StringFormat wrappedHashedValueInBase64StringFormat) throws InvalidEncodedValue {
		super(wrappedHashedValueInBase64StringFormat);
	}

	@Override
	public int hashCode()
	{
		if (hashCode==null)
		{
			hashCode=Objects.hash(type, Arrays.hashCode(getHashArray()));
		}
		return hashCode;
	}
	public static WrappedHashedValue from(MessageDigestType type, byte[] digest)
	{
		return new WrappedHashedValue(type.getDerivedType().getMessageDigestAlgorithmType(), digest);
	}
	public static WrappedHashedValue from(MessageDigestAlgorithmType type, byte[] digest)
	{
		return new WrappedHashedValue(type, digest);
	}




	@Override
	public String toString() {
		if (toString==null) {
			WrappedString ws=toShortData(8).toWrappedString();
			toString = "HashValue[.." +ws.toStringBuilder().toString() + "..]";
			ws.toStringBuilder();
		}
		return toString;
	}

	@Override
	public boolean equals(Object o)
	{
		if (o==null)
			return false;
		if (o.getClass()== WrappedHashedValue.class)
		{
			WrappedHashedValue d=(WrappedHashedValue) o;
			return type==d.type && com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(d.getHashArray(), getHashArray());
		}
		return false;
	}

	public StringBuilder getHashInBase64StringFormat()
	{
		if (base64String==null) {
			base64String=Bits.toBase64String(getHashArray(), false);
		}
		return base64String;
	}

	private static byte[] getSerializedArray(MessageDigestAlgorithmType type, byte[] t)
	{
		byte[] e=new byte[t.length+1];
		e[0]=(byte)type.ordinal();
		System.arraycopy(t, 0, e, 1, t.length);
		return e;
	}

	public StringBuilder getHashInBase16StringFormat()
	{
		if (base16String==null)
			base16String=Bits.toBase16String(getHashArray(), false);
		return base16String;
	}

	public static WrappedHashedValue fromBase64String(MessageDigestAlgorithmType type, String digest) throws InvalidEncodedValue {
		return from(type, Bits.toBytesArrayFromBase64String(digest, false));
	}
	public static WrappedHashedValue fromBase16String(MessageDigestAlgorithmType type, String digest) throws InvalidEncodedValue {
		return from(type, Bits.toBytesArrayFromBase16String(digest, false));
	}

	public byte[] getHashArray()
	{
		return digest;
	}

	public MessageDigestAlgorithmType getType()
	{
		return type;
	}

	@Override
	public WrappedHashedValueInBase64StringFormat toWrappedString() {
		return new WrappedHashedValueInBase64StringFormat(this);
	}
}
