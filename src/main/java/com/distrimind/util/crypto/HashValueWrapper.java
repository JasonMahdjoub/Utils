package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedString;
import com.distrimind.util.io.*;

import java.io.IOException;
import java.util.Arrays;
import java.util.Objects;

/**
 *
 *
 * @author Jason Mahdjoub
 * @version 3.9
 * @since Utils 5.25.0
 */
public final class HashValueWrapper extends WrappedData implements SecureExternalizable {
	private MessageDigestAlgorithmType type;
	private transient StringBuilder base64String=null, base16String=null;
	private transient String toString=null;
	private Integer hashCode=null;

	private HashValueWrapper(MessageDigestAlgorithmType type, byte[] digest) {
		super(digest);
		if (type==null)
			throw new NullPointerException();
		if (type.getDigestLengthInBytes()!=digest.length)
			throw new IllegalArgumentException();
		assert digest.length<=MessageDigestAlgorithmType.MAX_HASH_LENGTH_IN_BYTES;
		this.type = type;
		//noinspection ConstantValue
		assert type.ordinal()<256;
	}

	@Override
	public int hashCode()
	{
		if (hashCode==null)
		{
			hashCode=Objects.hash(type, Arrays.hashCode(getBytes()));
		}
		return hashCode;
	}
	public static HashValueWrapper from(MessageDigestType type, byte[] digest)
	{
		return new HashValueWrapper(type.getDerivedType().getMessageDigestAlgorithmType(), digest);
	}
	public static HashValueWrapper from(MessageDigestAlgorithmType type, byte[] digest)
	{
		return new HashValueWrapper(type, digest);
	}

	private static HashValueWrapper fromSerializedArray(byte[] e) throws InvalidEncodedValue {
		int o=e[0] & 0xFF;
		for (MessageDigestAlgorithmType t : MessageDigestAlgorithmType.values())
		{
			if (t.ordinal()==o)
			{
				return new HashValueWrapper(t, Arrays.copyOfRange(e, 1, e.length-1));
			}
		}
		throw new InvalidEncodedValue("Invalid message digest type ordinal : "+o);
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
		if (o.getClass()== HashValueWrapper.class)
		{
			HashValueWrapper d=(HashValueWrapper) o;
			return d.type==type && com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(d.getBytes(), getBytes());
		}
		return false;
	}

	public StringBuilder toBase64String()
	{
		if (base64String==null) {
			base64String=Bits.toBase64String(getSerializedArray(), true);
		}
		return base64String;
	}

	private byte[] getSerializedArray()
	{
		byte[] t=getBytes();
		byte[] e=new byte[t.length+1];
		e[0]=(byte)type.ordinal();
		System.arraycopy(t, 0, e, 1, t.length);
		return e;
	}

	public StringBuilder toBase16String()
	{
		if (base16String==null)
			base16String=Bits.toBase16String(getSerializedArray(), true);
		return base16String;
	}

	public static HashValueWrapper fromBase64String(StringBuilder digest) throws InvalidEncodedValue {
		byte[] e=Bits.toBytesArrayFromBase64String(digest, true, false);
		HashValueWrapper r= fromSerializedArray(e);
		r.base64String=digest;
		return r;
	}
	public static HashValueWrapper fromBase16String(StringBuilder digest) throws InvalidEncodedValue {
		byte[] e=Bits.toBytesArrayFromBase16String(digest, true, false);
		HashValueWrapper r= fromSerializedArray(e);
		r.base16String=digest;
		return r;
	}
	public static HashValueWrapper fromBase64String(MessageDigestAlgorithmType type, String digest) throws InvalidEncodedValue {
		return from(type, Bits.toBytesArrayFromBase64String(digest, false));
	}
	public static HashValueWrapper fromBase16String(MessageDigestAlgorithmType type, String digest) throws InvalidEncodedValue {
		return from(type, Bits.toBytesArrayFromBase16String(digest, false));
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(type)+ getBytes().length;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeEnum(type, false);
		out.write(getBytes());
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		hashCode=null;
		base64String=null;
		base16String=null;
		type=in.readEnum(false);
		int s=type.getDigestLengthInBytes();
		if (s>MessageDigestAlgorithmType.MAX_HASH_LENGTH_IN_BYTES)
			throw new MessageExternalizationException(Integrity.FAIL);
		byte[] t=new byte[s];
		in.readFully(t);
		setData(t);

	}

	public byte[] getHashArray()
	{
		return getBytes();
	}

	public MessageDigestAlgorithmType getType()
	{
		return type;
	}

	@Override
	public byte[] getBytes() {
		return super.getBytes();
	}
}
