package com.distrimind.util.crypto;

import com.distrimind.util.io.SecureExternalizable;
import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import com.distrimind.util.io.SerializationTools;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;
import java.util.Objects;

/**
 *
 *
 * @author Jason Mahdjoub
 * @version 3.9
 * @since Utils 5.25.0
 */
public final class HashValue implements SecureExternalizable {
	private byte[] digest;
	private MessageDigestType type;
	private transient String base64String=null;
	private Integer hashCode=null;

	private HashValue(MessageDigestType type, byte[] digest) {
		if (digest==null)
			throw new NullPointerException();
		if (type==null)
			throw new NullPointerException();
		if (type.getDigestLengthInBytes()!=digest.length)
			throw new IllegalArgumentException();
		this.digest = digest;
		this.type = type.getDerivedType();
		//noinspection ConstantValue
		assert type.ordinal()<256;
	}

	@Override
	public int hashCode()
	{
		if (hashCode==null)
		{
			hashCode=Objects.hash(type, Arrays.hashCode(digest));
		}
		return hashCode;
	}

	public static HashValue from(MessageDigestType type, byte[] digest)
	{
		return new HashValue(type, digest);
	}

	@Override
	public String toString() {
		return "Digest["+toBase64String()+"]";
	}

	@Override
	public boolean equals(Object o)
	{
		if (o==null)
			return false;
		if (o.getClass()== HashValue.class)
		{
			HashValue d=(HashValue) o;
			return d.type==type && Arrays.equals(d.digest, digest);
		}
		return false;
	}

	public String toBase64String()
	{
		if (base64String==null) {
			byte[] e=new byte[digest.length+1];
			e[0]=(byte)type.ordinal();
			System.arraycopy(digest, 0, e, 1, digest.length);

			base64String=Base64.getUrlEncoder().encodeToString(e);
		}
		return base64String;
	}

	public static HashValue fromBase64String(String digest) throws IOException {
		byte[] e=Base64.getUrlDecoder().decode(digest);
		int o=e[0] & 0xFF;
		for (MessageDigestType t : MessageDigestType.values())
		{
			if (t.ordinal()==o)
			{
				HashValue d= new HashValue(t, Arrays.copyOfRange(e, 1, e.length-1));
				d.base64String=digest;
				return d;
			}
		}
		throw new IOException("Invalid message digest type ordinal : "+o);
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(type)+ digest.length;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeEnum(type, false);
		out.write(digest);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		hashCode=null;
		base64String=null;
		type=in.readEnum(false);
		type=type.getDerivedType();
		int s=type.getDigestLengthInBytes();
		digest=new byte[s];
		in.readFully(digest);
	}

	public byte[] getDigest()
	{
		return digest;
	}

	public MessageDigestType getType()
	{
		return type;
	}
}
