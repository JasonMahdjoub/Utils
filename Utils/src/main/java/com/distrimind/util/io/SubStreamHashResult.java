package com.distrimind.util.io;

import com.distrimind.util.crypto.MessageDigestType;

import java.io.IOException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class SubStreamHashResult implements SecureExternalizable {
	private static final int MAX_HASH_SIZE= MessageDigestType.getMaxDigestLengthInBytes();
	private static final int MAX_IV_LENGTH=64;
	private byte[] hash;
	private byte[] iv;

	public SubStreamHashResult(byte[] hash, byte[] iv) {
		if (hash==null)
			throw new NullPointerException();
		if (hash.length>MAX_HASH_SIZE)
			throw new IllegalArgumentException();
		if (iv!=null && iv.length>MAX_IV_LENGTH)
			throw new IllegalArgumentException();
		this.hash = hash;
		this.iv = iv;
	}

	public byte[] getHash() {
		return hash;
	}

	public byte[] getIv() {
		return iv;
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(hash, MAX_HASH_SIZE)+SerializationTools.getInternalSize(iv, MAX_IV_LENGTH);
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeBytesArray(hash, false, MAX_HASH_SIZE);
		out.writeBytesArray(iv, true, MAX_IV_LENGTH);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		hash=in.readBytesArray(false, MAX_HASH_SIZE);
		iv=in.readBytesArray(true, MAX_IV_LENGTH);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		SubStreamHashResult that = (SubStreamHashResult) o;
		return Arrays.equals(hash, that.hash) &&
				Arrays.equals(iv, that.iv);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(hash);
	}
}
