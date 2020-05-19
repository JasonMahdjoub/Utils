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
	private static final int MAX_IV_NUMBERS=Short.MAX_VALUE;
	private byte[] hash;
	private byte[][] ivs;

	public SubStreamHashResult(byte[] hash, byte[][] ivs) {
		if (hash==null)
			throw new NullPointerException();
		if (hash.length>MAX_HASH_SIZE)
			throw new IllegalArgumentException();
		if (ivs!=null) {
			if (ivs.length>MAX_IV_NUMBERS)
				throw new IllegalArgumentException();
			for (byte[] iv : ivs)
				if (iv != null && iv.length > MAX_IV_LENGTH)
					throw new IllegalArgumentException();
		}
		this.hash = hash;
		this.ivs = ivs;
	}

	public byte[] getHash() {
		return hash;
	}

	public byte[][] getIvs() {
		return ivs;
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(hash, MAX_HASH_SIZE)+SerializationTools.getInternalSize(ivs, MAX_IV_NUMBERS);
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeBytesArray(hash, false, MAX_HASH_SIZE);
		out.write2DBytesArray(ivs, true, false, MAX_IV_NUMBERS, MAX_IV_LENGTH);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		hash=in.readBytesArray(false, MAX_HASH_SIZE);
		ivs=in.read2DBytesArray(true, false, MAX_IV_NUMBERS, MAX_IV_LENGTH);
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		SubStreamHashResult that = (SubStreamHashResult) o;
		return Arrays.equals(hash, that.hash);
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(hash);
	}
}
