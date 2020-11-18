package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import com.distrimind.util.io.SecureExternalizable;
import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import com.distrimind.util.io.SerializationTools;

import java.io.IOException;
import java.util.Arrays;
import java.util.Base64;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.10.0
 */
public class SecretData implements Zeroizable, SecureExternalizable {
	private byte[] secretData;
	private final static int MAX_HASHED_PASSWORD_SIZE_IN_BYTES=MessageDigestType.MAX_HASH_LENGTH+10;

	protected SecretData()
	{
		secretData =null;
	}
	public SecretData(SecretDataString secretData) throws IOException {
		if (secretData ==null)
			throw new NullPointerException();
		String s=new String(secretData.getChars());
		byte[] d=Base64.getUrlDecoder().decode(s);
		if (d.length>MAX_HASHED_PASSWORD_SIZE_IN_BYTES)
			throw new IllegalArgumentException();
		this.secretData=Bits.checkByteArrayAndReturnsItWithoutCheckSum(d);
		SecretDataString.zeroizeString(s);
		Arrays.fill(d, (byte)0);
	}


	public SecretData(byte[] secretData) {
		if (secretData ==null)
			throw new NullPointerException();
		if (secretData.length>MAX_HASHED_PASSWORD_SIZE_IN_BYTES)
			throw new IllegalArgumentException();
		this.secretData = secretData;
	}
	public SecretData(SecretData secretData) {
		this(secretData.secretData.clone());
	}

	public byte[] getBytes() {
		return secretData;
	}

	@Override
	public void zeroize()
	{
		Arrays.fill(secretData, (byte)0);
	}
	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		zeroize();
	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(secretData, MAX_HASHED_PASSWORD_SIZE_IN_BYTES);
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeBytesArray(secretData, false, MAX_HASHED_PASSWORD_SIZE_IN_BYTES);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		secretData =in.readBytesArray(false, MAX_HASHED_PASSWORD_SIZE_IN_BYTES);
	}
}
