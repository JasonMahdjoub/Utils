/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

This software is governed by the CeCILL-C license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
 */
package com.distrimind.util.crypto;


import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import com.distrimind.util.DecentralizedValue;
import org.apache.commons.codec.binary.Base64;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.2
 * @since Utils 2.0
 */
public abstract class Key extends DecentralizedValue {
	
	
	
	/**
	 * 
	 */
	private static final long serialVersionUID = -8425241891004940479L;



	abstract Object toGnuKey()
			throws InvalidKeySpecException, NoSuchAlgorithmException;

	abstract java.security.Key toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException;
	
	abstract org.bouncycastle.crypto.Key toBouncyCastleKey() throws NoSuchAlgorithmException, InvalidKeySpecException;
	
	public  abstract byte[] encode(boolean includeTimeExpiration);



	public static Key decode(byte[] b) throws IllegalArgumentException {
		return decode(b, !isPublicKey(b, 0));
	}

	static final int INCLUDE_KEY_EXPIRATION_CODE=1<<6;

	static final int IS_XDH_KEY=1<<5;
	static final int IS_HYBRID_KEY=1<<4;

	public static boolean isPublicKey(byte[] b)
	{
		return isPublicKey(b, 0);
	}

	public static boolean isPublicKey(byte[] b, int off)
	{
		byte type=b[off];
		type&=~INCLUDE_KEY_EXPIRATION_CODE;
		type&=~IS_XDH_KEY;
		return type==4 || type==5;

	}
	public static boolean isValidType(byte[] b, int off)
	{
		if (b[0]==IS_HYBRID_KEY)
		{
			int s=(int)Bits.getPositiveInteger(b, off+1, 3);
			if (b.length<off+36+s)
				return false;
			if (b[off+4]==IS_HYBRID_KEY || b[off+4+s]==IS_HYBRID_KEY)
				return false;
			return isValidType(b, off+4) && isValidType(b, off+4+s);
		}
		else {
			byte type = b[off];
			type &= ~INCLUDE_KEY_EXPIRATION_CODE;
			type &= ~IS_XDH_KEY;
			return type >= 0 && type <= 5;
		}
	}
	public static Key decode(byte[] b, boolean fillArrayWithZerosWhenDecoded) throws IllegalArgumentException {
		return decode(b, 0, b.length, fillArrayWithZerosWhenDecoded);
	}
	public static Key decode(byte[] b, int off, int len) throws IllegalArgumentException {
		return decode(b, off, len, !isPublicKey(b, off));
	}

	static byte[] encodeHybridKey(Key nonPQCKey, Key PQCKey, boolean includeTimeExpiration)
	{
		byte[] encodedNonPQC=nonPQCKey.encode(includeTimeExpiration);
		byte[] encodedPQC=PQCKey.encode(includeTimeExpiration);

		byte[] res=new byte[encodedNonPQC.length+encodedPQC.length+4];
		res[0]=IS_HYBRID_KEY;
		Bits.putPositiveInteger(res, 1, encodedNonPQC.length, 3);
		System.arraycopy(encodedNonPQC, 0, res, 4, encodedNonPQC.length );
		System.arraycopy(encodedPQC, 0, res, 4+encodedNonPQC.length, encodedPQC.length );
		return res;
	}

	static DecentralizedValue decodeHybridKey(byte[] encoded, int off, int len, boolean fillArrayWithZerosWhenDecoded)
			throws IllegalArgumentException
	{
		try {
			if (off < 0 || len < 0 || len + off > encoded.length)
				throw new IllegalArgumentException();

			if (len < 68)
				throw new IllegalArgumentException();
			if (encoded[off] != IS_HYBRID_KEY)
				throw new IllegalArgumentException();
			int size = (int) Bits.getPositiveInteger(encoded, off + 1, 3);
			if (size + 36 > len)
				throw new IllegalArgumentException();
			Key nonPQCKey = decode(encoded, off + 4, size);
			if (HybridKey.class.isAssignableFrom(nonPQCKey.getClass()))
				throw new IllegalArgumentException();
			if (!ASymmetricPrivateKey.class.equals(nonPQCKey.getClass())
					&& !ASymmetricPublicKey.class.equals(nonPQCKey.getClass()))
				throw new IllegalArgumentException();
			if (nonPQCKey.isPostQuantumKey())
				throw new IllegalArgumentException();

			Key PQCKey = decode(encoded, off + 4 + size, len - off - size - 4);

			if (!PQCKey.getClass().equals(nonPQCKey.getClass()))
				throw new IllegalArgumentException();
			if (!PQCKey.isPostQuantumKey())
				throw new IllegalArgumentException();

			if (ASymmetricPrivateKey.class.equals(nonPQCKey.getClass())) {
				return new HybridASymmetricPrivateKey((ASymmetricPrivateKey) nonPQCKey, (ASymmetricPrivateKey) PQCKey);
			}
			else {
				fillArrayWithZerosWhenDecoded = false;
				return new HybridASymmetricPublicKey((ASymmetricPublicKey) nonPQCKey, (ASymmetricPublicKey) PQCKey);
			}
		}
		catch (IllegalArgumentException e)
		{
			fillArrayWithZerosWhenDecoded=false;
			throw e;
		}
		finally {
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(encoded, off, len, (byte)0);
		}
	}


	public static Key decode(byte[] b, int off, int len, boolean fillArrayWithZerosWhenDecoded) throws IllegalArgumentException {
		if (off<0 || len<0 || len+off>b.length)
			throw new IllegalArgumentException();
			//byte[][] res = Bits.separateEncodingsWithShortSizedTabs(b);
		try {
			byte type=b[off];
			boolean includeKeyExpiration=(type & INCLUDE_KEY_EXPIRATION_CODE) == INCLUDE_KEY_EXPIRATION_CODE;

			boolean isXdh=(type & IS_XDH_KEY) == IS_XDH_KEY;
			if (includeKeyExpiration)
				type-=INCLUDE_KEY_EXPIRATION_CODE;
			if (isXdh)
				type-=IS_XDH_KEY;
			if (type == (byte)0) {
				int codedTypeSize = SymmetricSecretKey.getEncodedTypeSize();
				byte[] secretKey = new byte[len - 2 - codedTypeSize];
				System.arraycopy(b, 2 + codedTypeSize+off, secretKey, 0, secretKey.length);
				return new SymmetricSecretKey(SymmetricEncryptionType.valueOf((int) Bits.getPositiveInteger(b, off+1, codedTypeSize)), secretKey,
						SymmetricSecretKey.decodeKeySizeBits(b[codedTypeSize + 1+off]));
			} else if (type == (byte) 1) {
				int codedTypeSize = SymmetricSecretKey.getEncodedTypeSize();
				byte[] secretKey = new byte[len - 2 - codedTypeSize];
				System.arraycopy(b, 2 + codedTypeSize+off, secretKey, 0, secretKey.length);
				return new SymmetricSecretKey(SymmetricAuthentifiedSignatureType.valueOf((int) Bits.getPositiveInteger(b, off+1, codedTypeSize)), secretKey,
						SymmetricSecretKey.decodeKeySizeBits(b[codedTypeSize + 1+off]));
			} else if (type == 2) {

				byte[] privateKey = new byte[len - 3 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE];
				System.arraycopy(b, 3 + ASymmetricPrivateKey.ENCODED_TYPE_SIZE+off, privateKey, 0, privateKey.length);
				ASymmetricPrivateKey res=new ASymmetricPrivateKey(ASymmetricAuthenticatedSignatureType.valueOf((int) Bits.getPositiveInteger(b, off+3, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), privateKey,
						(int)Bits.getPositiveInteger(b, off+1, 2)*8);
				res.xdhKey=isXdh;
				return res;
			} else if (type == 3) {

				byte[] privateKey = new byte[len - 3 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE];
				System.arraycopy(b, 3 + ASymmetricPrivateKey.ENCODED_TYPE_SIZE+off, privateKey, 0, privateKey.length);
				return new ASymmetricPrivateKey(ASymmetricEncryptionType.valueOf((int) Bits.getPositiveInteger(b, off+3, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), privateKey,
						(int)Bits.getPositiveInteger(b, off+1, 2)*8);
			} else if (type == 4) {
				fillArrayWithZerosWhenDecoded=false;

				byte[] publicKey = new byte[len - 3 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE-(includeKeyExpiration?8:0)];
				int posKey=ASymmetricPrivateKey.ENCODED_TYPE_SIZE+3+off;
				long timeExpiration;
				if (includeKeyExpiration) {

					timeExpiration=Bits.getLong(b, posKey);
					posKey += 8;
				}
				else
					timeExpiration=Long.MAX_VALUE;
				System.arraycopy(b, posKey, publicKey, 0, publicKey.length);
				return new ASymmetricPublicKey(ASymmetricEncryptionType.valueOf((int) Bits.getPositiveInteger(b, off+3, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), publicKey,
						(int)Bits.getPositiveInteger(b, off+1, 2)*8, timeExpiration);
			} else if (type == 5) {
				fillArrayWithZerosWhenDecoded=false;

				byte[] publicKey = new byte[len - 3 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE - (includeKeyExpiration ? 8 : 0)];
				int posKey=ASymmetricPrivateKey.ENCODED_TYPE_SIZE+3+off;
				long timeExpiration;
				if (includeKeyExpiration) {

					timeExpiration=Bits.getLong(b, posKey);
					posKey += 8;
				}
				else
					timeExpiration=Long.MAX_VALUE;
				System.arraycopy(b, posKey+off, publicKey, 0, publicKey.length);
				ASymmetricPublicKey res=new ASymmetricPublicKey(ASymmetricAuthenticatedSignatureType.valueOf((int) Bits.getPositiveInteger(b, off+3, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), publicKey,
						(int)Bits.getPositiveInteger(b, off+1, 2)*8, timeExpiration);
				res.xdhKey=isXdh;
				return res;
			} else if (type==IS_HYBRID_KEY)
			{
				DecentralizedValue res=decodeHybridKey(b, off, len, fillArrayWithZerosWhenDecoded);
				if (!res.getClass().equals(HybridASymmetricPrivateKey.class)
						&& !res.getClass().equals(HybridASymmetricPublicKey.class)	)
					throw new IllegalArgumentException();
				return (Key)res;
			}
			else {
				fillArrayWithZerosWhenDecoded=false;
				throw new IllegalArgumentException();
			}

		}
		finally
		{
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(b, off, len, (byte)0);
		}
	}
	
	
	
	public static Key valueOf(String key) throws IllegalArgumentException {
		return decode(Base64.decodeBase64(key));
	}
	
	public abstract void zeroize();
	
	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		zeroize();
	}

    abstract byte[] getKeyBytes();

	public abstract boolean isPostQuantumKey();
}
