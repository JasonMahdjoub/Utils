/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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


import com.distrimind.util.*;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedString;

import java.util.Arrays;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.2
 * @since Utils 2.0
 */

public abstract class AbstractKey extends AbstractDecentralizedValue implements IKey, Zeroizable {

	public static AbstractKey decode(byte[] b) throws InvalidEncodedValue {
		return decode(b, !isPublicKey(b, 0));
	}

	static final int INCLUDE_KEY_EXPIRATION_CODE=1<<6;

	static final int IS_XDH_KEY=1<<5;


	static final byte IS_HYBRID_KEY_PAIR=(byte)(19);
	static final byte IS_HYBRID_PUBLIC_KEY=(byte)(20);
	static final byte IS_HYBRID_PRIVATE_KEY=(byte)(21);
	public static boolean isPublicKey(WrappedData b)
	{
		return isPublicKey(b.getBytes());
	}
	public static boolean isPublicKey(byte[] b)
	{
		return isPublicKey(b, 0);
	}

	@Override
	public String toString() {
		if (isDestroyed())
			return this.getClass().getSimpleName()+"[destroyed]";
		return super.toString();
	}

	public static boolean isPublicKey(byte[] b, int off)
	{
		byte type=b[off];
		type&=~INCLUDE_KEY_EXPIRATION_CODE;
		type&=~IS_XDH_KEY;
		return type==4 || type==5;

	}
	public static boolean isValidType(WrappedData wrappedData)
	{
		return isValidType(wrappedData.getBytes(), 0);
	}
	public static boolean isValidType(byte[] b, int off)
	{
		if (b[0]==IS_HYBRID_PRIVATE_KEY || b[0]==IS_HYBRID_PUBLIC_KEY)
		{
			return true;
		}
		else {
			byte type = b[off];
			type &= ~INCLUDE_KEY_EXPIRATION_CODE;
			type &= ~IS_XDH_KEY;
			return type >= 0 && type <= 5;
		}
	}


	public static AbstractKey decode(byte[] b, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue {
		return decode(b, 0, b.length, fillArrayWithZerosWhenDecoded);
	}
	public static AbstractKey decode(byte[] b, int off, int len) throws InvalidEncodedValue {
		return decode(b, off, len, !isPublicKey(b, off));
	}

	static WrappedData encodeHybridKey(AbstractKey nonPQCKey, AbstractKey PQCKey, boolean includeTimes)
	{
		WrappedData encodedNonPQC=nonPQCKey instanceof IASymmetricPublicKey?((IASymmetricPublicKey)nonPQCKey).encode(includeTimes):nonPQCKey.encode();
		WrappedData encodedPQC=PQCKey instanceof IASymmetricPublicKey?((IASymmetricPublicKey)PQCKey).encode(includeTimes):PQCKey.encode();

		byte[] res=new byte[encodedNonPQC.getBytes().length+encodedPQC.getBytes().length+4];
		res[0]=((nonPQCKey instanceof HybridASymmetricPublicKey)?IS_HYBRID_PUBLIC_KEY:IS_HYBRID_PRIVATE_KEY);
		Bits.putUnsignedInt(res, 1, encodedNonPQC.getBytes().length, 3);
		System.arraycopy(encodedNonPQC.getBytes(), 0, res, 4, encodedNonPQC.getBytes().length );
		System.arraycopy(encodedPQC.getBytes(), 0, res, 4+encodedNonPQC.getBytes().length, encodedPQC.getBytes().length );
		if (encodedNonPQC instanceof AutoZeroizable) {
			((AutoZeroizable) encodedNonPQC).clean();
			((AutoZeroizable) encodedPQC).clean();
			return new WrappedSecretData(res);
		}
		else
		{
			return new WrappedData(res);
		}

	}

	static IHybridKey decodeHybridKey(byte[] encoded, int off, int len, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue {
		try {
			if (off < 0 || len < 0 || len + off > encoded.length)
				throw new IllegalArgumentException();
			try {
				if (len < 68)
					throw new InvalidEncodedValue();
				if (encoded[off] != IS_HYBRID_PRIVATE_KEY && encoded[off] != IS_HYBRID_PUBLIC_KEY)
					throw new InvalidEncodedValue("" + (encoded[off] & 0xFF));
				int size = (int) Bits.getUnsignedInt(encoded, off + 1, 3);
				if (size + 36 > len)
					throw new InvalidEncodedValue();
				AbstractKey nonPQCKey = decode(encoded, off + 4, size);
				if (IHybridKey.class.isAssignableFrom(nonPQCKey.getClass()))
					throw new InvalidEncodedValue();
				if (!ASymmetricPrivateKey.class.equals(nonPQCKey.getClass())
						&& !ASymmetricPublicKey.class.equals(nonPQCKey.getClass()))
					throw new InvalidEncodedValue();
				if (nonPQCKey.isPostQuantumKey())
					throw new InvalidEncodedValue();

				AbstractKey PQCKey = decode(encoded, off + 4 + size, len - size - 4);

				if (!PQCKey.getClass().equals(nonPQCKey.getClass()))
					throw new InvalidEncodedValue();
				if (!PQCKey.isPostQuantumKey())
					throw new InvalidEncodedValue();

				if (ASymmetricPrivateKey.class.equals(nonPQCKey.getClass())) {
					return new HybridASymmetricPrivateKey((ASymmetricPrivateKey) nonPQCKey, (ASymmetricPrivateKey) PQCKey);
				} else {
					fillArrayWithZerosWhenDecoded = false;
					return new HybridASymmetricPublicKey((ASymmetricPublicKey) nonPQCKey, (ASymmetricPublicKey) PQCKey);
				}
			}
			catch (IllegalArgumentException e)
			{
				throw new InvalidEncodedValue(e);
			}
		}
		catch (InvalidEncodedValue e)
		{
			fillArrayWithZerosWhenDecoded=false;
			throw e;
		}
		finally {
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(encoded, off, off+len, (byte)0);
		}
	}

	public static AbstractKey decode(WrappedData wrappedData) throws InvalidEncodedValue {
		AbstractKey k=decode(wrappedData.getBytes(), false);
		if (k instanceof ISecretDecentralizedValue)
			wrappedData.transformToSecretData();
		return k;
	}
	public static AbstractKey decode(byte[] b, int off, int len, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue {
		if (off<0 || len<0 || len+off>b.length)
			throw new IllegalArgumentException();
			//byte[][] res = Bits.separateEncodingsWithShortSizedTabs(b);
		try {
			int type=b[off] & 0xFF;
			boolean includeKeyExpiration=(type & INCLUDE_KEY_EXPIRATION_CODE) == INCLUDE_KEY_EXPIRATION_CODE;

			boolean isXdh=(type & IS_XDH_KEY) == IS_XDH_KEY;
			if (includeKeyExpiration)
				type-=INCLUDE_KEY_EXPIRATION_CODE;
			if (isXdh)
				type-=IS_XDH_KEY;
			if (type == (byte)0) {
				if (isXdh)
				{
					int s=b[off+1] & 0xFF;

					AbstractKey ke=decode(b, off+2, s, false);
					if (!(ke instanceof SymmetricSecretKey))
						throw new InvalidEncodedValue();
					AbstractKey ks=decode(b, off+2+s, len-2-s, false);
					if (!(ks instanceof SymmetricSecretKey))
						throw new InvalidEncodedValue();
					return new SymmetricSecretKeyPair((SymmetricSecretKey)ke, (SymmetricSecretKey)ks);
				}
				else {
					int codedTypeSize = SymmetricSecretKey.ENCODED_TYPE_SIZE;
					byte[] secretKey = new byte[len - 2 - codedTypeSize];
					System.arraycopy(b, 2 + codedTypeSize + off, secretKey, 0, secretKey.length);
					return new SymmetricSecretKey(SymmetricEncryptionType.valueOf((int) Bits.getUnsignedInt(b, off + 1, codedTypeSize)), secretKey,
							SymmetricSecretKey.decodeKeySizeBits(b[codedTypeSize + 1 + off]));
				}
			} else if (type == (byte) 1) {
				int codedTypeSize = SymmetricSecretKey.ENCODED_TYPE_SIZE;
				byte[] secretKey = new byte[len - 2 - codedTypeSize];
				System.arraycopy(b, 2 + codedTypeSize+off, secretKey, 0, secretKey.length);
				return new SymmetricSecretKey(SymmetricAuthenticatedSignatureType.valueOf((int) Bits.getUnsignedInt(b, off+1, codedTypeSize)), secretKey,
						SymmetricSecretKey.decodeKeySizeBits(b[codedTypeSize + 1+off]));
			} else if (type == 2) {

				byte[] privateKey = new byte[len - 4 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE];
				System.arraycopy(b, 4 + ASymmetricPrivateKey.ENCODED_TYPE_SIZE+off, privateKey, 0, privateKey.length);
				ASymmetricPrivateKey res=new ASymmetricPrivateKey(ASymmetricAuthenticatedSignatureType.valueOf((int) Bits.getUnsignedInt(b, off+4, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), privateKey,
						(int)Bits.getUnsignedInt(b, off+1, 3));
				res.xdhKey=isXdh;
				return res;
			} else if (type == 3) {

				byte[] privateKey = new byte[len - 4 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE];
				System.arraycopy(b, 4 + ASymmetricPrivateKey.ENCODED_TYPE_SIZE+off, privateKey, 0, privateKey.length);
				return new ASymmetricPrivateKey(ASymmetricEncryptionType.valueOf((int) Bits.getUnsignedInt(b, off+4, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), privateKey,
						(int)Bits.getUnsignedInt(b, off+1, 3));
			} else if (type == 4) {
				fillArrayWithZerosWhenDecoded=false;

				byte[] publicKey = new byte[len - 4 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE-(includeKeyExpiration?16:0)];
				int posKey=ASymmetricPrivateKey.ENCODED_TYPE_SIZE+4+off;
				long timeExpiration;
				long publicKeyBeginDateUTC;
				if (includeKeyExpiration) {

					publicKeyBeginDateUTC=Bits.getLong(b, posKey);
					posKey += 8;
					timeExpiration=Bits.getLong(b, posKey);
					posKey += 8;
				}
				else {
					publicKeyBeginDateUTC=Long.MIN_VALUE;
					timeExpiration = Long.MAX_VALUE;
				}
				System.arraycopy(b, posKey, publicKey, 0, publicKey.length);
				return new ASymmetricPublicKey(ASymmetricEncryptionType.valueOf((int) Bits.getUnsignedInt(b, off+4, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), publicKey,
						(int)Bits.getUnsignedInt(b, off+1, 3), publicKeyBeginDateUTC, timeExpiration);
			} else if (type == 5) {
				fillArrayWithZerosWhenDecoded=false;

				byte[] publicKey = new byte[len - 4 - ASymmetricPrivateKey.ENCODED_TYPE_SIZE - (includeKeyExpiration ? 16 : 0)];
				int posKey=ASymmetricPrivateKey.ENCODED_TYPE_SIZE+4+off;
				long timeExpiration;
				long publicKeyBeginDateUTC;
				if (includeKeyExpiration) {

					publicKeyBeginDateUTC=Bits.getLong(b, posKey);
					posKey += 8;
					timeExpiration=Bits.getLong(b, posKey);
					posKey += 8;
				}
				else {
					publicKeyBeginDateUTC=Long.MIN_VALUE;
					timeExpiration = Long.MAX_VALUE;
				}
				System.arraycopy(b, posKey, publicKey, 0, publicKey.length);
				ASymmetricPublicKey res=new ASymmetricPublicKey(ASymmetricAuthenticatedSignatureType.valueOf((int) Bits.getUnsignedInt(b, off+4, ASymmetricPrivateKey.ENCODED_TYPE_SIZE)), publicKey,
						(int)Bits.getUnsignedInt(b, off+1, 3), publicKeyBeginDateUTC, timeExpiration);
				res.xdhKey=isXdh;
				return res;
			} else if (type==IS_HYBRID_PRIVATE_KEY || type==IS_HYBRID_PUBLIC_KEY)
			{
				IHybridKey res=decodeHybridKey(b, off, len, fillArrayWithZerosWhenDecoded);
				if (!res.getClass().equals(HybridASymmetricPrivateKey.class)
						&& !res.getClass().equals(HybridASymmetricPublicKey.class)	)
					throw new InvalidEncodedValue();
				return (AbstractKey)res;
			}
			else {
				fillArrayWithZerosWhenDecoded=false;
				throw new InvalidEncodedValue();
			}

		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidEncodedValue(e);
		}
		finally
		{
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(b, off, off+len, (byte)0);
		}
	}



	public static AbstractKey valueOf(WrappedString key) throws InvalidEncodedValue {
		if (key==null)
			throw new NullPointerException();
		AbstractKey k=decode(new WrappedSecretData(key));
		if (k instanceof ISecretDecentralizedValue)
			key.transformToSecretString();
		return k;
	}






}