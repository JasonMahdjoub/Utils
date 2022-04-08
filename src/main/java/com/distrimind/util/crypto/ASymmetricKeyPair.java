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

import com.distrimind.util.Bits;
import com.distrimind.util.Cleanable;
import com.distrimind.util.InvalidEncodedValue;
import com.distrimind.util.data_buffers.WrappedSecretData;

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Base64;

/**
 * 
 * @author Jason Mahdjoub
 * @version 4.0
 * @since Utils 1.7.1
 */
public class ASymmetricKeyPair extends AbstractKeyPair<ASymmetricPrivateKey, ASymmetricPublicKey> {

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_KEY_PAIR =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE;

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PAIR_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PAIR_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION;
	private static final class Finalizer extends Cleaner
	{
		private ASymmetricPrivateKey privateKey;
		private ASymmetricPublicKey publicKey;
		private transient volatile KeyPair nativeKeyPair;
		private transient volatile Object gnuKeyPair;

		private Finalizer(Cleanable cleanable) {
			super(cleanable);
		}


		@Override
		protected void performCleanup() {
			if (privateKey!=null) {
				privateKey = null;
			}
			publicKey=null;
			if (nativeKeyPair!=null)
			{
				Arrays.fill(nativeKeyPair.getPublic().getEncoded(), (byte) 0);
				PrivateKey privk=nativeKeyPair.getPrivate();
				if (privk != null && !privk.isDestroyed()) {
					Arrays.fill(privk.getEncoded(), (byte) 0);
				}
				nativeKeyPair=null;
			}
			if (gnuKeyPair!=null)
			{
				Arrays.fill(GnuFunctions.keyGetEncoded(GnuFunctions.getPublicKey(gnuKeyPair)), (byte)0);
				Arrays.fill(GnuFunctions.keyGetEncoded(GnuFunctions.getPrivateKey(gnuKeyPair)), (byte)0);
				gnuKeyPair=null;
			}
		}
	}


	public static ASymmetricKeyPair valueOf(String key) throws InvalidEncodedValue {
		return decode(Bits.checkByteArrayAndReturnsItWithoutCheckSum(Base64.getUrlDecoder().decode(key)));
	}

	private final Finalizer finalizer;
	private final int keySizeBits;
	private final ASymmetricEncryptionType encryptionType;
	private final ASymmetricAuthenticatedSignatureType signatureType;
	private final int hashCode;
	private void checkNotDestroyed()
	{
		if (isDestroyed())
			throw new IllegalAccessError();
	}



	ASymmetricKeyPair(ASymmetricEncryptionType type, ASymmetricPrivateKey privateKey, ASymmetricPublicKey publicKey,
			int keySize) {
		if (type == null)
			throw new NullPointerException("type");
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer(this);
		this.finalizer.privateKey = privateKey;
		this.finalizer.publicKey = publicKey;
		this.keySizeBits = keySize;
		this.encryptionType = type;
		this.signatureType=null;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
	}

	public ASymmetricKeyPair(ASymmetricPrivateKey privateKey, ASymmetricPublicKey publicKey) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (privateKey.getAuthenticatedSignatureAlgorithmType()!=publicKey.getAuthenticatedSignatureAlgorithmType())
			throw new IllegalArgumentException();
		if (privateKey.getEncryptionAlgorithmType()!=publicKey.getEncryptionAlgorithmType())
			throw new IllegalArgumentException();
		this.finalizer=new Finalizer(this);
		this.finalizer.privateKey = privateKey;
		this.finalizer.publicKey = publicKey;
		this.keySizeBits = publicKey.getKeySizeBits();
		this.encryptionType = publicKey.getEncryptionAlgorithmType();
		this.signatureType=privateKey.getAuthenticatedSignatureAlgorithmType();

		hashCode = privateKey.hashCode() + publicKey.hashCode();
	}

	public ASymmetricKeyPair getKeyPairWithNewExpirationTime(long timeExpirationUTC)
	{
		checkNotDestroyed();
		return new ASymmetricKeyPair(this.finalizer.privateKey.getNewClonedPrivateKey(), this.finalizer.publicKey.getPublicKeyWithNewExpirationTime(timeExpirationUTC));
	}

	ASymmetricKeyPair(ASymmetricEncryptionType type, Object keyPair, int keySize, long publicKeyValidityBeginDateUTC,
			long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer(this);
		finalizer.privateKey = new ASymmetricPrivateKey(type, GnuFunctions.getPrivateKey(keyPair), keySize);
		finalizer.publicKey = new ASymmetricPublicKey(type, GnuFunctions.getPublicKey(keyPair), keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = type;
		this.signatureType=null;

		hashCode = finalizer.privateKey.hashCode() + finalizer.publicKey.hashCode();
		this.finalizer.gnuKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricEncryptionType type, KeyPair keyPair, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer(this);
		finalizer.privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(), keySize);
		finalizer.publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = type;
		this.signatureType=null;

		hashCode = finalizer.privateKey.hashCode() + finalizer.publicKey.hashCode();
		this.finalizer.nativeKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricAuthenticatedSignatureType type, ASymmetricPrivateKey privateKey, ASymmetricPublicKey publicKey,
					  int keySize) {
		if (type == null)
			throw new NullPointerException("type");
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer(this);
		this.finalizer.privateKey = privateKey;
		this.finalizer.publicKey = publicKey;
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
	}

	ASymmetricKeyPair(ASymmetricAuthenticatedSignatureType type, Object keyPair, int keySize, long publicKeyValidityBeginDateUTC,
					  long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer(this);
		finalizer.privateKey = new ASymmetricPrivateKey(type, GnuFunctions.getPrivateKey(keyPair), keySize);
		finalizer.publicKey = new ASymmetricPublicKey(type, GnuFunctions.getPublicKey(keyPair), keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = finalizer.privateKey.hashCode() + finalizer.publicKey.hashCode();
		this.finalizer.gnuKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricAuthenticatedSignatureType type, KeyPair keyPair, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC, boolean xdhKey) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer(this);
		finalizer.privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(), keySize, xdhKey);
		finalizer.publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize, publicKeyValidityBeginDateUTC, expirationUTC, xdhKey);
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = finalizer.privateKey.hashCode() + finalizer.publicKey.hashCode();
		this.finalizer.nativeKeyPair=keyPair;
	}

	public WrappedSecretData encode() {
		return encode(true);
	}
	@Override
	public WrappedSecretData encode(boolean includeTimes)
	{
		checkNotDestroyed();
		if (getTimeExpirationUTC()==Long.MAX_VALUE)
			includeTimes =false;

		byte[] kp=Bits.concatenateEncodingWithShortIntSizedTabs(finalizer.privateKey.getBytesPrivateKey(), finalizer.publicKey.getBytesPublicKey());
		byte[] tab = new byte[4+ASymmetricPrivateKey.ENCODED_TYPE_SIZE+kp.length+(includeTimes ?16:0)];
		tab[0]=encryptionType==null?(byte)9:(byte)8;
		if (includeTimes)
			tab[0]|= AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
		if (finalizer.privateKey.xdhKey)
			tab[0]|= AbstractKey.IS_XDH_KEY;
		Bits.putUnsignedInt(tab, 1, keySizeBits, 3);
		Bits.putUnsignedInt(tab, 4, encryptionType==null?signatureType.ordinal():encryptionType.ordinal(), ASymmetricPrivateKey.ENCODED_TYPE_SIZE);
		int pos=4+ASymmetricPrivateKey.ENCODED_TYPE_SIZE;
		if (includeTimes) {
			Bits.putLong(tab, pos, finalizer.publicKey.getPublicKeyValidityBeginDateUTC());
			pos += 8;
			Bits.putLong(tab, pos, finalizer.publicKey.getTimeExpirationUTC());
			pos += 8;
		}
		System.arraycopy(kp, 0, tab, pos, kp.length);
		Arrays.fill(kp, (byte)0);
		return new WrappedSecretData(tab);
	}
	public static boolean isValidType(byte[] b, int off)
	{
		byte type=b[off];
		type&=~AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
		type&=~AbstractKey.IS_XDH_KEY;
		return type>=8 && type<=9;
	}


	public static ASymmetricKeyPair decode(byte[] b) throws InvalidEncodedValue {
		return decode(b, true);
	}
	public static ASymmetricKeyPair decode(byte[] b, int off, int len) throws InvalidEncodedValue {
		return decode(b, off, len,true);
	}
	public static ASymmetricKeyPair decode(byte[] b, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue {
		return decode(b, 0, b.length, fillArrayWithZerosWhenDecoded);
	}


	public static ASymmetricKeyPair decode(byte[] b, int off, int len, boolean fillArrayWithZerosWhenDecoded) throws InvalidEncodedValue {
		if (off<0 || len<0 || len+off>b.length)
			throw new IllegalArgumentException();

		try {
			try {
				int codedTypeSize = SymmetricSecretKey.ENCODED_TYPE_SIZE;
				int keySize = (int) (Bits.getUnsignedInt(b, 1 + off, 3));
				int posKey = codedTypeSize + 4 + off;
				byte type = b[off];

				boolean includeKeyExpiration = (type & AbstractKey.INCLUDE_KEY_EXPIRATION_CODE) == AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
				boolean kdhKey = (type & AbstractKey.IS_XDH_KEY) == AbstractKey.IS_XDH_KEY;
				if (includeKeyExpiration)
					type -= AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
				if (kdhKey)
					type -= AbstractKey.IS_XDH_KEY;
				long timeExpiration;
				long publicKeyBeginDateUTC;
				if (includeKeyExpiration) {

					publicKeyBeginDateUTC = Bits.getLong(b, posKey);
					posKey += 8;
					timeExpiration = Bits.getLong(b, posKey);
					posKey += 8;
				} else {
					publicKeyBeginDateUTC = Long.MIN_VALUE;
					timeExpiration = Long.MAX_VALUE;
				}

				byte[] kp = new byte[len - 4 - codedTypeSize - (includeKeyExpiration ? 16 : 0)];
				System.arraycopy(b, posKey, kp, 0, kp.length);
				byte[][] keys = Bits.separateEncodingsWithShortIntSizedTabs(kp);

				if (type == 9) {
					ASymmetricAuthenticatedSignatureType type2 = ASymmetricAuthenticatedSignatureType.valueOf((int) Bits.getUnsignedInt(b, 4 + off, codedTypeSize));

					ASymmetricKeyPair res = new ASymmetricKeyPair(type2, new ASymmetricPrivateKey(type2, keys[0], keySize),
							new ASymmetricPublicKey(type2, keys[1], keySize, publicKeyBeginDateUTC, timeExpiration), keySize);
					res.getASymmetricPublicKey().xdhKey = kdhKey;
					res.getASymmetricPrivateKey().xdhKey = kdhKey;
					return res;
				} else if (type == 8) {
					ASymmetricEncryptionType type2 = ASymmetricEncryptionType.valueOf((int) Bits.getUnsignedInt(b, 4 + off, codedTypeSize));

					ASymmetricKeyPair res = new ASymmetricKeyPair(type2, new ASymmetricPrivateKey(type2, keys[0], keySize),
							new ASymmetricPublicKey(type2, keys[1], keySize, publicKeyBeginDateUTC, timeExpiration), keySize);
					res.getASymmetricPublicKey().xdhKey = kdhKey;
					res.getASymmetricPrivateKey().xdhKey = kdhKey;
					return res;
				} else {

					throw new InvalidEncodedValue();
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
				Arrays.fill(b, off, off+len, (byte)0);
		}



    }



	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof ASymmetricKeyPair) {
			ASymmetricKeyPair other = ((ASymmetricKeyPair) o);
			return finalizer.privateKey.equals(other.finalizer.privateKey) && finalizer.publicKey.equals(other.finalizer.publicKey) && keySizeBits == other.keySizeBits
					&& encryptionType == other.encryptionType && signatureType == other.signatureType;
		}
		return false;
	}

	@Override
	public long getTimeExpirationUTC() {
		return finalizer.publicKey.getTimeExpirationUTC();
	}


	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}

	public ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() {
		return signatureType;
	}

	@Override
	public ASymmetricPrivateKey getASymmetricPrivateKey() {
		checkNotDestroyed();
		return finalizer.privateKey;
	}

	@Override
	public ASymmetricPublicKey getASymmetricPublicKey() {
		checkNotDestroyed();
		return finalizer.publicKey;
	}

	@Override
	public boolean useEncryptionAlgorithm() {
		return getEncryptionAlgorithmType()!=null;
	}

	@Override
	public boolean useAuthenticatedSignatureAlgorithm() {
		return getAuthenticatedSignatureAlgorithmType()!=null;
	}

	@Override
	public ASymmetricKeyPair getNonPQCKeyPair() {
		checkNotDestroyed();
		return this;
	}

	public int getKeySizeBits() {
		return keySizeBits;
	}

	public int getMaxBlockSize() {
		if (encryptionType==null)
			throw new IllegalAccessError("This key should be used for signature");
		else
			return encryptionType.getMaxBlockSize(keySizeBits);
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public Object toGnuKeyPair() throws NoSuchAlgorithmException, IOException {
		checkNotDestroyed();
		if (finalizer.gnuKeyPair == null)
			finalizer.gnuKeyPair = GnuFunctions.getKeyPairInstance(finalizer.publicKey.toGnuKey(), finalizer.privateKey.toGnuKey());

		return finalizer.gnuKeyPair;
	}

	/*
	 * public static ASymmetricKeyPair generate(SecureRandom random) throws
	 * NoSuchAlgorithmException { return generate(random,
	 * ASymmetricEncryptionType.DEFAULT,
	 * ASymmetricEncryptionType.DEFAULT.getDefaultKeySize()); }
	 * 
	 * public static ASymmetricKeyPair generate(SecureRandom random,
	 * ASymmetricEncryptionType type) throws NoSuchAlgorithmException { return
	 * generate(random, type, type.getDefaultKeySize()); }
	 * 
	 * public static ASymmetricKeyPair generate(SecureRandom random,
	 * ASymmetricEncryptionType type, short keySize) throws NoSuchAlgorithmException
	 * { return new ASymmetricKeyPair(type, type.getKeyPairGenerator(random,
	 * keySize).generateKeyPair(), keySize); }
	 */
	@Override
	public KeyPair toJavaNativeKeyPair()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		checkNotDestroyed();
		if (finalizer.nativeKeyPair == null)
			finalizer.nativeKeyPair = new KeyPair(finalizer.publicKey.toJavaNativeKey(), finalizer.privateKey.toJavaNativeKey());

		return finalizer.nativeKeyPair;
	}


	@Override
	public boolean isPostQuantumKey() {
		return encryptionType==null?signatureType.isPostQuantumAlgorithm():encryptionType.isPostQuantumAlgorithm();
	}

	@Override
	public boolean areTimesValid() {
		return finalizer.publicKey.areTimesValid();
	}
}
