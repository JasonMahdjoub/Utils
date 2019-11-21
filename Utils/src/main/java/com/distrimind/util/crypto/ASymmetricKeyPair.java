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

import java.io.IOException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 4.0
 * @since Utils 1.7.1
 */
public class ASymmetricKeyPair extends AbstractKeyPair<ASymmetricPrivateKey, ASymmetricPublicKey> {
	/**
	 * 
	 */
	private static final long serialVersionUID = -8249147431069134363L;



	public static ASymmetricKeyPair valueOf(String key) throws IllegalArgumentException, IOException {
		return decode(Bits.checkByteArrayAndReturnsItWithoutCheckSum(Base64.decodeBase64(key)));
	}

	private ASymmetricPrivateKey privateKey;

	private ASymmetricPublicKey publicKey;

	private final int keySizeBits;

	private final ASymmetricEncryptionType encryptionType;
	private final ASymmetricAuthenticatedSignatureType signatureType;

	private final int hashCode;

	private transient volatile KeyPair nativeKeyPair;

	private transient volatile Object gnuKeyPair;

	@Override
	public void zeroize()
	{
		privateKey=null;
		publicKey=null;
		if (nativeKeyPair!=null)
		{
			Arrays.fill(nativeKeyPair.getPublic().getEncoded(), (byte)0);
			Arrays.fill(nativeKeyPair.getPrivate().getEncoded(), (byte)0);
			nativeKeyPair=null;
		}
		if (gnuKeyPair!=null)
		{
			Arrays.fill(GnuFunctions.keyGetEncoded(GnuFunctions.getPublicKey(gnuKeyPair)), (byte)0);
			Arrays.fill(GnuFunctions.keyGetEncoded(GnuFunctions.getPrivateKey(gnuKeyPair)), (byte)0);
			gnuKeyPair=null;
		}
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
		this.privateKey = privateKey;
		this.publicKey = publicKey;
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
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.keySizeBits = publicKey.getKeySizeBits();
		this.encryptionType = publicKey.getEncryptionAlgorithmType();
		this.signatureType=privateKey.getAuthenticatedSignatureAlgorithmType();

		hashCode = privateKey.hashCode() + publicKey.hashCode();
	}

	public ASymmetricKeyPair getKeyPairWithNewExpirationTime(long timeExpirationUTC)
	{
		return new ASymmetricKeyPair(this.privateKey.getNewClonedPrivateKey(), this.publicKey.getPublicKeyWithNewExpirationTime(timeExpirationUTC));
	}

	ASymmetricKeyPair(ASymmetricEncryptionType type, Object keyPair, int keySize,
			long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		privateKey = new ASymmetricPrivateKey(type, GnuFunctions.getPrivateKey(keyPair), keySize);
		publicKey = new ASymmetricPublicKey(type, GnuFunctions.getPublicKey(keyPair), keySize, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = type;
		this.signatureType=null;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
		this.gnuKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricEncryptionType type, KeyPair keyPair, int keySize, long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(), keySize);
		publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = type;
		this.signatureType=null;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
		this.nativeKeyPair=keyPair;
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
		this.privateKey = privateKey;
		this.publicKey = publicKey;
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
	}

	ASymmetricKeyPair(ASymmetricAuthenticatedSignatureType type, Object keyPair, int keySize,
					  long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		privateKey = new ASymmetricPrivateKey(type, GnuFunctions.getPrivateKey(keyPair), keySize);
		publicKey = new ASymmetricPublicKey(type, GnuFunctions.getPublicKey(keyPair), keySize, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
		this.gnuKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricAuthenticatedSignatureType type, KeyPair keyPair, int keySize, long expirationUTC, boolean xdhKey) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(), keySize, xdhKey);
		publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize, expirationUTC, xdhKey);
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
		this.nativeKeyPair=keyPair;
	}

	public byte[] encode() {
		return encode(true);
	}
	@Override
	public byte[] encode(boolean includeTimeExpiration)
	{
		if (getTimeExpirationUTC()==Long.MAX_VALUE)
			includeTimeExpiration=false;

		byte[] kp=Bits.concatenateEncodingWithShortIntSizedTabs(privateKey.getBytesPrivateKey(), publicKey.getBytesPublicKey());
		byte[] tab = new byte[4+ASymmetricPrivateKey.ENCODED_TYPE_SIZE+kp.length+(includeTimeExpiration?8:0)];
		tab[0]=encryptionType==null?(byte)9:(byte)8;
		if (includeTimeExpiration)
			tab[0]|= AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
		if (privateKey.xdhKey)
			tab[0]|= AbstractKey.IS_XDH_KEY;
		Bits.putPositiveInteger(tab, 1, keySizeBits, 3);
		Bits.putPositiveInteger(tab, 4, encryptionType==null?signatureType.ordinal():encryptionType.ordinal(), ASymmetricPrivateKey.ENCODED_TYPE_SIZE);
		int pos=4+ASymmetricPrivateKey.ENCODED_TYPE_SIZE;
		if (includeTimeExpiration) {
			Bits.putLong(tab, 4 + ASymmetricPrivateKey.ENCODED_TYPE_SIZE, publicKey.getTimeExpirationUTC());
			pos += 8;
		}
		System.arraycopy(kp, 0, tab, pos, kp.length);
		return tab;
	}
	public static boolean isValidType(byte[] b, int off)
	{
		byte type=b[off];
		type&=~AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
		type&=~AbstractKey.IS_XDH_KEY;
		return type>=8 && type<=9;
	}
	public static ASymmetricKeyPair decode(byte[] b) throws IllegalArgumentException {
		return decode(b, true);
	}
	public static ASymmetricKeyPair decode(byte[] b, int off, int len) throws IllegalArgumentException {
		return decode(b, off, len,true);
	}
	public static ASymmetricKeyPair decode(byte[] b, boolean fillArrayWithZerosWhenDecoded) throws IllegalArgumentException {
		return decode(b, 0, b.length, fillArrayWithZerosWhenDecoded);
	}


	public static ASymmetricKeyPair decode(byte[] b, int off, int len, boolean fillArrayWithZerosWhenDecoded) throws IllegalArgumentException {
		if (off<0 || len<0 || len+off>b.length)
			throw new IllegalArgumentException();

		try {
			int codedTypeSize = SymmetricSecretKey.getEncodedTypeSize();
			int keySize = (int)(Bits.getPositiveInteger(b, 1+off, 3));
			int posKey=codedTypeSize+4+off;
			long expirationUTC;
			byte type=b[off];

			boolean includeKeyExpiration=(type & AbstractKey.INCLUDE_KEY_EXPIRATION_CODE) == AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
			boolean kdhKey=(type & AbstractKey.IS_XDH_KEY) == AbstractKey.IS_XDH_KEY;
			if (includeKeyExpiration)
				type-= AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
			if (kdhKey)
				type-= AbstractKey.IS_XDH_KEY;
			if (includeKeyExpiration) {

				expirationUTC=Bits.getLong(b, posKey);
				posKey += 8;
			}
			else
				expirationUTC=Long.MAX_VALUE;

			byte[] kp = new byte[len - 4 - codedTypeSize-(includeKeyExpiration?8:0)];
			System.arraycopy(b, posKey, kp, 0, kp.length);
			byte[][] keys = Bits.separateEncodingsWithShortIntSizedTabs(kp);

			if (type == 9) {
				ASymmetricAuthenticatedSignatureType type2 = ASymmetricAuthenticatedSignatureType.valueOf((int) Bits.getPositiveInteger(b, 4+off, codedTypeSize));

				ASymmetricKeyPair res=new ASymmetricKeyPair(type2, new ASymmetricPrivateKey(type2, keys[0], keySize),
						new ASymmetricPublicKey(type2, keys[1], keySize, expirationUTC), keySize);
				res.getASymmetricPublicKey().xdhKey=kdhKey;
				res.getASymmetricPrivateKey().xdhKey=kdhKey;
				return res;
			} else if (type == 8) {
				ASymmetricEncryptionType type2 = ASymmetricEncryptionType.valueOf((int) Bits.getPositiveInteger(b, 4+off, codedTypeSize));

				ASymmetricKeyPair res=new ASymmetricKeyPair(type2, new ASymmetricPrivateKey(type2, keys[0], keySize),
						new ASymmetricPublicKey(type2, keys[1], keySize, expirationUTC), keySize);
				res.getASymmetricPublicKey().xdhKey=kdhKey;
				res.getASymmetricPrivateKey().xdhKey=kdhKey;
				return res;
			} else {

				throw new IllegalArgumentException();
			}
		}
		catch (IllegalArgumentException e)
		{
			fillArrayWithZerosWhenDecoded=false;
			throw e;
		}
		finally {
			if (fillArrayWithZerosWhenDecoded)
				Arrays.fill(b, off, len, (byte)0);
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
			return privateKey.equals(other.privateKey) && publicKey.equals(other.publicKey) && keySizeBits == other.keySizeBits
					&& encryptionType == other.encryptionType && signatureType == other.signatureType;
		}
		return false;
	}

	@Override
	public long getTimeExpirationUTC() {
		return publicKey.getTimeExpirationUTC();
	}


	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}

	public ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() {
		return signatureType;
	}

	@Override
	public ASymmetricPrivateKey getASymmetricPrivateKey() {
		return privateKey;
	}

	@Override
	public ASymmetricPublicKey getASymmetricPublicKey() {
		return publicKey;
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
	public Object toGnuKeyPair()throws NoSuchAlgorithmException, InvalidKeySpecException
	{
		if (gnuKeyPair == null)
			gnuKeyPair = GnuFunctions.getKeyPairInstance(publicKey.toGnuKey(), privateKey.toGnuKey());

		return gnuKeyPair;
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
		if (nativeKeyPair == null)
			nativeKeyPair = new KeyPair(publicKey.toJavaNativeKey(), privateKey.toJavaNativeKey());

		return nativeKeyPair;
	}


	@Override
	public boolean isPostQuantumKey() {
		return encryptionType==null?signatureType.isPostQuantumAlgorithm():encryptionType.isPostQuantumAlgorithm();
	}

}
