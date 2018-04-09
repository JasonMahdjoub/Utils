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
import java.io.Serializable;
import java.security.KeyPair;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.1
 * @since Utils 1.7.1
 */
public class ASymmetricKeyPair implements Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = -8249147431069134363L;

	public static ASymmetricKeyPair decode(byte[] b) throws IllegalArgumentException {
			byte[][] res1 = Bits.separateEncodingsWithIntSizedTabs(b);
			byte[][] res2 = Bits.separateEncodingsWithShortSizedTabs(res1[0]);
			
			short keySize = Bits.getShort(res2[0], 0);
			long expirationUTC = Bits.getLong(res2[0], 6);
			
			if (res2[0][14]==1)
			{
				ASymmetricAuthentifiedSignatureType type = ASymmetricAuthentifiedSignatureType.valueOf(Bits.getInt(res2[0], 2));
				
				return new ASymmetricKeyPair(type, new ASymmetricPrivateKey(type, res1[1], keySize),
					new ASymmetricPublicKey(type, res2[1], keySize, expirationUTC), keySize);
			}
			else
			{
				ASymmetricEncryptionType type = ASymmetricEncryptionType.valueOf(Bits.getInt(res2[0], 2));
			
				return new ASymmetricKeyPair(type, new ASymmetricPrivateKey(type, res1[1], keySize),
					new ASymmetricPublicKey(type, res2[1], keySize, expirationUTC), keySize);
			}
	}

	public static ASymmetricKeyPair valueOf(String key) throws IllegalArgumentException, IOException {
		return decode(Base64.decodeBase64(key));
	}

	private ASymmetricPrivateKey privateKey;

	private ASymmetricPublicKey publicKey;

	private final short keySizeBits;

	private final ASymmetricEncryptionType encryptionType;
	private final ASymmetricAuthentifiedSignatureType signatureType;

	private final int hashCode;

	private transient volatile KeyPair nativeKeyPair;

	private transient volatile gnu.vm.jgnu.security.KeyPair gnuKeyPair;

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
			Arrays.fill(gnuKeyPair.getPublic().getEncoded(), (byte)0);
			Arrays.fill(gnuKeyPair.getPrivate().getEncoded(), (byte)0);
			gnuKeyPair=null;
		}
	}
	
	@Override public void finalize()
	{
		zeroize();
	}
	
	ASymmetricKeyPair(ASymmetricEncryptionType type, ASymmetricPrivateKey privateKey, ASymmetricPublicKey publicKey,
			short keySize) {
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

	ASymmetricKeyPair(ASymmetricEncryptionType type, gnu.vm.jgnu.security.KeyPair keyPair, short keySize,
			long expirationUTC) {
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
		this.gnuKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricEncryptionType type, KeyPair keyPair, short keySize, long expirationUTC) {
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

	ASymmetricKeyPair(ASymmetricAuthentifiedSignatureType type, ASymmetricPrivateKey privateKey, ASymmetricPublicKey publicKey,
			short keySize) {
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

	ASymmetricKeyPair(ASymmetricAuthentifiedSignatureType type, gnu.vm.jgnu.security.KeyPair keyPair, short keySize,
			long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(), keySize);
		publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
		this.gnuKeyPair=keyPair;
	}

	ASymmetricKeyPair(ASymmetricAuthentifiedSignatureType type, KeyPair keyPair, short keySize, long expirationUTC) {
		if (type == null)
			throw new NullPointerException("type");
		if (keyPair == null)
			throw new NullPointerException("keyPair");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(), keySize);
		publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize, expirationUTC);
		this.keySizeBits = keySize;
		this.encryptionType = null;
		this.signatureType=type;

		hashCode = privateKey.hashCode() + publicKey.hashCode();
		this.nativeKeyPair=keyPair;
	}
	
	
	public byte[] encode() {
		byte[] tab = new byte[15];
		Bits.putShort(tab, 0, keySizeBits);
		Bits.putInt(tab, 2, encryptionType==null?signatureType.ordinal():encryptionType.ordinal());
		Bits.putLong(tab, 6, publicKey.getTimeExpirationUTC());
		tab[14]=encryptionType==null?(byte)1:(byte)0;
		return Bits.concateEncodingWithIntSizedTabs(
				Bits.concateEncodingWithShortSizedTabs(tab, publicKey.getBytesPublicKey()),
				privateKey.getBytesPrivateKey());
		// return Bits.concateEncodingWithShortSizedTabs(tab,
		// ASymmetricEncryptionType.encodeKeyPair(toGnuKeyPair()));
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

	public long getTimeExpirationUTC() {
		return publicKey.getTimeExpirationUTC();
	}

	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}
	public ASymmetricAuthentifiedSignatureType getAuthentifiedSignatureAlgorithmType() {
		return signatureType;
	}

	public ASymmetricPrivateKey getASymmetricPrivateKey() {
		return privateKey;
	}

	public ASymmetricPublicKey getASymmetricPublicKey() {
		return publicKey;
	}

	public short getKeySizeBits() {
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

	public gnu.vm.jgnu.security.KeyPair toGnuKeyPair()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		if (gnuKeyPair == null)
			gnuKeyPair = new gnu.vm.jgnu.security.KeyPair(publicKey.toGnuKey(), privateKey.toGnuKey());

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

	public KeyPair toJavaNativeKeyPair()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		if (nativeKeyPair == null)
			nativeKeyPair = new KeyPair(publicKey.toJavaNativeKey(), privateKey.toJavaNativeKey());

		return nativeKeyPair;
	}

	@Override
	public String toString() {
		try {
			return Base64.encodeBase64URLSafeString(encode());
		} catch (Exception e) {
			return e.toString();
		}
	}

}
