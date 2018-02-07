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
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPublicKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPublicKey;

import com.distrimind.util.Bits;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.7.1
 */
public class ASymmetricPublicKey implements UtilKey {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1279365581082525690L;

	public static ASymmetricPublicKey decode(byte[] b) {
		byte[][] res = Bits.separateEncodingsWithShortSizedTabs(b);
		if (res[0][14]==0)
			return new ASymmetricPublicKey(ASymmetricEncryptionType.valueOf(Bits.getInt(res[0], 2)), res[1],
				Bits.getShort(res[0], 0), Bits.getLong(b, 6));
		else if (res[0][14]==1)
			return new ASymmetricPublicKey(ASymmetricAuthentifiedSignatureType.valueOf(Bits.getInt(res[0], 2)), res[1],
					Bits.getShort(res[0], 0), Bits.getLong(b, 6));
		else throw new IllegalArgumentException();
	}

	public static ASymmetricPublicKey valueOf(String key) throws IOException {
		return decode(Base64.decodeBase64(key));
	}

	// private final PublicKey publicKey;
	private final byte[] publicKey;

	private final short keySize;

	private ASymmetricEncryptionType encryptionType;
	private ASymmetricAuthentifiedSignatureType signatureType;


	private final int hashCode;

	private final long expirationUTC;

	private volatile transient PublicKey nativePublicKey = null;

	private volatile transient gnu.vm.jgnu.security.PublicKey gnuPublicKey = null;

	ASymmetricPublicKey(ASymmetricEncryptionType type, byte[] publicKey, short keySize, long expirationUTC) {
		this(publicKey, keySize, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPublicKey(ASymmetricAuthentifiedSignatureType type, byte[] publicKey, short keySize, long expirationUTC) {
		this(publicKey, keySize, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type;
	}

	ASymmetricPublicKey(ASymmetricEncryptionType type, gnu.vm.jgnu.security.PublicKey publicKey, short keySize,
			long expirationUTC) {
		this(publicKey, keySize, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");

		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPublicKey(ASymmetricAuthentifiedSignatureType type, gnu.vm.jgnu.security.PublicKey publicKey, short keySize,
			long expirationUTC) {
		this(publicKey, keySize, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");

		this.encryptionType = null;
		this.signatureType=type;
	}

	ASymmetricPublicKey(ASymmetricEncryptionType type, PublicKey publicKey, short keySize, long expirationUTC) {
		this(publicKey, keySize, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();

		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPublicKey(ASymmetricAuthentifiedSignatureType type, PublicKey publicKey, short keySize, long expirationUTC) {
		this(publicKey, keySize, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();

		this.encryptionType = null;
		this.signatureType=type;
	}
	private ASymmetricPublicKey(byte[] publicKey, short keySize, long expirationUTC) {
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");

		this.publicKey = publicKey;
		this.keySize = keySize;
		hashCode = Arrays.hashCode(this.publicKey);
		this.expirationUTC = expirationUTC;
	}

	private ASymmetricPublicKey(gnu.vm.jgnu.security.PublicKey publicKey, short keySize,
			long expirationUTC) {
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");

		this.publicKey = ASymmetricEncryptionType.encodePublicKey(publicKey);
		this.keySize = keySize;
		hashCode = Arrays.hashCode(this.publicKey);
		this.expirationUTC = expirationUTC;
	}

	private ASymmetricPublicKey(PublicKey publicKey, short keySize, long expirationUTC) {
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");

		this.publicKey = ASymmetricEncryptionType.encodePublicKey(publicKey);
		this.keySize = keySize;
		hashCode = Arrays.hashCode(this.publicKey);
		this.expirationUTC = expirationUTC;
	}

	public byte[] encode() {
		byte[] tab = new byte[15];
		Bits.putShort(tab, 0, keySize);
		Bits.putInt(tab, 2, encryptionType==null?signatureType.ordinal():encryptionType.ordinal());
		Bits.putLong(tab, 6, expirationUTC);
		tab[14]=encryptionType==null?(byte)1:(byte)0;
		return Bits.concateEncodingWithShortSizedTabs(tab, publicKey);
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof ASymmetricPublicKey) {

			ASymmetricPublicKey other = (ASymmetricPublicKey) o;
			return keySize == other.keySize && encryptionType == other.encryptionType && signatureType == other.signatureType && Arrays.equals(publicKey, other.publicKey);
		}
		return false;
	}

	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}
	public ASymmetricAuthentifiedSignatureType getAuthentifiedSignatureAlgorithmType() {
		return signatureType;
	}

	byte[] getBytesPublicKey() {
		return publicKey;
	}

	public short getKeySize() {
		return keySize;
	}

	public int getMaxBlockSize() {
		if (encryptionType==null)
			throw new IllegalAccessError("This key should be used for signature");
		else
			return encryptionType.getMaxBlockSize(keySize);
	}

	public long getTimeExpirationUTC() {
		return expirationUTC;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public gnu.vm.jgnu.security.PublicKey toGnuKey()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		if (gnuPublicKey == null)
			gnuPublicKey = ASymmetricEncryptionType.decodeGnuPublicKey(publicKey);

		return gnuPublicKey;
	}

	@Override
	public PublicKey toJavaNativeKey()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		if (nativePublicKey == null)
			nativePublicKey = ASymmetricEncryptionType.decodeNativePublicKey(publicKey);

		return nativePublicKey;
	}

	@Override
	public String toString() {
		return Base64.encodeBase64URLSafeString(encode());
	}

	Algorithm getBouncyCastleAlgorithm()
	{
		if (encryptionType==null)
			return signatureType.getBouncyCastleAlgorithm();
		else
			return encryptionType.getBouncyCastleAlgorithm();
					
	}
	
	@Override
	public AsymmetricKey toBouncyCastleKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		PublicKey pk=toJavaNativeKey();
		if (pk instanceof RSAPublicKey)
		{
			RSAPublicKey javaNativePublicKey=(RSAPublicKey)pk;
			AsymmetricRSAPublicKey bcPK=new AsymmetricRSAPublicKey(
				getBouncyCastleAlgorithm(), 
				javaNativePublicKey.getModulus(), javaNativePublicKey.getPublicExponent());
			return bcPK;
		}
		else if (pk instanceof ECPublicKey)
		{
			ECPublicKey javaNativePublicKey=(ECPublicKey)pk;
			AsymmetricECPublicKey bcPK=new AsymmetricECPublicKey(getBouncyCastleAlgorithm(), javaNativePublicKey.getEncoded());
			return bcPK;
		}
		else
			throw new IllegalAccessError();
		
	}

}
