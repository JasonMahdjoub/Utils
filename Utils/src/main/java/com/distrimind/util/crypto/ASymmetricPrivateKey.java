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
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Arrays;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.AsymmetricKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricECPrivateKey;
import org.bouncycastle.crypto.asymmetric.AsymmetricRSAPrivateKey;

import com.distrimind.util.Bits;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.7.1
 */
public class ASymmetricPrivateKey implements UtilKey {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1279365581082525690L;

	public static ASymmetricPrivateKey decode(byte[] b) {
		byte[][] res = Bits.separateEncodingsWithShortSizedTabs(b);
		if (res[0][6]==1)
			return new ASymmetricPrivateKey(ASymmetricEncryptionType.valueOf(Bits.getInt(res[0], 2)), res[1],
				Bits.getShort(res[0], 0));
		else if (res[0][6]==0)
			return new ASymmetricPrivateKey(ASymmetricAuthentifiedSignatureType.valueOf(Bits.getInt(res[0], 2)), res[1],
					Bits.getShort(res[0], 0));
		else throw new IllegalArgumentException();
	}

	public static ASymmetricPrivateKey valueOf(String key) throws IOException {
		return decode(Base64.decodeBase64(key));
	}

	// private final PrivateKey privateKey;
	private final byte[] privateKey;

	private final short keySize;

	private ASymmetricEncryptionType encryptionType;
	private ASymmetricAuthentifiedSignatureType signatureType;

	private final int hashCode;

	private volatile transient PrivateKey nativePrivateKey;

	private volatile transient gnu.vm.jgnu.security.PrivateKey gnuPrivateKey;

	ASymmetricPrivateKey(ASymmetricEncryptionType type, byte privateKey[], short keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPrivateKey(ASymmetricAuthentifiedSignatureType type, byte privateKey[], short keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type;
	}

	ASymmetricPrivateKey(ASymmetricEncryptionType type, gnu.vm.jgnu.security.PrivateKey privateKey, short keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPrivateKey(ASymmetricAuthentifiedSignatureType type, gnu.vm.jgnu.security.PrivateKey privateKey, short keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type;
	}

	ASymmetricPrivateKey(ASymmetricEncryptionType type, PrivateKey privateKey, short keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPrivateKey(ASymmetricAuthentifiedSignatureType type, PrivateKey privateKey, short keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = null;
		this.signatureType=type;
	}
	private ASymmetricPrivateKey(byte privateKey[], short keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.privateKey = privateKey;
		this.keySize = keySize;
		hashCode = Arrays.hashCode(privateKey);
	}

	private ASymmetricPrivateKey(gnu.vm.jgnu.security.PrivateKey privateKey, short keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.privateKey = ASymmetricEncryptionType.encodePrivateKey(privateKey);
		this.keySize = keySize;
		hashCode = Arrays.hashCode(this.privateKey);
	}

	private ASymmetricPrivateKey(PrivateKey privateKey, short keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		this.privateKey = ASymmetricEncryptionType.encodePrivateKey(privateKey);
		this.keySize = keySize;
		hashCode = Arrays.hashCode(this.privateKey);
	}

	public byte[] encode() {
		byte[] tab = new byte[7];
		Bits.putShort(tab, 0, keySize);
		Bits.putInt(tab, 2, encryptionType==null?signatureType.ordinal():encryptionType.ordinal());
		tab[6]=encryptionType==null?(byte)0:(byte)1;
		return Bits.concateEncodingWithShortSizedTabs(tab, privateKey);
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof ASymmetricPrivateKey) {
			ASymmetricPrivateKey other = (ASymmetricPrivateKey) o;
			return keySize == other.keySize && encryptionType == other.encryptionType && signatureType == other.signatureType && Arrays.equals(privateKey, other.privateKey);
		}
		return false;
	}

	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}
	public ASymmetricAuthentifiedSignatureType getAuthentifiedSignatureAlgorithmType() {
		return signatureType;
	}

	byte[] getBytesPrivateKey() {
		return privateKey;
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

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public gnu.vm.jgnu.security.PrivateKey toGnuKey()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		if (gnuPrivateKey == null)
			gnuPrivateKey = ASymmetricEncryptionType.decodeGnuPrivateKey(privateKey);

		return gnuPrivateKey;
	}

	@Override
	public PrivateKey toJavaNativeKey()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		if (nativePrivateKey == null)
			nativePrivateKey = ASymmetricEncryptionType.decodeNativePrivateKey(privateKey);

		return nativePrivateKey;
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
		PrivateKey pk=toJavaNativeKey();
		if (pk instanceof RSAPrivateKey)
		{
			RSAPrivateKey javaNativePrivateKey=(RSAPrivateKey)pk;
			AsymmetricRSAPrivateKey bcPK=new AsymmetricRSAPrivateKey(getBouncyCastleAlgorithm(), 
				javaNativePrivateKey.getModulus(), javaNativePrivateKey.getPrivateExponent());
			return bcPK;
		}
		else if (pk instanceof ECPrivateKey)
		{
			ECPrivateKey javaNativePrivateKey=(ECPrivateKey)pk;
			AsymmetricECPrivateKey bcPK=new AsymmetricECPrivateKey(getBouncyCastleAlgorithm(), javaNativePrivateKey.getEncoded());
			return bcPK;
		}
		else 
			throw new IllegalAccessError();
		
	}
}
