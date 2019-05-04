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

import java.util.Arrays;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.Algorithm;


import com.distrimind.util.Bits;



/**
 * 
 * @author Jason Mahdjoub
 * @version 2.3
 * @since Utils 1.7.1
 */
public class SymmetricSecretKey extends Key {

	/**
	 * 
	 */
	private static final long serialVersionUID = -1811177031909192919L;

	

	private byte[] secretKey;

	private final short keySizeBits;

	private SymmetricEncryptionType encryptionType;
	private SymmetricAuthentifiedSignatureType signatureType;

	private final int hashCode;

	private transient SecretKey javaNativeSecretKey = null;

	private transient gnu.vm.jgnux.crypto.SecretKey gnuSecretKey = null;
	
	private transient org.bouncycastle.crypto.SymmetricSecretKey bcfipsNativeSecretKey=null;

	@Override
	public void zeroize()
	{
		if (secretKey!=null)
		{
			Arrays.fill(secretKey, (byte)0);
			secretKey=null;
		}
		if (javaNativeSecretKey!=null)
		{
			Arrays.fill(javaNativeSecretKey.getEncoded(), (byte)0);
			javaNativeSecretKey=null;
		}
		if (gnuSecretKey!=null)
		{
			Arrays.fill(gnuSecretKey.getEncoded(), (byte)0);
			gnuSecretKey=null;
		}
		if (bcfipsNativeSecretKey!=null)
		{
			Arrays.fill(bcfipsNativeSecretKey.getKeyBytes(), (byte)0);
			bcfipsNativeSecretKey=null;
		}
	}
	
	
	SymmetricSecretKey(SymmetricEncryptionType type, byte[] secretKey, short keySize) {
		this(secretKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type;
		this.signatureType=null;
		//Arrays.fill(secretKey, (byte)0);
	}
	SymmetricSecretKey(SymmetricEncryptionType type, byte[] secretKey) {
		if (type == null)
			throw new NullPointerException("type");
		if (secretKey == null)
			throw new NullPointerException("secretKey");
		this.secretKey=secretKey.clone();
		switch (type.getAlgorithmName().toUpperCase()) {
			case "DES":
				this.keySizeBits = 56;
				break;
			case "DESEDE":
				this.keySizeBits = 168;
				break;
			default:
				this.keySizeBits = (short) (secretKey.length * 8);
				break;
		}
		this.encryptionType = type;
		this.signatureType=null;
		hashCode = Arrays.hashCode(this.secretKey);
		Arrays.fill(secretKey, (byte)0);
	}
	SymmetricSecretKey(SymmetricAuthentifiedSignatureType type, byte[] secretKey, short keySize) {
		this(secretKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type;
		//Arrays.fill(secretKey, (byte)0);
	}
	SymmetricSecretKey(SymmetricAuthentifiedSignatureType type, byte[] secretKey) {
		if (type == null)
			throw new NullPointerException("type");
		if (secretKey == null)
			throw new NullPointerException("secretKey");
		this.secretKey=secretKey.clone();
		this.keySizeBits=(short)(secretKey.length*8);
		this.encryptionType = null;
		this.signatureType=type;
		hashCode = Arrays.hashCode(this.secretKey);
		Arrays.fill(secretKey, (byte)0);
	}
	SymmetricSecretKey(SymmetricEncryptionType type, gnu.vm.jgnux.crypto.SecretKey secretKey, short keySize) {
		this(SymmetricEncryptionType.encodeSecretKey(secretKey, type.getAlgorithmName()), keySize);
		if (type.getCodeProviderForEncryption() != CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = type;
		this.signatureType=null;
		this.gnuSecretKey=secretKey;
	}
	
	
	SymmetricSecretKey(SymmetricAuthentifiedSignatureType type, gnu.vm.jgnux.crypto.SecretKey secretKey, short keySize) {
		this(SymmetricEncryptionType.encodeSecretKey(secretKey, type.getAlgorithmName()), keySize);
		if (type.getCodeProviderForSignature() != CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = null;
		this.signatureType=type;
		this.gnuSecretKey=secretKey;
	}

	SymmetricSecretKey(SymmetricEncryptionType type, SecretKey secretKey, short keySize) {
		this(SymmetricEncryptionType.encodeSecretKey(secretKey, type.getAlgorithmName()), keySize);
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = type;
		this.signatureType=null;
		this.javaNativeSecretKey=secretKey;
	}
	SymmetricSecretKey(SymmetricAuthentifiedSignatureType type, SecretKey secretKey, short keySize) {
		this(SymmetricEncryptionType.encodeSecretKey(secretKey, type.getAlgorithmName()), keySize);
		if (type.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = null;
		this.signatureType=type;
		this.javaNativeSecretKey=secretKey;
	}
	
	SymmetricSecretKey(SymmetricEncryptionType type, org.bouncycastle.crypto.SymmetricSecretKey secretKey, short keySize) {
		this(SymmetricEncryptionType.encodeSecretKey(secretKey, type.getAlgorithmName()), keySize);
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = type;
		this.signatureType=null;
		
		this.bcfipsNativeSecretKey=new org.bouncycastle.crypto.SymmetricSecretKey(getBouncyCastleAlgorithm(), secretKey.getKeyBytes());
	}
	
	SymmetricSecretKey(SymmetricAuthentifiedSignatureType type, org.bouncycastle.crypto.SymmetricSecretKey secretKey, short keySize) {
		this(SymmetricEncryptionType.encodeSecretKey(secretKey, type.getAlgorithmName()), keySize);
		if (type.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = null;
		this.signatureType=type;
		this.bcfipsNativeSecretKey=new org.bouncycastle.crypto.SymmetricSecretKey(getBouncyCastleAlgorithm(), secretKey.getKeyBytes());
	}
	
	private SymmetricSecretKey(byte[] secretKey, short keySize) {
		if (secretKey == null)
			throw new NullPointerException("secretKey");
		this.secretKey = secretKey;
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(this.secretKey);
	}
    static int getEncodedTypeSize()
	{
		int max=Math.max(SymmetricEncryptionType.values().length, SymmetricAuthentifiedSignatureType.values().length);
		if (max<=0xFF)
			return 1;
		else if (max<=0xFFFF)
			return 2;
        else if (max<=0xFFFFFF)
            return 3;
        else
			return 4;
	}
    static int encodeKeySizeBits(short keySizeBits)
    {
        return (keySizeBits-56)/8;
    }

    static short decodeKeySizeBits(int encodedKeySizeBits)
    {
        return (short)(encodedKeySizeBits*8+56);
    }

    static int maxKeySizeBits(int usedBitsForEncoding)
    {
        return decodeKeySizeBits((1<<usedBitsForEncoding)-1);
    }

	@Override
	public byte[] encode(boolean includeTimeExpiration) {
		return encode();
	}

	public byte[] encode() {
	    int codedTypeSize=getEncodedTypeSize();
		byte[] tab = new byte[2+codedTypeSize+secretKey.length];
		if (keySizeBits<56)
		    throw new InternalError();
        if (keySizeBits>maxKeySizeBits(8))
            throw new InternalError();
		tab[0]=encryptionType==null?(byte)1:(byte)0;
		Bits.putPositiveInteger(tab, 1, encryptionType==null?signatureType.ordinal():encryptionType.ordinal(), codedTypeSize);
        tab[codedTypeSize+1]=(byte)encodeKeySizeBits(keySizeBits);
        System.arraycopy(secretKey, 0, tab, codedTypeSize+2, secretKey.length);
        return tab;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof SymmetricSecretKey) {
			SymmetricSecretKey other = ((SymmetricSecretKey) o);
			return Arrays.equals(secretKey, other.secretKey) && encryptionType == other.encryptionType && signatureType == other.signatureType;
		}
		return false;
	}

	public SymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}
	public SymmetricAuthentifiedSignatureType getAuthentifiedSignatureAlgorithmType() {
		return signatureType;
	}

	public short getKeySizeBits() {
		return keySizeBits;
	}

	public int getMaxBlockSize() {
		return Integer.MAX_VALUE;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public gnu.vm.jgnux.crypto.SecretKey toGnuKey() {
		if (gnuSecretKey == null)
			gnuSecretKey = SymmetricEncryptionType.decodeGnuSecretKey(secretKey, encryptionType==null?signatureType.getAlgorithmName():encryptionType.getAlgorithmName());

		return gnuSecretKey;
	}

	@Override
	public SecretKey toJavaNativeKey() {
		if (javaNativeSecretKey == null)
			javaNativeSecretKey = SymmetricEncryptionType.decodeNativeSecretKey(secretKey, encryptionType==null?signatureType.getAlgorithmName():encryptionType.getAlgorithmName());

		return javaNativeSecretKey;
	}

	@Override
    byte[] getKeyBytes()
	{
		return secretKey;
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
	public org.bouncycastle.crypto.SymmetricSecretKey toBouncyCastleKey() {
		
		if (bcfipsNativeSecretKey == null)
			bcfipsNativeSecretKey = SymmetricEncryptionType.decodeBCSecretKey(getBouncyCastleAlgorithm(), secretKey);
		
		return bcfipsNativeSecretKey;
		
	}

	/*
	 * public static SymmetricSecretKey generate(SecureRandom random,
	 * SymmetricEncryptionType type) throws NoSuchAlgorithmException { return new
	 * SymmetricSecretKey(type, type.getKeyGenerator(random).generateKey()); }
	 * 
	 * public static SymmetricSecretKey generate(SecureRandom random) throws
	 * NoSuchAlgorithmException { return new
	 * SymmetricSecretKey(SymmetricEncryptionType.DEFAULT,
	 * SymmetricEncryptionType.DEFAULT.getKeyGenerator(random).generateKey()); }
	 */
}
