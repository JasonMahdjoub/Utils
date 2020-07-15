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
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.util.io.RandomByteArrayInputStream;
import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricKey;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricECPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricRSAPrivateKey;
import com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePrivateKey;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7.1
 */
public class ASymmetricPrivateKey extends AbstractKey implements IASymmetricPrivateKey {
	/**
	 * 
	 */
	private static final long serialVersionUID = 1279365581082525690L;


	// private final PrivateKey privateKey;
	public static final int MAX_KEY_SIZE_BITS=1<<24-1;
	private byte[] privateKey;

	private final int keySizeBits;

	private ASymmetricEncryptionType encryptionType;
	private ASymmetricAuthenticatedSignatureType signatureType;

	private final int hashCode;

	private volatile transient PrivateKey nativePrivateKey=null;

	private volatile transient Object gnuPrivateKey=null;
	private volatile transient AsymmetricPrivateKey bouncyCastlePrivateKey=null;
	boolean xdhKey=false;

	
	@Override
	public void zeroize()
	{
		if (privateKey!=null)
		{
			Arrays.fill(privateKey, (byte)0);
			privateKey=null;
		}
		if (nativePrivateKey!=null)
		{
			Arrays.fill(nativePrivateKey.getEncoded(), (byte)0);
			nativePrivateKey=null;
		}
		if (gnuPrivateKey!=null)
		{
			Arrays.fill(GnuFunctions.keyGetEncoded(gnuPrivateKey), (byte)0);
			gnuPrivateKey=null;
		}
		if (bouncyCastlePrivateKey==null)
		{
			if (bouncyCastlePrivateKey instanceof BCMcElieceCipher.PrivateKey)
				((BCMcElieceCipher.PrivateKey) bouncyCastlePrivateKey).zeroize();
			else if (bouncyCastlePrivateKey instanceof BCMcElieceCipher.PrivateKeyCCA2)
				((BCMcElieceCipher.PrivateKeyCCA2) bouncyCastlePrivateKey).zeroize();
			bouncyCastlePrivateKey=null;
		}
	}



    @Override
	public byte[] getKeyBytes() {
        return privateKey;
    }

	@Override
	public boolean isPostQuantumKey() {
		return encryptionType==null?signatureType.isPostQuantumAlgorithm():encryptionType.isPostQuantumAlgorithm();
	}

	ASymmetricPrivateKey(ASymmetricEncryptionType type, byte[] privateKey, int keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPrivateKey(ASymmetricAuthenticatedSignatureType type, byte[] privateKey, int keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type;
	}

	ASymmetricPrivateKey(ASymmetricEncryptionType type, Object privateKey, int keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type;
		this.signatureType=null;
		
	}
	ASymmetricPrivateKey(ASymmetricAuthenticatedSignatureType type, Object privateKey, int keySize) {
		this(privateKey, keySize);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type;
	}

	ASymmetricPrivateKey(ASymmetricEncryptionType type, PrivateKey privateKey, int keySize) {
		this(ASymmetricEncryptionType.encodePrivateKey(privateKey, type), keySize);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = type;
		this.signatureType=null;
	}
	ASymmetricPrivateKey(ASymmetricEncryptionType type, AsymmetricPrivateKey privateKey, int keySize) {
		this(privateKey.getEncoded(), keySize);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = type;
		this.signatureType=null;
		this.bouncyCastlePrivateKey=privateKey;
	}
	ASymmetricPrivateKey(ASymmetricAuthenticatedSignatureType type, PrivateKey privateKey, int keySize, boolean xdhKey) {
		this(ASymmetricEncryptionType.encodePrivateKey(privateKey, type, xdhKey), keySize);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();
		this.encryptionType = null;
		this.signatureType=type;
		this.xdhKey=xdhKey;
	}

	ASymmetricPrivateKey getNewClonedPrivateKey()
	{
		if (signatureType==null)
			return new ASymmetricPrivateKey(encryptionType, privateKey.clone(), keySizeBits);
		else
			return new ASymmetricPrivateKey(signatureType, privateKey.clone(), keySizeBits);
	}

	private ASymmetricPrivateKey(byte[] privateKey, int keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		if (keySize>MAX_KEY_SIZE_BITS)
			throw new IllegalArgumentException("keySize");
		this.privateKey = privateKey;
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(privateKey);
	}

	private ASymmetricPrivateKey(Object privateKey, int keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		if (keySize>MAX_KEY_SIZE_BITS)
			throw new IllegalArgumentException("keySize");
		this.privateKey = ASymmetricEncryptionType.encodeGnuPrivateKey(privateKey);
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(this.privateKey);
		this.gnuPrivateKey=null;
	}


	public static final int ENCODED_TYPE_SIZE;
	static
	{
		int max=Math.max(ASymmetricEncryptionType.values().length, ASymmetricAuthenticatedSignatureType.values().length);
		if (max<=0xFF)
			ENCODED_TYPE_SIZE=1;
		else if (max<=0xFFFF)
			ENCODED_TYPE_SIZE=2;
		else if (max<=0xFFFFFF)
			ENCODED_TYPE_SIZE=3;
		else
			ENCODED_TYPE_SIZE=4;

	}

	@Override
	public byte[] encode()
	{
		byte[] tab = new byte[4+ENCODED_TYPE_SIZE+privateKey.length];
		tab[0]=encryptionType==null?(byte)((xdhKey? AbstractKey.IS_XDH_KEY:0)|2):(byte)3;
		Bits.putPositiveInteger(tab, 1, keySizeBits, 3);
		Bits.putPositiveInteger(tab, 4, encryptionType==null?signatureType.ordinal():encryptionType.ordinal(), ENCODED_TYPE_SIZE);
        System.arraycopy(privateKey, 0, tab, ENCODED_TYPE_SIZE+4, privateKey.length);
        return tab;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof ASymmetricPrivateKey) {
			ASymmetricPrivateKey other = (ASymmetricPrivateKey) o;
			return keySizeBits == other.keySizeBits && encryptionType == other.encryptionType && signatureType == other.signatureType && Arrays.equals(privateKey, other.privateKey);
		}
		return false;
	}


	public ASymmetricEncryptionType getEncryptionAlgorithmType() {
		return encryptionType;
	}

	public ASymmetricAuthenticatedSignatureType getAuthenticatedSignatureAlgorithmType() {
		return signatureType;
	}

	byte[] getBytesPrivateKey() {
		return privateKey;
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
	public Object toGnuKey() throws NoSuchAlgorithmException, MessageExternalizationException {
		if (gnuPrivateKey == null)
			gnuPrivateKey = ASymmetricEncryptionType.decodeGnuPrivateKey(privateKey, encryptionType==null?signatureType.getKeyGeneratorAlgorithmName():encryptionType.getAlgorithmName());

		return gnuPrivateKey;
	}

	@Override
	public PrivateKey toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		if (encryptionType!=null && encryptionType.name().startsWith("BCPQC_MCELIECE_"))
		{
			AsymmetricKey bk=toBouncyCastleKey();
			if (bk instanceof BCMcElieceCipher.PrivateKeyCCA2)
				nativePrivateKey= new BCMcElieceCCA2PrivateKey(((BCMcElieceCipher.PrivateKeyCCA2)bk).getPrivateKeyParameters());
			else
				nativePrivateKey= new BCMcEliecePrivateKey(((BCMcElieceCipher.PrivateKey)bk).getPrivateKeyParameters());
		}
		else
			if (nativePrivateKey == null)
				nativePrivateKey = ASymmetricEncryptionType.decodeNativePrivateKey(privateKey, encryptionType==null?signatureType.getKeyGeneratorAlgorithmName():encryptionType.getAlgorithmName(),
					encryptionType==null?signatureType.name():encryptionType.name(), xdhKey);

		return nativePrivateKey;
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
		if (encryptionType!=null && encryptionType.name().startsWith("BCPQC_MCELIECE_"))
		{
			if (bouncyCastlePrivateKey==null) {
				if (encryptionType.name().contains("CCA2")) {
					BCMcElieceCipher.PrivateKeyCCA2 res = new BCMcElieceCipher.PrivateKeyCCA2();
					try {
						res.readExternal(new RandomByteArrayInputStream(this.privateKey), encryptionType);
						bouncyCastlePrivateKey=res;
					} catch (IOException e) {
						throw new InvalidKeySpecException(e);
					}
				} else {
					BCMcElieceCipher.PrivateKey res = new BCMcElieceCipher.PrivateKey();
					try {
						res.readExternal(new RandomByteArrayInputStream(this.privateKey));
						bouncyCastlePrivateKey=res;
					} catch (IOException e) {
						throw new InvalidKeySpecException(e);
					}
				}
			}
			return bouncyCastlePrivateKey;
		}
		else {
			PrivateKey pk = toJavaNativeKey();
			if (pk instanceof RSAPrivateKey) {
				RSAPrivateKey javaNativePrivateKey = (RSAPrivateKey) pk;
				return new AsymmetricRSAPrivateKey(getBouncyCastleAlgorithm(),
						javaNativePrivateKey.getModulus(), javaNativePrivateKey.getPrivateExponent());

			} else if (pk instanceof ECPrivateKey) {
				ECPrivateKey javaNativePrivateKey = (ECPrivateKey) pk;
				return new AsymmetricECPrivateKey(getBouncyCastleAlgorithm(), javaNativePrivateKey.getEncoded());
			} else
				throw new IllegalAccessError(pk.getClass().toString());
		}
		
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
	public ASymmetricPrivateKey getNonPQCPrivateKey() {
		return this;
	}
}
