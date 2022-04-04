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

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.AsymmetricKey;
import com.distrimind.bcfips.crypto.AsymmetricPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricECPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricRSAPrivateKey;
import com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PrivateKey;
import com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePrivateKey;
import com.distrimind.util.Bits;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedSecretString;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.util.io.RandomByteArrayInputStream;

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

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE;

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;

	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY = MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;

	private static final int MAX_SIZE_IN_BITS_OF_NON_HYBRID_PRIVATE_KEY=MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY*8;
	private static final class Finalizer extends Cleaner
	{
		private byte[] privateKey;
		private volatile transient PrivateKey nativePrivateKey=null;

		private volatile transient Object gnuPrivateKey=null;
		private volatile transient AsymmetricPrivateKey bouncyCastlePrivateKey=null;
		@Override
		protected void performCleanup() {
			if (privateKey!=null)
			{
				Arrays.fill(privateKey, (byte)0);
				privateKey=null;
			}
			if (nativePrivateKey!=null)
			{
				if (!nativePrivateKey.isDestroyed()) {
					Arrays.fill(nativePrivateKey.getEncoded(), (byte) 0);
				}
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
					((BCMcElieceCipher.PrivateKey) bouncyCastlePrivateKey).clean();
				else if (bouncyCastlePrivateKey instanceof BCMcElieceCipher.PrivateKeyCCA2)
					((BCMcElieceCipher.PrivateKeyCCA2) bouncyCastlePrivateKey).clean();
				bouncyCastlePrivateKey=null;
			}
		}
	}


	private final Finalizer finalizer;
	private final int keySizeBits;

	private ASymmetricEncryptionType encryptionType;
	private ASymmetricAuthenticatedSignatureType signatureType;

	private final int hashCode;


	boolean xdhKey=false;

    @Override
	public WrappedSecretData getKeyBytes() {
		checkNotDestroyed();
        return new WrappedSecretData(finalizer.privateKey.clone());
    }

	@Override
	public boolean isPostQuantumKey() {
		return encryptionType==null?signatureType.isPostQuantumAlgorithm():encryptionType.isPostQuantumAlgorithm();
	}
	private void checkNotDestroyed()
	{
		if (isCleaned())
			throw new IllegalAccessError();
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
		this.finalizer.bouncyCastlePrivateKey=privateKey;
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
		checkNotDestroyed();
		if (signatureType==null)
			return new ASymmetricPrivateKey(encryptionType, finalizer.privateKey.clone(), keySizeBits);
		else
			return new ASymmetricPrivateKey(signatureType, finalizer.privateKey.clone(), keySizeBits);
	}

	private ASymmetricPrivateKey(byte[] privateKey, int keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		if (keySize>MAX_SIZE_IN_BITS_OF_NON_HYBRID_PRIVATE_KEY)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer();
		this.finalizer.privateKey = privateKey;
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(privateKey);
		registerCleaner(finalizer);
	}

	private ASymmetricPrivateKey(Object privateKey, int keySize) {
		if (privateKey == null)
			throw new NullPointerException("privateKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		if (keySize>MAX_SIZE_IN_BITS_OF_NON_HYBRID_PRIVATE_KEY)
			throw new IllegalArgumentException("keySize");
		this.finalizer=new Finalizer();
		this.finalizer.privateKey = ASymmetricEncryptionType.encodeGnuPrivateKey(privateKey);
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(this.finalizer.privateKey);
		this.finalizer.gnuPrivateKey=null;
		registerCleaner(finalizer);
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
	public WrappedSecretData encode()
	{
		checkNotDestroyed();
		byte[] tab = new byte[4+ENCODED_TYPE_SIZE+finalizer.privateKey.length];
		tab[0]=encryptionType==null?(byte)((xdhKey? AbstractKey.IS_XDH_KEY:0)|2):(byte)3;
		Bits.putUnsignedInt(tab, 1, keySizeBits, 3);
		Bits.putUnsignedInt(tab, 4, encryptionType==null?signatureType.ordinal():encryptionType.ordinal(), ENCODED_TYPE_SIZE);
        System.arraycopy(finalizer.privateKey, 0, tab, ENCODED_TYPE_SIZE+4, finalizer.privateKey.length);
        return new WrappedSecretData(tab);
	}

	@Override
	public WrappedSecretString encodeString() {
		return new WrappedSecretString(encode());
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof ASymmetricPrivateKey) {
			ASymmetricPrivateKey other = (ASymmetricPrivateKey) o;
			boolean b=com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(finalizer.privateKey, other.finalizer.privateKey);
			b=keySizeBits == other.keySizeBits && b;
			b=encryptionType == other.encryptionType && b;
			b=signatureType == other.signatureType && b;
			return b;
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
		checkNotDestroyed();
		return finalizer.privateKey;
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
		checkNotDestroyed();
		if (finalizer.gnuPrivateKey == null)
			finalizer.gnuPrivateKey = ASymmetricEncryptionType.decodeGnuPrivateKey(finalizer.privateKey, encryptionType==null?signatureType.getKeyGeneratorAlgorithmName():encryptionType.getAlgorithmName());

		return finalizer.gnuPrivateKey;
	}

	@Override
	public PrivateKey toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		checkNotDestroyed();
		if (encryptionType!=null && encryptionType.name().startsWith("BCPQC_MCELIECE_"))
		{
			AsymmetricKey bk=toBouncyCastleKey();
			if (bk instanceof BCMcElieceCipher.PrivateKeyCCA2)
				finalizer.nativePrivateKey= new BCMcElieceCCA2PrivateKey(((BCMcElieceCipher.PrivateKeyCCA2)bk).getPrivateKeyParameters());
			else
				finalizer.nativePrivateKey= new BCMcEliecePrivateKey(((BCMcElieceCipher.PrivateKey)bk).getPrivateKeyParameters());
		}
		else
			if (finalizer.nativePrivateKey == null)
				finalizer.nativePrivateKey = ASymmetricEncryptionType.decodeNativePrivateKey(finalizer.privateKey, encryptionType==null?signatureType.getKeyGeneratorAlgorithmName():encryptionType.getAlgorithmName(),
					encryptionType==null?signatureType.name():encryptionType.name(), xdhKey);

		return finalizer.nativePrivateKey;
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
		checkNotDestroyed();
		if (encryptionType!=null && encryptionType.name().startsWith("BCPQC_MCELIECE_"))
		{
			if (finalizer.bouncyCastlePrivateKey==null) {
				if (encryptionType.name().contains("CCA2")) {
					BCMcElieceCipher.PrivateKeyCCA2 res = new BCMcElieceCipher.PrivateKeyCCA2();
					try {
						res.readExternal(new RandomByteArrayInputStream(this.finalizer.privateKey), encryptionType);
						finalizer.bouncyCastlePrivateKey=res;
					} catch (IOException e) {
						throw new InvalidKeySpecException(e);
					}
				} else {
					BCMcElieceCipher.PrivateKey res = new BCMcElieceCipher.PrivateKey();
					try {
						res.readExternal(new RandomByteArrayInputStream(this.finalizer.privateKey));
						finalizer.bouncyCastlePrivateKey=res;
					} catch (IOException e) {
						throw new InvalidKeySpecException(e);
					}
				}
			}
			return finalizer.bouncyCastlePrivateKey;
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
		checkNotDestroyed();
		return this;
	}
}
