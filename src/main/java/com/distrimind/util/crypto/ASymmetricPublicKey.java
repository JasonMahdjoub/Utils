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
import com.distrimind.bcfips.crypto.AsymmetricPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricECPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricRSAPublicKey;
import com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece.BCMcElieceCCA2PublicKey;
import com.distrimind.bouncycastle.pqc.jcajce.provider.mceliece.BCMcEliecePublicKey;
import com.distrimind.util.Bits;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedString;
import com.distrimind.util.io.RandomByteArrayInputStream;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


/**
 * 
 * @author Jason Mahdjoub
 * @version 6.0
 * @since Utils 1.7.1
 */
public class ASymmetricPublicKey extends AbstractKey implements IASymmetricPublicKey {

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE =ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION =ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION = ASymmetricEncryptionType.MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;

	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY = MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;
	private static final int MAX_SIZE_IN_BITS_OF_NON_HYBRID_PUBLIC_KEY = MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY*8;


	// private final PublicKey publicKey;
	private byte[] publicKey;

	private final int keySizeBits;

	private ASymmetricEncryptionType encryptionType;
	private ASymmetricAuthenticatedSignatureType signatureType;


	private final int hashCode;

	private final long expirationUTC;

	public final long publicKeyValidityBeginDateUTC;

	private volatile transient PublicKey nativePublicKey = null;

	private volatile transient Object gnuPublicKey = null;

	private volatile transient AsymmetricPublicKey bouncyCastlePublicKey=null;


	boolean xdhKey=false;

	@Override
	public void clean()
	{
		if (publicKey!=null)
		{
			Arrays.fill(publicKey, (byte)0);
			publicKey=null;
		}
		if (nativePublicKey!=null)
		{
			Arrays.fill(nativePublicKey.getEncoded(), (byte)0);
			nativePublicKey=null;
		}
		if (nativePublicKey!=null)
		{
			Arrays.fill(GnuFunctions.keyGetEncoded(gnuPublicKey), (byte)0);
			gnuPublicKey=null;
		}
		if (bouncyCastlePublicKey==null)
		{
			if (bouncyCastlePublicKey instanceof BCMcElieceCipher.PublicKey)
				((BCMcElieceCipher.PublicKey) bouncyCastlePublicKey).clean();
			else if (bouncyCastlePublicKey instanceof BCMcElieceCipher.PublicKeyCCA2)
				((BCMcElieceCipher.PublicKeyCCA2) bouncyCastlePublicKey).clean();
			bouncyCastlePublicKey=null;
		}

	}
	@Override
	public boolean isDestroyed() {
		return publicKey==null && nativePublicKey==null && gnuPublicKey==null && bouncyCastlePublicKey==null;
	}


	private void checkNotDestroyed()
	{
		if (isDestroyed())
			throw new IllegalAccessError();
	}
	@Override
	public WrappedData getKeyBytes() {
		checkNotDestroyed();
        return new WrappedData(publicKey);
    }


    ASymmetricPublicKey(ASymmetricEncryptionType type, byte[] publicKey, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC) {
		this(publicKey, keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = type.getDerivedType();
		this.signatureType=null;
	}
	ASymmetricPublicKey(ASymmetricAuthenticatedSignatureType type, byte[] publicKey, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC) {
		this(publicKey, keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		this.encryptionType = null;
		this.signatureType=type.getDerivedType();
	}

	ASymmetricPublicKey(ASymmetricEncryptionType type, Object publicKey, int keySize,
						long publicKeyValidityBeginDateUTC, long expirationUTC) {
		this(publicKey, keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");

		this.encryptionType = type.getDerivedType();
		this.signatureType=null;
	}
	ASymmetricPublicKey(ASymmetricAuthenticatedSignatureType type, Object publicKey, int keySize,
						long publicKeyValidityBeginDateUTC, long expirationUTC) {
		this(publicKey, keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");

		this.encryptionType = null;
		this.signatureType=type.getDerivedType();

	}

	ASymmetricPublicKey(ASymmetricEncryptionType type, PublicKey publicKey, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC) {
		this(ASymmetricEncryptionType.encodePublicKey(publicKey, type), keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();

		this.encryptionType = type.getDerivedType();
		this.signatureType=null;
	}
	ASymmetricPublicKey(ASymmetricEncryptionType type, AsymmetricPublicKey publicKey, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC) {
		this(publicKey.getEncoded(), keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();

		this.encryptionType = type.getDerivedType();
		this.signatureType=null;
		this.bouncyCastlePublicKey=publicKey;
	}
	ASymmetricPublicKey(ASymmetricAuthenticatedSignatureType type, PublicKey publicKey, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC, boolean xdhKey) {
		this(ASymmetricEncryptionType.encodePublicKey(publicKey, type, xdhKey), keySize, publicKeyValidityBeginDateUTC, expirationUTC);
		if (type == null)
			throw new NullPointerException("type");
		if (type.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)
			throw new IllegalAccessError();

		this.encryptionType = null;
		this.signatureType=type.getDerivedType();
		this.xdhKey=xdhKey;
	}
	private ASymmetricPublicKey(byte[] publicKey, int keySize, long publicKeyValidityBeginDateUTC, long expirationUTC) {
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		if (keySize>MAX_SIZE_IN_BITS_OF_NON_HYBRID_PUBLIC_KEY)
			throw new IllegalArgumentException("keySize");
		if (expirationUTC<= publicKeyValidityBeginDateUTC)
			throw new IllegalArgumentException();
		this.publicKey = publicKey;
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(this.publicKey);
		this.expirationUTC = expirationUTC;
		this.publicKeyValidityBeginDateUTC = publicKeyValidityBeginDateUTC;
	}

	public ASymmetricPublicKey getPublicKeyWithNewExpirationTime(long timeExpirationUTC)
	{
		checkNotDestroyed();
		ASymmetricPublicKey res;
		if (signatureType==null)
			res=new ASymmetricPublicKey(this.encryptionType, publicKey.clone(), this.keySizeBits, this.publicKeyValidityBeginDateUTC, timeExpirationUTC);
		else
			res=new ASymmetricPublicKey(this.signatureType, publicKey.clone(), this.keySizeBits, this.publicKeyValidityBeginDateUTC, timeExpirationUTC);
		return res;
	}



	private ASymmetricPublicKey(Object publicKey, int keySize,
								long publicKeyValidityBeginDateUTC, long expirationUTC) {
		if (publicKey == null)
			throw new NullPointerException("publicKey");
		if (keySize < 256)
			throw new IllegalArgumentException("keySize");
		if (keySize>MAX_SIZE_IN_BITS_OF_NON_HYBRID_PUBLIC_KEY)
			throw new IllegalArgumentException("keySize");
		if (publicKeyValidityBeginDateUTC >=expirationUTC)
			throw new IllegalArgumentException();

		this.publicKey = ASymmetricEncryptionType.encodeGnuPublicKey(publicKey);
		this.keySizeBits = keySize;
		hashCode = Arrays.hashCode(this.publicKey);
		this.expirationUTC = expirationUTC;
		this.gnuPublicKey=null;
		this.publicKeyValidityBeginDateUTC = publicKeyValidityBeginDateUTC;
	}



	public WrappedData encode() {
		return encode(true);
	}

	@Override
	public WrappedString encodeString() {
		return new WrappedString(encode());
	}

	@Override
	public WrappedData encode(boolean includeTimes)
	{
		checkNotDestroyed();
		if (getTimeExpirationUTC()==Long.MAX_VALUE)
			includeTimes =false;
		byte[] tab = new byte[4+ASymmetricPrivateKey.ENCODED_TYPE_SIZE+publicKey.length+(includeTimes ?16:0)];
		tab[0]=encryptionType==null?(byte)5:(byte)4;
		if (includeTimes)
			tab[0]|= AbstractKey.INCLUDE_KEY_EXPIRATION_CODE;
		if (xdhKey)
			tab[0]|= AbstractKey.IS_XDH_KEY;
		Bits.putUnsignedInt(tab, 1, keySizeBits, 3);
		Bits.putUnsignedInt(tab, 4, encryptionType==null?signatureType.ordinal():encryptionType.ordinal(), ASymmetricPrivateKey.ENCODED_TYPE_SIZE);
		int pos=4+ASymmetricPrivateKey.ENCODED_TYPE_SIZE;
		if (includeTimes) {
			Bits.putLong(tab, pos, publicKeyValidityBeginDateUTC);
			pos+=8;
			Bits.putLong(tab, pos, expirationUTC);
			pos+=8;
		}

		System.arraycopy(publicKey, 0, tab, pos, publicKey.length);
		return new WrappedData(tab);
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof ASymmetricPublicKey) {

			ASymmetricPublicKey other = (ASymmetricPublicKey) o;
			boolean b=keySizeBits == other.keySizeBits;
			b=encryptionType == other.encryptionType && b;
			b=signatureType == other.signatureType && b;
			b=com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(publicKey, other.publicKey) && b;
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

	byte[] getBytesPublicKey() {
		checkNotDestroyed();
		return publicKey;
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
	public long getPublicKeyValidityBeginDateUTC() {
		return publicKeyValidityBeginDateUTC;
	}

	@Override
	public long getTimeExpirationUTC() {
		return expirationUTC;
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
	public ASymmetricPublicKey getNonPQCPublicKey() {
		checkNotDestroyed();
		return this;
	}

	@Override
	public int hashCode() {
		return hashCode;
	}

	@Override
	public Object toGnuKey()
			throws NoSuchAlgorithmException, IOException {
		checkNotDestroyed();
		if (gnuPublicKey == null)
			gnuPublicKey = ASymmetricEncryptionType.decodeGnuPublicKey(publicKey, encryptionType==null?signatureType.getKeyGeneratorAlgorithmName():encryptionType.getAlgorithmName());

		return gnuPublicKey;
	}

	@Override
	public PublicKey toJavaNativeKey()
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		checkNotDestroyed();
		if (encryptionType!=null && encryptionType.name().startsWith("BCPQC_MCELIECE_"))
		{
			AsymmetricKey bk=toBouncyCastleKey();
			if (bk instanceof BCMcElieceCipher.PublicKeyCCA2)
				nativePublicKey= new BCMcElieceCCA2PublicKey(((BCMcElieceCipher.PublicKeyCCA2)bk).getPublicKeyParameters());
			else
				nativePublicKey= new BCMcEliecePublicKey(((BCMcElieceCipher.PublicKey)bk).getPublicKeyParameters());
		}
		else
			if (nativePublicKey == null)
				nativePublicKey = ASymmetricEncryptionType.decodeNativePublicKey(publicKey, encryptionType==null?signatureType.getKeyGeneratorAlgorithmName():encryptionType.getAlgorithmName(),
					encryptionType==null?signatureType.name():encryptionType.name(), xdhKey, encryptionType==null?signatureType.getCodeProviderForKeyGenerator():encryptionType.getCodeProviderForKeyGenerator());

		return nativePublicKey;
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
			if (bouncyCastlePublicKey==null) {
				if (encryptionType.name().contains("CCA2")) {
					BCMcElieceCipher.PublicKeyCCA2 res = new BCMcElieceCipher.PublicKeyCCA2();
					try {
						res.readExternal(new RandomByteArrayInputStream(this.publicKey), encryptionType);
						bouncyCastlePublicKey = res;
					} catch (IOException  e) {
						throw new InvalidKeySpecException(e);
					}
				} else {
					BCMcElieceCipher.PublicKey res = new BCMcElieceCipher.PublicKey();
					try {
						res.readExternal(new RandomByteArrayInputStream(this.publicKey));
						bouncyCastlePublicKey = res;
					} catch (IOException  e) {
						throw new InvalidKeySpecException(e);
					}

				}
			}
			return bouncyCastlePublicKey;
		}
		else {
			PublicKey pk = toJavaNativeKey();
			if (pk instanceof RSAPublicKey) {
				RSAPublicKey javaNativePublicKey = (RSAPublicKey) pk;
				return new AsymmetricRSAPublicKey(
						getBouncyCastleAlgorithm(),
						javaNativePublicKey.getModulus(), javaNativePublicKey.getPublicExponent());

			} else if (pk instanceof ECPublicKey) {
				ECPublicKey javaNativePublicKey = (ECPublicKey) pk;
				return new AsymmetricECPublicKey(getBouncyCastleAlgorithm(), javaNativePublicKey.getEncoded());

			} else
				throw new IllegalAccessError(pk.getClass().getName());
		}
		
	}

	@Override
	public boolean isPostQuantumKey() {
		return encryptionType==null?signatureType.isPostQuantumAlgorithm():encryptionType.isPostQuantumAlgorithm();
	}

}
