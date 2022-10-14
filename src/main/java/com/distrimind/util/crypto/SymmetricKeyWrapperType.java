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

import com.distrimind.bcfips.crypto.InvalidWrappingException;
import com.distrimind.bcfips.crypto.PlainInputProcessingException;
import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.util.Arrays;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 1.17.0
 */
public enum SymmetricKeyWrapperType {

	BC_FIPS_AES("AESKW", CodeProvider.BCFIPS, SymmetricEncryptionType.AES_GCM),
	BC_FIPS_AES_WITH_PADDING("AESKWP", CodeProvider.BCFIPS, SymmetricEncryptionType.AES_GCM),
	CLASSIC_ENCRYPTION(null, null, SymmetricEncryptionType.AES_GCM),
	DEFAULT(BC_FIPS_AES_WITH_PADDING);

	private final String algorithmName;
	private final CodeProvider provider;
	private final SymmetricEncryptionType symmetricEncryptionType;
	private SymmetricKeyWrapperType derivedType;

	public boolean equals(SymmetricKeyWrapperType type)
	{

		if (type==null)
			return false;
		//noinspection StringEquality
		return this.algorithmName==type.algorithmName && this.provider==type.provider && this.symmetricEncryptionType==type.symmetricEncryptionType;
	}
	
	SymmetricKeyWrapperType(String algorithmName, CodeProvider provider, SymmetricEncryptionType symmetricEncryptionType) {
		this.algorithmName = algorithmName;
		this.provider = provider;
		this.symmetricEncryptionType=symmetricEncryptionType;
		this.derivedType=this;
	}


	SymmetricKeyWrapperType(SymmetricKeyWrapperType other)
	{
		this(other.algorithmName, other.provider, other.symmetricEncryptionType);
		this.derivedType=other;
	}

	public SymmetricEncryptionType getSymmetricEncryptionType() {
		return symmetricEncryptionType;
	}

	public short getDefaultKeySizeBits()
	{
		return symmetricEncryptionType.getDefaultKeySizeBits();
	}
	public short getDefaultKeySizeBytes()
	{
		return symmetricEncryptionType.getDefaultKeySizeBytes();
	}

	public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random, short keySizeBits) throws NoSuchProviderException, NoSuchAlgorithmException {
		return symmetricEncryptionType.getKeyGenerator(random, keySizeBits);
	}

	public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random) throws NoSuchProviderException, NoSuchAlgorithmException {
		return symmetricEncryptionType.getKeyGenerator(random);
	}

	public SymmetricSecretKey generateSecretKeyFromHashedPassword(WrappedSecretData wrappedSecretData) throws NoSuchProviderException, NoSuchAlgorithmException {
		return symmetricEncryptionType.generateSecretKeyFromHashedPassword(wrappedSecretData);
	}

	public SymmetricSecretKey generateSecretKeyFromHashedPassword(WrappedSecretData wrappedSecretData, short keySizeBits) throws NoSuchProviderException, NoSuchAlgorithmException {
		return symmetricEncryptionType.generateSecretKeyFromHashedPassword(wrappedSecretData, keySizeBits);
	}



	public CodeProvider getCodeProvider()
	{
		return provider;
	}
	public String getAlgorithmName()
	{
		return algorithmName;
	}

	static SymmetricSecretKey hashPasswordForSecretKeyEncryption(SymmetricEncryptionType symmetricEncryptionType, PasswordHashType passwordHashType, WrappedPassword password) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		if (password==null)
			throw new NullPointerException();
		if (passwordHashType==null)
			throw new NullPointerException();
		if (password.isCleaned())
			throw new IllegalArgumentException();
		PasswordHash ph = new PasswordHash(passwordHashType, new SecureRandom(), (byte)16, (byte)0);
		return symmetricEncryptionType.generateSecretKeyFromHashedPassword(ph.hash(password, null), (short)256);
	}



	WrappedEncryptedSymmetricSecretKey wrapKey(SymmetricSecretKey key, SymmetricSecretKey keyToWrap, AbstractSecureRandom random) throws IOException
	{
		try {
			//CodeProvider.ensureProviderLoaded(provider);
			if (key.getAuthenticatedSignatureAlgorithmType() != null)
				throw new IllegalArgumentException();
			if (key.isCleaned())
				throw new IllegalArgumentException();
			if (keyToWrap.isCleaned())
				throw new IllegalArgumentException();
			if ((key.getEncryptionAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
					|| (keyToWrap.getAuthenticatedSignatureAlgorithmType() != null && (provider == CodeProvider.GNU_CRYPTO) != (keyToWrap.getAuthenticatedSignatureAlgorithmType().getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO))
					|| (keyToWrap.getEncryptionAlgorithmType() != null && (provider == CodeProvider.GNU_CRYPTO) != (keyToWrap.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
			if (!algorithmName.startsWith(key.getEncryptionAlgorithmType().getAlgorithmName()))
				throw new IllegalArgumentException("The key must be compatible with algorithm " + algorithmName);
			if (provider.equals(CodeProvider.GNU_CRYPTO)) {

				Object cipher = GnuFunctions.cipherGetInstance(algorithmName);
				GnuFunctions.cipherInit(cipher, Cipher.WRAP_MODE, key);
				byte[] wrappedKey=GnuFunctions.cipherWrap(cipher, keyToWrap.toGnuKey());
				byte[] res=ASymmetricKeyWrapperType.wrapKeyWithMetaData(wrappedKey, keyToWrap);
				Arrays.fill(wrappedKey, (byte)0);
				return new WrappedEncryptedSymmetricSecretKey(res);
			} else if (provider.equals(CodeProvider.BC) || provider.equals(CodeProvider.BCFIPS)) {

				BCCipher cipher = new BCCipher(this);

				cipher.init(javax.crypto.Cipher.WRAP_MODE, key, random);
				try {
					byte[] wrappedKey=cipher.wrap(keyToWrap);
					byte[] res=ASymmetricKeyWrapperType.wrapKeyWithMetaData(wrappedKey, keyToWrap);
					Arrays.fill(wrappedKey, (byte)0);
					return new WrappedEncryptedSymmetricSecretKey(res);
				} catch (PlainInputProcessingException e) {
					throw new IllegalStateException(e);
				}
			} else {
				javax.crypto.Cipher cipher;
				cipher = javax.crypto.Cipher.getInstance(algorithmName, provider.getCompatibleProvider());

				cipher.init(javax.crypto.Cipher.WRAP_MODE, key.toJavaNativeKey());
				byte[] wrappedKey=cipher.wrap(keyToWrap.toJavaNativeKey());
				byte[] res=ASymmetricKeyWrapperType.wrapKeyWithMetaData(wrappedKey, keyToWrap);
				Arrays.fill(wrappedKey, (byte)0);
				return new WrappedEncryptedSymmetricSecretKey(res);

			}
		} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidKeyException | NoSuchPaddingException | IllegalBlockSizeException e) {
			throw new IOException(e);
		}

	}


	SymmetricSecretKey unwrapKey(SymmetricSecretKey key, WrappedEncryptedSymmetricSecretKey keyToUnwrap) throws IOException {
		if (key.isCleaned())
			throw new IllegalArgumentException();
		if (keyToUnwrap.isCleaned())
			throw new IllegalArgumentException();
		try {
			if (!algorithmName.startsWith(key.getEncryptionAlgorithmType().getAlgorithmName()))
				throw new IllegalArgumentException("The key must be compatible with algorithm " + algorithmName);
			byte[] ktu=ASymmetricKeyWrapperType.getWrappedKeyFromMetaData(keyToUnwrap);
			SymmetricSecretKey res;
			if (ASymmetricKeyWrapperType.isSignatureFromMetaData(keyToUnwrap))
				res=unwrapKey(key, ktu, null, ASymmetricKeyWrapperType.getSignatureTypeFromMetaData(keyToUnwrap), ASymmetricKeyWrapperType.getKeySizeFromMetaData(keyToUnwrap));
			else
				res=unwrapKey(key, ktu, ASymmetricKeyWrapperType.getEncryptionTypeFromMetaData(keyToUnwrap), null, ASymmetricKeyWrapperType.getKeySizeFromMetaData(keyToUnwrap));
			Arrays.fill(ktu, (byte)0);
			return res;
		} catch (InvalidKeyException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	@SuppressWarnings("ConstantConditions")
	private SymmetricSecretKey unwrapKey(SymmetricSecretKey key, byte[] keyToUnwrap, SymmetricEncryptionType encryptionType, SymmetricAuthenticatedSignatureType signatureType, short keySize) throws IOException {
		if (key.isCleaned())
			throw new IllegalArgumentException();
		try {
			if ((key.getAuthenticatedSignatureAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getAuthenticatedSignatureAlgorithmType().getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
					|| (key.getEncryptionAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
					|| (encryptionType != null && (provider == CodeProvider.GNU_CRYPTO) != (encryptionType.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO))
					|| (signatureType != null && (provider == CodeProvider.GNU_CRYPTO) != (signatureType.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
			//CodeProvider.ensureProviderLoaded(provider);
			if (provider.equals(CodeProvider.GNU_CRYPTO)) {

				Object cipher = GnuFunctions.cipherGetInstance(algorithmName);
				GnuFunctions.cipherInit(cipher, Cipher.UNWRAP_MODE, key.toGnuKey());
				if (encryptionType == null) {
					return new SymmetricSecretKey(signatureType, GnuFunctions.cipherUnwrap(cipher, keyToUnwrap, signatureType.getAlgorithmName()), keySize);
				} else
					return new SymmetricSecretKey(encryptionType, GnuFunctions.cipherUnwrap(cipher, keyToUnwrap, encryptionType.getAlgorithmName()), keySize);
			} else if (provider.equals(CodeProvider.BC) || provider.equals(CodeProvider.BCFIPS)) {

				BCCipher cipher = new BCCipher(this);

				cipher.init(Cipher.UNWRAP_MODE, key);
				try {
					if (encryptionType == null) {
						return new SymmetricSecretKey(signatureType, cipher.unwrap(keyToUnwrap));
					} else
						return new SymmetricSecretKey(encryptionType, cipher.unwrap(keyToUnwrap));
				} catch (InvalidWrappingException e) {
					throw new IllegalStateException("encryptionType="+encryptionType+", keyWrapperType="+this, e);
				}


			} else {
				javax.crypto.Cipher cipher;
				cipher = javax.crypto.Cipher.getInstance(algorithmName, provider.getCompatibleProvider());


				cipher.init(Cipher.UNWRAP_MODE, key.toJavaNativeKey());
				if (encryptionType == null) {
					return new SymmetricSecretKey(signatureType, (javax.crypto.SecretKey) cipher.unwrap(keyToUnwrap, signatureType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);
				} else
					return new SymmetricSecretKey(encryptionType, (javax.crypto.SecretKey) cipher.unwrap(keyToUnwrap, encryptionType.getAlgorithmName(), javax.crypto.Cipher.SECRET_KEY), keySize);


			}
		} catch (NoSuchPaddingException | InvalidKeyException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}

	}

	public boolean isPostQuantumAlgorithm(short keySizeBits)
	{
		return keySizeBits>=256;
	}

	private static final int MAX_SYMMETRIC_ENCRYPTION_META_DATA=SymmetricEncryptionType.MAX_IV_SIZE_IN_BYTES+31;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION =SymmetricSecretKey.MAX_SIZE_IN_BYTES_OF_SYMMETRIC_KEY_FOR_SIGNATURE +MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	static final int MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA=SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE+2;
	static final int MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE +2;
	static final int MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA=HybridASymmetricAuthenticatedSignatureType.MAX_HYBRID_ASYMMETRIC_SIGNATURE_SIZE+2;

	private static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_ASYMMETRIC_SIGNATURE_META_DATA=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_ASYMMETRIC_SIGNATURE +2;
	private static final int MAX_SIZE_IN_BYTES_OF_PQC_ASYMMETRIC_SIGNATURE_META_DATA=ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_PQC_ASYMMETRIC_SIGNATURE +2;
	private static final int MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA=SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE+ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE +2;
	private static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_SIGNATURE_META_DATA=SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE+ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_ASYMMETRIC_SIGNATURE +2;
	private static final int MAX_SIZE_IN_BYTES_OF_PQC_SIGNATURE_META_DATA=SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE+ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_PQC_ASYMMETRIC_SIGNATURE +2;
	static final int MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA=SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE+HybridASymmetricAuthenticatedSignatureType.MAX_HYBRID_ASYMMETRIC_SIGNATURE_SIZE+2;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_NON_PQC_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_NON_PQC_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_PQC_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_PQC_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_HYBRID_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_HYBRID_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_SYMMETRIC_AND_NON_PQC_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_NON_PQC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_SYMMETRIC_AND_PQC_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_PQC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION_WITH_SYMMETRIC_AND_HYBRID_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_SYMMETRIC_SECRET_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_HYBRID_SIGNATURE_META_DATA;





	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION =HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION =IASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION =IASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION =IASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_FOR_ENCRYPTION+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION =IASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION =ASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION =ASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION =ASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION =ASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION =ASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION+MAX_SYMMETRIC_ENCRYPTION_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION =HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION =HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION+MAX_SYMMETRIC_ENCRYPTION_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION =HybridASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE+MAX_SYMMETRIC_ENCRYPTION_META_DATA;




	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SYMMETRIC_SIGNATURE_META_DATA;




	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE_META_DATA;



	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_NON_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_ASYMMETRIC_PQC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;

	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_ENCRYPTION_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;
	public static final int MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION_AND_WITH_SYMMETRIC_AND_ASYMMETRIC_SIGNATURE =MAX_SIZE_IN_BYTES_OF_WRAPPED_HYBRID_ASYMMETRIC_PRIVATE_KEY_FOR_SIGNATURE_WITHOUT_RSA_WITH_SYMMETRIC_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_SIGNATURE_META_DATA;


	public static void main(String []arg) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		for (SymmetricKeyWrapperType kwt : SymmetricKeyWrapperType.values()) {
			SymmetricSecretKey mainKey = kwt.getSymmetricEncryptionType().getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null)).generateKey();
			for (SymmetricEncryptionType et : SymmetricEncryptionType.values()) {
				if (et.getAlgorithmName().toLowerCase().contains("aes")
						|| et.getAlgorithmName().toLowerCase().contains("chacha20")
						|| et.getAlgorithmName().toLowerCase().contains("twofish")
						|| et.getAlgorithmName().toLowerCase().contains("serpent")
						|| et.getAlgorithmName().toLowerCase().contains("anubis")) {
					for (short keySizeBits : new short[]{128, 256}) {
						SymmetricSecretKey k = et.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), keySizeBits).generateKey();
						System.out.println(et + " , " + kwt + ", " + k.getKeySizeBits() + ", " + kwt.wrapKey(mainKey, k, SecureRandomType.DEFAULT.getSingleton(null)).getBytes().length);
					}
				}
			}
		}
	}

	public SymmetricKeyWrapperType getDerivedType() {
		return derivedType;
	}
}
