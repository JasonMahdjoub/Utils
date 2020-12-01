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
	BC_CHACHA20_POLY1305(null, CodeProvider.BC, SymmetricEncryptionType.BC_CHACHA20_POLY1305),
	DEFAULT(BC_FIPS_AES_WITH_PADDING);
	
	private final String algorithmName;
	private final CodeProvider provider;
	private final SymmetricEncryptionType symmetricEncryptionType;

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
	}


	SymmetricKeyWrapperType(SymmetricKeyWrapperType other)
	{
		this(other.algorithmName, other.provider, other.symmetricEncryptionType);
	}

	SymmetricEncryptionType getSymmetricEncryptionType() {
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
		PasswordHash ph = new PasswordHash(passwordHashType, new SecureRandom(), (byte)16, (byte)0);
		return symmetricEncryptionType.generateSecretKeyFromHashedPassword(ph.hash(password, null), (short)256);
	}

	WrappedEncryptedSymmetricSecretKey wrapKey(PasswordHashType passwordHashType, WrappedPassword password, SymmetricSecretKey secretKeyToWrap, AbstractSecureRandom random) throws IOException {

		try {
			SymmetricSecretKey secretKey = hashPasswordForSecretKeyEncryption(symmetricEncryptionType, passwordHashType, password);
			return wrapKey(secretKey, secretKeyToWrap, random);
		} catch (NoSuchAlgorithmException | NoSuchProviderException  e) {
			throw new IOException(e);
		}

	}
	WrappedEncryptedSymmetricSecretKeyString wrapKeyString(PasswordHashType passwordHashType, WrappedPassword password, SymmetricSecretKey secretKeyToWrap, AbstractSecureRandom random) throws IOException {
		return new WrappedEncryptedSymmetricSecretKeyString(wrapKey(passwordHashType, password, secretKeyToWrap, random));
	}

	SymmetricSecretKey unwrapKey(PasswordHashType passwordHashType, WrappedPassword password, WrappedEncryptedSymmetricSecretKeyString encryptedSecretKey) throws IOException {
		return unwrapKey(passwordHashType, password, new WrappedEncryptedSymmetricSecretKey(encryptedSecretKey));
	}
	SymmetricSecretKey unwrapKey(PasswordHashType passwordHashType, WrappedPassword password, WrappedEncryptedSymmetricSecretKey encryptedSecretKey) throws IOException {
		if (encryptedSecretKey==null)
			throw new NullPointerException();

		try {
			SymmetricSecretKey secretKey=  hashPasswordForSecretKeyEncryption(symmetricEncryptionType, passwordHashType, password);
			return unwrapKey(secretKey, encryptedSecretKey);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}

	}

	WrappedEncryptedSymmetricSecretKey wrapKey(SymmetricSecretKey key, SymmetricSecretKey keyToWrap, AbstractSecureRandom random) throws IOException
	{
		try {
			CodeProvider.ensureProviderLoaded(provider);
			if ((key.getAuthenticatedSignatureAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getAuthenticatedSignatureAlgorithmType().getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
					|| (key.getEncryptionAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
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
				cipher = javax.crypto.Cipher.getInstance(algorithmName, provider.checkProviderWithCurrentOS().name());

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
		try {
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
		try {
			if ((key.getAuthenticatedSignatureAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getAuthenticatedSignatureAlgorithmType().getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
					|| (key.getEncryptionAlgorithmType() != null && ((provider == CodeProvider.GNU_CRYPTO) != (key.getEncryptionAlgorithmType().getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO)))
					|| (encryptionType != null && (provider == CodeProvider.GNU_CRYPTO) != (encryptionType.getCodeProviderForEncryption() == CodeProvider.GNU_CRYPTO))
					|| (signatureType != null && (provider == CodeProvider.GNU_CRYPTO) != (signatureType.getCodeProviderForSignature() == CodeProvider.GNU_CRYPTO)))
				throw new IllegalArgumentException("The keys must come from the same providers");
			CodeProvider.ensureProviderLoaded(provider);
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
					throw new IllegalStateException(e);
				}


			} else {
				javax.crypto.Cipher cipher;
				cipher = javax.crypto.Cipher.getInstance(algorithmName, provider.checkProviderWithCurrentOS().name());


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
}
