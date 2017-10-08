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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import com.distrimind.util.Bits;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.NoSuchProviderException;

/**
 * List of asymmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.4
 */
public enum ASymmetricEncryptionType {
	RSA_OAEPWithSHA256AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-256ANDMGF1PADDING", ASymmetricAuthentifiedSignatureType.SHA384withRSA,
			(short) 3072, 31536000000l, (short) 66, CodeProvider.SunJCE,CodeProvider.SunRsaSign), 
	RSA_PKCS1Padding("RSA", "ECB", "PKCS1Padding", ASymmetricAuthentifiedSignatureType.SHA384withRSA, (short) 3072, 31536000000l, (short) 11,
					CodeProvider.SunJCE,CodeProvider.SunRsaSign),
	BC_FIPS_RSA_OAEPWithSHA256AndMGF1Padding("RSA", "NONE", "OAEPwithSHA256andMGF1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 66,CodeProvider.BCFIPS,CodeProvider.BCFIPS),
	BC_FIPS_RSA_PKCS1Padding("RSA", "NONE", "PKCS1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 11,CodeProvider.BCFIPS,CodeProvider.BCFIPS),
	DEFAULT(BC_FIPS_RSA_OAEPWithSHA256AndMGF1Padding);
	


	static gnu.vm.jgnu.security.KeyPair decodeGnuKeyPair(byte[] encodedKeyPair)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		return decodeGnuKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
	}

	static gnu.vm.jgnu.security.KeyPair decodeGnuKeyPair(byte[] encodedKeyPair, int off, int len)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
		return new gnu.vm.jgnu.security.KeyPair(decodeGnuPublicKey(parts[0]), decodeGnuPrivateKey(parts[1]));
	}

	static gnu.vm.jgnu.security.PrivateKey decodeGnuPrivateKey(byte[] encodedKey)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
		gnu.vm.jgnu.security.spec.PKCS8EncodedKeySpec pkcsKeySpec = new gnu.vm.jgnu.security.spec.PKCS8EncodedKeySpec(
				parts[1]);
		gnu.vm.jgnu.security.KeyFactory kf = gnu.vm.jgnu.security.KeyFactory.getInstance(new String(parts[0]));
		return kf.generatePrivate(pkcsKeySpec);
	}

	static gnu.vm.jgnu.security.PublicKey decodeGnuPublicKey(byte[] encodedKey)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
		gnu.vm.jgnu.security.spec.X509EncodedKeySpec pubKeySpec = new gnu.vm.jgnu.security.spec.X509EncodedKeySpec(
				parts[1]);
		gnu.vm.jgnu.security.KeyFactory kf = gnu.vm.jgnu.security.KeyFactory.getInstance(new String(parts[0]));
		return kf.generatePublic(pubKeySpec);
	}

	static KeyPair decodeNativeKeyPair(byte[] encodedKeyPair)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		return decodeNativeKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
	}

	static KeyPair decodeNativeKeyPair(byte[] encodedKeyPair, int off, int len)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
		return new KeyPair(decodeNativePublicKey(parts[0]), decodeNativePrivateKey(parts[1]));
	}

	static PrivateKey decodeNativePrivateKey(byte[] encodedKey)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {

		try {
			byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
			PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(parts[1]);
			KeyFactory kf = KeyFactory.getInstance(new String(parts[0]));
			return kf.generatePrivate(pkcsKeySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
		} catch (InvalidKeySpecException e) {
			throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
		}
	}

	static PublicKey decodeNativePublicKey(byte[] encodedKey)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		try {
			byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
			X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(parts[1]);
			KeyFactory kf = KeyFactory.getInstance(new String(parts[0]));
			return kf.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
		} catch (InvalidKeySpecException e) {
			throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
		}

	}

	static byte[] encodeKeyPair(gnu.vm.jgnu.security.KeyPair keyPair) {
		return Bits.concateEncodingWithShortSizedTabs(encodePublicKey(keyPair.getPublic()),
				encodePrivateKey(keyPair.getPrivate()));
	}

	static byte[] encodeKeyPair(KeyPair keyPair) {
		return Bits.concateEncodingWithShortSizedTabs(encodePublicKey(keyPair.getPublic()),
				encodePrivateKey(keyPair.getPrivate()));
	}

	static byte[] encodePrivateKey(gnu.vm.jgnu.security.PrivateKey key) {
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	}

	static byte[] encodePrivateKey(PrivateKey key) {
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	}

	static byte[] encodePublicKey(gnu.vm.jgnu.security.PublicKey key) {
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
		/*
		 * X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key.getEncoded());
		 * return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(),
		 * pubKeySpec.getEncoded());
		 */
	}

	static byte[] encodePublicKey(PublicKey key) {
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
		/*
		 * X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key.getEncoded());
		 * return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(),
		 * pubKeySpec.getEncoded());
		 */
	}

	static ASymmetricEncryptionType valueOf(int ordinal) throws IllegalArgumentException {
		for (ASymmetricEncryptionType a : values()) {
			if (a.ordinal() == ordinal)
				return a;
		}
		throw new IllegalArgumentException();
	}

	private final String algorithmName;

	private final String blockMode;

	private final String padding;

	private final ASymmetricAuthentifiedSignatureType signature;

	private final short keySize;

	private final long expirationTimeMilis;

	private final short blockSizeDecrement;

	private final CodeProvider codeProviderForEncryption, codeProviderForKeyGenerator;

	private ASymmetricEncryptionType(ASymmetricEncryptionType type) {
		this(type.algorithmName, type.blockMode, type.padding, type.signature, type.keySize, type.expirationTimeMilis,
				type.blockSizeDecrement, type.codeProviderForEncryption, type.codeProviderForKeyGenerator);
	}

	private ASymmetricEncryptionType(String algorithmName, String blockMode, String padding,
			ASymmetricAuthentifiedSignatureType signature, short keySize, long expirationTimeMilis, short blockSizeDecrement,
			CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenetor) {
		this.algorithmName = algorithmName;
		this.blockMode = blockMode;
		this.padding = padding;
		this.signature = signature;
		this.keySize = keySize;
		this.blockSizeDecrement = blockSizeDecrement;
		this.codeProviderForEncryption = codeProviderForEncryption;
		this.codeProviderForKeyGenerator=codeProviderForKeyGenetor;
		this.expirationTimeMilis = expirationTimeMilis;
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public String getBlockMode() {
		return blockMode;
	}

	public AbstractCipher getCipherInstance()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnux.crypto.NoSuchPaddingException, NoSuchProviderException {
		String name = algorithmName+"/" + blockMode + "/" + padding;
		if (codeProviderForEncryption == CodeProvider.GNU_CRYPTO) {
			return new GnuCipher(gnu.vm.jgnux.crypto.Cipher.getInstance(name));
		} else if (codeProviderForEncryption == CodeProvider.BCFIPS || codeProviderForEncryption == CodeProvider.BC) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				
				return new JavaNativeCipher(Cipher.getInstance(name, codeProviderForEncryption.name()));
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (NoSuchPaddingException e) {
				throw new gnu.vm.jgnux.crypto.NoSuchPaddingException(e.getMessage());
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}

		} else {
			try {
				
				return new JavaNativeCipher(Cipher.getInstance(name, codeProviderForEncryption.checkProviderWithCurrentOS().name()));
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (NoSuchPaddingException e) {
				throw new gnu.vm.jgnux.crypto.NoSuchPaddingException(e.getMessage());
			}catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
		}
	}

	
	
	public short getDefaultKeySize() {
		return keySize;
	}

	public int getDefaultMaxBlockSize() {
		return getMaxBlockSize(keySize);
	}

	public ASymmetricAuthentifiedSignatureType getDefaultSignatureAlgorithm() {
		return signature;
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize,
			long expirationTimeUTC) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			gnu.vm.jgnu.security.KeyPairGenerator kgp = gnu.vm.jgnu.security.KeyPairGenerator
					.getInstance(algorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kgp);
			res.initialize(keySize, expirationTimeUTC, random);

			return res;
		} else if (codeProviderForKeyGenerator == CodeProvider.BCFIPS) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, CodeProvider.BCFIPS.name());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySize, expirationTimeUTC, random);

				return res;
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
		} else {
			try {
				KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, codeProviderForKeyGenerator.checkProviderWithCurrentOS().name());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySize, expirationTimeUTC, random);

				return res;
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}

		}

	}
	public int getMaxBlockSize(int keySize) {
		return keySize / 8 - blockSizeDecrement;
	}

	public String getPadding() {
		return padding;
	}

	public CodeProvider getCodeProviderForEncryption() {
		return codeProviderForEncryption;
	}

	public CodeProvider getCodeProviderForKeyGenerator() {
		return codeProviderForKeyGenerator;
	}
	
}
