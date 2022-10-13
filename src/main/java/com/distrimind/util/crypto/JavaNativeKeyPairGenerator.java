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

import com.distrimind.bouncycastle.pqc.jcajce.spec.KyberParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 */
public final class JavaNativeKeyPairGenerator extends AbstractKeyPairGenerator {
	private final KeyPairGenerator keyPairGenerator;

	private int keySizeBits = -1;
	private long expirationTime = -1;
	private long publicKeyValidityBeginDateUTC;
	private final ASymmetricAuthenticatedSignatureType typeToSynchronize;
	private final boolean synchronize;

	JavaNativeKeyPairGenerator(ASymmetricEncryptionType type, KeyPairGenerator keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
		synchronize=false;
		typeToSynchronize=null;
	}
	JavaNativeKeyPairGenerator(ASymmetricAuthenticatedSignatureType type, KeyPairGenerator keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
		synchronize=this.signatureType.getSignatureAlgorithmName().equals("SPHINCSPLUS");
		if (synchronize)
			this.typeToSynchronize=ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST;
		else
			this.typeToSynchronize=null;
	}

	private boolean isXDHKey()
	{
		return keyPairGenerator.getAlgorithm().equals("X25519") || keyPairGenerator.getAlgorithm().equals("X448");
	}

	@Override
	public ASymmetricKeyPair generateKeyPair() {
		KeyPair kp;
		if (synchronize)
		{
			synchronized(typeToSynchronize)
			{
				kp = keyPairGenerator.generateKeyPair();
			}
		}
		else
			kp = keyPairGenerator.generateKeyPair();
		if (encryptionType==null)
			return new ASymmetricKeyPair(signatureType, kp, keySizeBits, publicKeyValidityBeginDateUTC, expirationTime, isXDHKey());
		else
			return new ASymmetricKeyPair(encryptionType, kp, keySizeBits, publicKeyValidityBeginDateUTC, expirationTime);
	}

	@Override
	public String getAlgorithm() {
		return keyPairGenerator.getAlgorithm();
	}

	@Override
	public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime) throws IOException {
		try {
			this.initialize(keySize, publicKeyValidityBeginDateUTC, expirationTime, SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS.getSingleton(null));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}

	}


	@Override
	public void initialize(int keySize, long publicKeyValidityBeginDateUTC, long expirationTime, AbstractSecureRandom _random) throws IOException {
		try {
			this.keySizeBits = keySize;
			this.expirationTime = expirationTime;
			this.publicKeyValidityBeginDateUTC=publicKeyValidityBeginDateUTC;
			if (encryptionType!=null && encryptionType.getAlgorithmName().startsWith("CRYSTALS-Kyber"))
			{
				if (encryptionType.getAlgorithmName().endsWith("512"))
				{
					keyPairGenerator.initialize(KyberParameterSpec.kyber512, _random);
				}
				else if (encryptionType.getAlgorithmName().endsWith("768"))
				{
					keyPairGenerator.initialize(KyberParameterSpec.kyber768, _random);
				}
				else if (encryptionType.getAlgorithmName().endsWith("1024"))
				{
					keyPairGenerator.initialize(KyberParameterSpec.kyber1024, _random);
				}
				else if (encryptionType.getAlgorithmName().endsWith("512-AES"))
				{
					keyPairGenerator.initialize(KyberParameterSpec.kyber512_aes, _random);
				}
				else if (encryptionType.getAlgorithmName().endsWith("768-AES"))
				{
					keyPairGenerator.initialize(KyberParameterSpec.kyber768_aes, _random);
				}
				else if (encryptionType.getAlgorithmName().endsWith("1024-AES"))
				{
					keyPairGenerator.initialize(KyberParameterSpec.kyber1024_aes, _random);
				}
				else
					throw new IllegalAccessError();
			}
			else if (signatureType != null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA3_512.getKeyGeneratorAlgorithmName())) {
				this.keySizeBits = signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA3_256), _random.getJavaNativeSecureRandom());
			} else if (signatureType != null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA2_512_256.getKeyGeneratorAlgorithmName())) {
				this.keySizeBits = signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType != null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHAKE256_SLOW.getKeyGeneratorAlgorithmName())) {
				this.keySizeBits = signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(SPHINCSPlusParameterSpec.shake_256s, _random.getJavaNativeSecureRandom());
			}
			else if (signatureType != null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHAKE256_FAST.getKeyGeneratorAlgorithmName())) {
				this.keySizeBits = signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(SPHINCSPlusParameterSpec.shake_256f, _random.getJavaNativeSecureRandom());
			}
			else if (signatureType != null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_SLOW.getKeyGeneratorAlgorithmName())) {
				this.keySizeBits = signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(SPHINCSPlusParameterSpec.sha2_256s, _random.getJavaNativeSecureRandom());
			}
			else if (signatureType != null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST.getKeyGeneratorAlgorithmName())) {
				this.keySizeBits = signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(SPHINCSPlusParameterSpec.sha2_256f, _random.getJavaNativeSecureRandom());
			}
			else if (signatureType == null || signatureType.getCurveName() == null)
				keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4), _random.getJavaNativeSecureRandom());
			else {
				switch (signatureType.getCurveName()) {
					case "P-256":
					case "P-384":
					case "P-521":
						this.keySizeBits = signatureType.getDefaultKeySize();
						keyPairGenerator.initialize(new ECGenParameterSpec(signatureType.getCurveName()), _random.getJavaNativeSecureRandom());
						break;
					case "Ed25519":
					case "Ed448":
					case "X25519":
					case "X448":
						keyPairGenerator.initialize(signatureType.getDefaultKeySize(), _random.getJavaNativeSecureRandom());
						break;
					default:
						throw new InternalError();

				}
			}

		}
		catch (InvalidAlgorithmParameterException e){
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
	}
	
	

}
