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

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 2.0
 */
public final class JavaNativeKeyPairGenerator extends AbstractKeyPairGenerator {
	private final KeyPairGenerator keyPairGenerator;

	private short keySizeBits = -1;
	private long expirationTime = -1;

	JavaNativeKeyPairGenerator(ASymmetricEncryptionType type, KeyPairGenerator keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
	}
	JavaNativeKeyPairGenerator(ASymmetricAuthentifiedSignatureType type, KeyPairGenerator keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
	}

	@Override
	public ASymmetricKeyPair generateKeyPair() {
		KeyPair kp = keyPairGenerator.generateKeyPair();
		if (encryptionType==null)
			return new ASymmetricKeyPair(signatureType, kp, keySizeBits, expirationTime);
		else
			return new ASymmetricKeyPair(encryptionType, kp, keySizeBits, expirationTime);
	}

	@Override
	public String getAlgorithm() {
		return keyPairGenerator.getAlgorithm();
	}

	@Override
	public void initialize(short _keysize, long expirationTime) {
		keyPairGenerator.initialize(_keysize);
		this.keySizeBits = _keysize;
		this.expirationTime = expirationTime;

	}


	@SuppressWarnings({"deprecation", "ConstantConditions"})
	@Override
	public void initialize(short _keySize, long expirationTime, AbstractSecureRandom _random) throws gnu.vm.jgnu.security.InvalidAlgorithmParameterException {
		this.keySizeBits = _keySize;
		this.expirationTime = expirationTime;
		
		try
		{
			if (signatureType!=null && (signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA256withECDSA_P_256.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withECDSA_P_384.getKeyGeneratorAlgorithmName())
							|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withECDSA_P_521.getKeyGeneratorAlgorithmName())))
			{
				if (_keySize<256)
				{
					this.keySizeBits=224;
					keyPairGenerator.initialize(new ECGenParameterSpec("P-224"), _random.getJavaNativeSecureRandom());
				}
				else if (_keySize<(384-256)/2)
				{
					this.keySizeBits=256;
					keyPairGenerator.initialize(new ECGenParameterSpec("P-256"), _random.getJavaNativeSecureRandom());
				}
				else if (_keySize<(521-384)/2)
				{
					this.keySizeBits=384;
					keyPairGenerator.initialize(new ECGenParameterSpec("P-384"), _random.getJavaNativeSecureRandom());
				}
				else
				{
					this.keySizeBits=521;
					keyPairGenerator.initialize(new ECGenParameterSpec("P-521"), _random.getJavaNativeSecureRandom());
				}
			}
			else if (signatureType!=null && (signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_25519.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_25519.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_25519.getKeyGeneratorAlgorithmName())))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
				keyPairGenerator.initialize(new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(),
				        ecP.getN(), ecP.getH(), ecP.getSeed()), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType!=null && (signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_221.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_221.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_221.getKeyGeneratorAlgorithmName())))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				X9ECParameters ecP = CustomNamedCurves.getByName("M-221");
				keyPairGenerator.initialize(new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(),
				        ecP.getN(), ecP.getH(), ecP.getSeed()), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType!=null && (signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_383.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_383.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_383.getKeyGeneratorAlgorithmName())))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				X9ECParameters ecP = CustomNamedCurves.getByName("M-383");
				keyPairGenerator.initialize(new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(),
				        ecP.getN(), ecP.getH(), ecP.getSeed()), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType!=null && (signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_511.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_511.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_511.getKeyGeneratorAlgorithmName())))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				X9ECParameters ecP = CustomNamedCurves.getByName("M-511");
				keyPairGenerator.initialize(new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(),
				        ecP.getN(), ecP.getH(), ecP.getSeed()), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType!=null && (signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_41417.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_41417.getKeyGeneratorAlgorithmName())
					|| signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_41417.getKeyGeneratorAlgorithmName())))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				X9ECParameters ecP = CustomNamedCurves.getByName("curve41417");
				keyPairGenerator.initialize(new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(),
				        ecP.getN(), ecP.getH(), ecP.getSeed()), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType!=null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BCPQC_SPHINCS256_SHA3_512.getKeyGeneratorAlgorithmName()))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA3_256), _random.getJavaNativeSecureRandom());
			}
			else if (signatureType!=null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BCPQC_SPHINCS256_SHA2_512_256.getKeyGeneratorAlgorithmName()))
			{
				this.keySizeBits=signatureType.getDefaultKeySize();
				keyPairGenerator.initialize(new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256), _random.getJavaNativeSecureRandom());
			}
			else
				keyPairGenerator.initialize(new RSAKeyGenParameterSpec(_keySize, RSAKeyGenParameterSpec.F4), _random.getJavaNativeSecureRandom());
		}
		catch(InvalidAlgorithmParameterException e)
		{
			throw new gnu.vm.jgnu.security.InvalidAlgorithmParameterException(e);
		}

	}
	
	

}
