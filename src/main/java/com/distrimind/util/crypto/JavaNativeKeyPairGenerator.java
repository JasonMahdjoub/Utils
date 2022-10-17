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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.security.*;
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
	JavaNativeKeyPairGenerator(EllipticCurveDiffieHellmanType type, KeyPairGenerator keyPairGenerator) {
		super(type);
		this.keyPairGenerator = keyPairGenerator;
		synchronize=false;
		typeToSynchronize=null;
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
			if (encryptionType!=null && encryptionType.getAlgorithmParameterSpecForKeyGenerator()!=null)
			{
				keyPairGenerator.initialize(encryptionType.getAlgorithmParameterSpecForKeyGenerator(), _random);
			}
			else if (ellipticCurveDiffieHellmanType!=null)
			{
				keyPairGenerator.initialize(ellipticCurveDiffieHellmanType.getAlgorithmParameterSpecForKeyGenerator(), _random);
			}
			else if ((signatureType != null && signatureType.getAlgorithmParameterSpecForKeyGenerator() == null) || (encryptionType!=null))
				if ((signatureType!=null && signatureType.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.SHA256withRSA.getKeyGeneratorAlgorithmName()))
					|| encryptionType!=null)
					keyPairGenerator.initialize(new RSAKeyGenParameterSpec(keySize, RSAKeyGenParameterSpec.F4), _random.getJavaNativeSecureRandom());
				else
					throw new IllegalAccessError();
			else if (signatureType!=null){
				keyPairGenerator.initialize(signatureType.getAlgorithmParameterSpecForKeyGenerator(), _random.getJavaNativeSecureRandom());
			}
			else {
				throw new IllegalAccessError();
			}

		}
		catch (InvalidAlgorithmParameterException e){
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
	}
	
	

}
