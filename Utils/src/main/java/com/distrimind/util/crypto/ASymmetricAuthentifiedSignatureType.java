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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;

import gnu.vm.jgnu.security.NoSuchProviderException;

/**
 * List of signature algorithms
 * 
 * @author Jason Mahdjoub
 * @version 4.0
 * @since Utils 1.4
 */
public enum ASymmetricAuthentifiedSignatureType {
	@Deprecated
	SHA1withRSA("SHA1withRSA", "RSA", CodeProvider.SUN,(short) 3072, 31536000000l), 
	SHA256withRSA("SHA256withRSA","RSA", CodeProvider.SUN,(short) 3072, 31536000000l), 
	SHA384withRSA("SHA384withRSA", "RSA", CodeProvider.SUN,(short) 3072, 31536000000l), 
	SHA512withRSA("SHA512withRSA", "RSA", CodeProvider.SUN,(short) 3072, 31536000000l),
	SHA384withECDSA("SHA384withECDSA", "EC", CodeProvider.SUN,(short) 384, 31536000000l),
	BC_FIPS_SHA256withRSA("SHA256withRSA","RSA", CodeProvider.BCFIPS,(short) 3072, 31536000000l), 
	BC_FIPS_SHA384withRSA("SHA384withRSA","RSA", CodeProvider.BCFIPS,(short) 3072, 31536000000l), 
	BC_FIPS_SHA512withRSA("SHA512withRSA", "RSA", CodeProvider.BCFIPS,(short) 3072, 31536000000l),
	BC_FIPS_SHA256withRSAandMGF1("SHA256withRSAandMGF1","RSA", CodeProvider.BCFIPS,(short) 3072, 31536000000l), 
	BC_FIPS_SHA384withRSAandMGF1("SHA384withRSAandMGF1","RSA", CodeProvider.BCFIPS,(short) 3072, 31536000000l), 
	BC_FIPS_SHA512withRSAandMGF1("SHA512withRSAandMGF1", "RSA", CodeProvider.BCFIPS,(short) 3072, 31536000000l),
	BC_FIPS_SHA384withECDSA("SHA384withECDSA", "EC", CodeProvider.BCFIPS,(short) 384, 31536000000l),
	DEFAULT(BC_FIPS_SHA384withRSAandMGF1);

	private final String signatureAlgorithmName;
	private final String keyGeneratorAlgorithmName;

	private final CodeProvider codeProvider;
	
	private final short keySize;

	private final long expirationTimeMilis;



	private ASymmetricAuthentifiedSignatureType(String signatureAlgorithmName, String keyGeneratorAlgorithmName, CodeProvider codeProvider, short keySize, long expirationTimeMilis) {
		this.signatureAlgorithmName = signatureAlgorithmName;
		this.keyGeneratorAlgorithmName=keyGeneratorAlgorithmName;
		this.codeProvider = codeProvider;
		this.keySize=keySize;
		this.expirationTimeMilis=expirationTimeMilis;
	}
	private ASymmetricAuthentifiedSignatureType(ASymmetricAuthentifiedSignatureType other) {
		this(other.signatureAlgorithmName, other.keyGeneratorAlgorithmName, other.codeProvider, other.keySize, other.expirationTimeMilis);
	}

	public String getSignatureAlgorithmName() {
		return signatureAlgorithmName;
	}
	
	public String getKeyGeneratorAlgorithmName()
	{
		return keyGeneratorAlgorithmName;
	}

	public AbstractSignature getSignatureInstance() throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException {
		if (codeProvider == CodeProvider.GNU_CRYPTO) {
			return new GnuSignature(gnu.vm.jgnu.security.Signature.getInstance(signatureAlgorithmName));
		} else if (codeProvider == CodeProvider.BCFIPS) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				Signature s=Signature.getInstance(signatureAlgorithmName, CodeProvider.BCFIPS.name());
					
				return new JavaNativeSignature(s);
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			} 

		} else {
			try {
				return new JavaNativeSignature(Signature.getInstance(signatureAlgorithmName));
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}
		}
	}

	public int getSignatureSizeBits(int keySize) {
		return keySize;
	}

	public int getSignatureSizeBytes(int keySize) {
		return keySize / 8;
	}

	public CodeProvider getCodeProvider() {
		return codeProvider;
	}
	static ASymmetricAuthentifiedSignatureType valueOf(int ordinal) throws IllegalArgumentException {
		for (ASymmetricAuthentifiedSignatureType a : values()) {
			if (a.ordinal() == ordinal)
				return a;
		}
		throw new IllegalArgumentException();
	}
	/*public int getMaxBlockSize(int keySize) {
		return keySize / 8 - blockSizeDecrement;
	}*/
	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize,
			long expirationTimeUTC) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException {
		if (codeProvider == CodeProvider.GNU_CRYPTO) {
			gnu.vm.jgnu.security.KeyPairGenerator kgp = gnu.vm.jgnu.security.KeyPairGenerator.getInstance(keyGeneratorAlgorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kgp);
			res.initialize(keySize, expirationTimeUTC, random);

			return res;
		} else if (codeProvider == CodeProvider.BCFIPS) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				KeyPairGenerator kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName, CodeProvider.BCFIPS.name());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySize, expirationTimeUTC, random);	
				
				return res;
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}
			catch(java.security.NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			} 
		} else {
			try {
				KeyPairGenerator kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName);
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySize, expirationTimeUTC, random);

				return res;
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}

		}

	}	

}
