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


import javax.crypto.spec.SecretKeySpec;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnux.crypto.KeyGenerator;
import gnu.vm.jgnux.crypto.Mac;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 2.10.0
 */
public enum SymmetricAuthentifiedSignatureType {
	HMAC_SHA_256("HmacSHA256", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_256), 
	HMAC_SHA_384("HmacSHA384", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_384), 
	HMAC_SHA_512("HmacSHA512", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_512), 
	BC_FIPS_HMAC_SHA_256("HmacSHA256", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_256), 
	BC_FIPS_HMAC_SHA_384("HmacSHA384", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_384), 
	BC_FIPS_HMAC_SHA_512("HmacSHA512", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_512), 
	BC_FIPS_HMAC_WHIRLPOOL("HmacWHIRLPOOL",CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_WHIRLPOOL), 
	DEFAULT(BC_FIPS_HMAC_SHA_256);

	private final String algorithmName;
	private final CodeProvider codeProviderForSignature, codeProviderForKeyGenerator;
	private final short keySizeBits;
	private final short keySizeBytes;
	private final MessageDigestType messageDigestType;

		
	
	private SymmetricAuthentifiedSignatureType(String algorithmName, CodeProvider codeProviderForSignature, CodeProvider codeProviderForKeyGenerator, short keySizeBits, short keySizeBytes, MessageDigestType messageDigestType) {
		this.algorithmName = algorithmName;
		this.codeProviderForSignature = codeProviderForSignature;
		this.codeProviderForKeyGenerator=codeProviderForKeyGenerator;
		this.keySizeBits=keySizeBits;
		this.keySizeBytes=keySizeBytes;
		this.messageDigestType=messageDigestType;
	}

	private SymmetricAuthentifiedSignatureType(SymmetricAuthentifiedSignatureType other) {
		this(other.algorithmName, other.codeProviderForSignature, other.codeProviderForKeyGenerator, other.keySizeBits, other.keySizeBytes, other.messageDigestType);
	}

	public int getSignatureSizeInBits()
	{
		return messageDigestType.getDigestLengthInBits();
	}
	
	public MessageDigestType getMessageDigestType()
	{
		return messageDigestType;
	}
	
	public String getAlgorithmName() {
		return algorithmName;
	}

	public AbstractMac getHMacInstance() throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException {
		if (codeProviderForSignature == CodeProvider.GNU_CRYPTO) {
			return new GnuMac(Mac.getInstance(algorithmName));
		} else if (codeProviderForSignature == CodeProvider.BCFIPS) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				return new JavaNativeMac(javax.crypto.Mac.getInstance(algorithmName, codeProviderForSignature.name()));
			} catch (java.security.NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}
			catch(java.security.NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
		} else {
			try {
				return new JavaNativeMac(javax.crypto.Mac.getInstance(algorithmName, codeProviderForSignature.checkProviderWithCurrentOS().name()));
			} catch (java.security.NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}
			catch(java.security.NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
		}
	}

	public CodeProvider getCodeProviderForSignature() {
		return codeProviderForSignature;
	}
	public CodeProvider getCodeProviderForKeyGenerator() {
		return codeProviderForKeyGenerator;
	}

	public short getDefaultKeySizeBits() {
		return keySizeBits;
	}

	public short getDefaultKeySizeBytes() {
		return keySizeBytes;
	}

	public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException {
		return getKeyGenerator(random, keySizeBits);
	}
	
	static SymmetricAuthentifiedSignatureType valueOf(int ordinal) throws IllegalArgumentException {
		for (SymmetricAuthentifiedSignatureType a : values()) {
			if (a.ordinal() == ordinal)
				return a;
		}
		throw new IllegalArgumentException();
	}
	

	public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random, short keySizeBits)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractKeyGenerator res = null;
		if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			res = new GnuKeyGenerator(this, KeyGenerator.getInstance(algorithmName));
		} else if (codeProviderForKeyGenerator == CodeProvider.BCFIPS) {

			try {
				CodeProvider.ensureBouncyCastleProviderLoaded();
				res = new JavaNativeKeyGenerator(this,javax.crypto.KeyGenerator.getInstance(algorithmName, "BCFIPS"));
			} catch (java.security.NoSuchAlgorithmException e) {
				throw new NoSuchAlgorithmException(e);
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
			

		} else {
			try {
				res = new JavaNativeKeyGenerator(this, javax.crypto.KeyGenerator.getInstance(algorithmName, codeProviderForKeyGenerator.checkProviderWithCurrentOS().name()));
			} catch (java.security.NoSuchAlgorithmException e) {
				throw new NoSuchAlgorithmException(e);
			}catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
		}
		res.init(keySizeBits, random);
		return res;

	}
	
	
	public SymmetricSecretKey getSymmetricSecretKey(byte[] secretKey) {
		return this.getSymmetricSecretKey(secretKey, getDefaultKeySizeBits());
	}

	public SymmetricSecretKey getSymmetricSecretKey(byte[] secretKey, short keySizeBits) {
		if (codeProviderForKeyGenerator == CodeProvider.BCFIPS || codeProviderForKeyGenerator == CodeProvider.SunJCE) {
			return new SymmetricSecretKey(this, new SecretKeySpec(secretKey, getAlgorithmName()), keySizeBits);
		} else if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			return new SymmetricSecretKey(this,
					new gnu.vm.jgnux.crypto.spec.SecretKeySpec(secretKey, getAlgorithmName()), keySizeBits);
		} else
			throw new IllegalAccessError();

	}
	
}
