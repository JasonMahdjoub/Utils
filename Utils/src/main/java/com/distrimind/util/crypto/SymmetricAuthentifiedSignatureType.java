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


import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.fips.FipsSHS;
import org.bouncycastle.crypto.fips.FipsSHS.AuthParameters;

import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.10.0
 */
public enum SymmetricAuthentifiedSignatureType {
	HMAC_SHA2_256("HmacSHA256", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_256, null), 
	HMAC_SHA2_384("HmacSHA384", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_384, null), 
	HMAC_SHA2_512("HmacSHA512", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_512, null),
    BC_FIPS_HMAC_SHA2_256("HmacSHA256", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_256, FipsSHS.SHA256_HMAC),
	BC_FIPS_HMAC_SHA2_384("HmacSHA384", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_384, FipsSHS.SHA384_HMAC), 
	BC_FIPS_HMAC_SHA2_512("HmacSHA512", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_512, FipsSHS.SHA512_HMAC),
	BC_FIPS_HMAC_SHA2_512_224("HmacSHA512/224", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_512_224, FipsSHS.SHA512_224_HMAC),
	BC_FIPS_HMAC_SHA2_512_256("HmacSHA512/256", CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA2_512_256, FipsSHS.SHA512_256_HMAC),
	BC_HMAC_SHA3_256("HmacSHA3-256", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA3_256, null),
	BC_HMAC_SHA3_384("HmacSHA3-384", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA3_384, null),
	BC_HMAC_SHA3_512("HmacSHA3-512", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_FIPS_SHA3_512, null),
    HMAC_SHA2_512_224("HmacSHA512/224", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_512_224, null, BC_FIPS_HMAC_SHA2_512_224),
    HMAC_SHA2_512_256("HmacSHA512/256", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA2_512_256, null, BC_FIPS_HMAC_SHA2_512_256),
    HMAC_SHA3_256("HmacSHA3-256", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA3_256, null, BC_HMAC_SHA3_256),
    HMAC_SHA3_384("HmacSHA3-384", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA3_384, null, BC_HMAC_SHA3_384),
    HMAC_SHA3_512("HmacSHA3-512", CodeProvider.SunJCE, CodeProvider.SunJCE, (short)128, (short)16, MessageDigestType.SHA3_512, null, BC_HMAC_SHA3_512),
	BC_HMAC_BLAKE2B_160("HmacBLAKE2B56", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_BLAKE2B_160, null),
	BC_HMAC_BLAKE2B_256("HmacBLAKE2B56", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_BLAKE2B_256, null),
	BC_HMAC_BLAKE2B_384("HmacBLAKE2B384", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_BLAKE2B_384, null),
	BC_HMAC_BLAKE2B_512("HmacBLAKE2B512", CodeProvider.BC, CodeProvider.BC, (short)128, (short)16, MessageDigestType.BC_BLAKE2B_512, null),
	//BC_FIPS_HMAC_WHIRLPOOL("HmacWHIRLPOOL",CodeProvider.BCFIPS, CodeProvider.BCFIPS, (short)128, (short)16, MessageDigestType.BC_WHIRLPOOL, FipsSHS.WHIRPOOL_HMAC),
	DEFAULT(HMAC_SHA2_256);

	private final String algorithmName;
	private final CodeProvider codeProviderForSignature, codeProviderForKeyGenerator;
	private final short keySizeBits;
	private final short keySizeBytes;
	private final MessageDigestType messageDigestType;
	private final AuthParameters messageDigestAuth;
    private final SymmetricAuthentifiedSignatureType replacer;

	
	SymmetricAuthentifiedSignatureType(String algorithmName, CodeProvider codeProviderForSignature, CodeProvider codeProviderForKeyGenerator, short keySizeBits, short keySizeBytes, MessageDigestType messageDigestType, AuthParameters messageDigestAuth) {
        this(algorithmName,codeProviderForSignature, codeProviderForKeyGenerator, keySizeBits, keySizeBytes, messageDigestType, messageDigestAuth, null);

	}
    SymmetricAuthentifiedSignatureType(String algorithmName, CodeProvider codeProviderForSignature, CodeProvider codeProviderForKeyGenerator, short keySizeBits, short keySizeBytes, MessageDigestType messageDigestType, AuthParameters messageDigestAuth, SymmetricAuthentifiedSignatureType replacer) {
        this.algorithmName = algorithmName;
        this.codeProviderForSignature = codeProviderForSignature;
        this.codeProviderForKeyGenerator=codeProviderForKeyGenerator;
        this.keySizeBits=keySizeBits;
        this.keySizeBytes=keySizeBytes;
        this.messageDigestType=messageDigestType;
        this.messageDigestAuth=messageDigestAuth;
        this.replacer=replacer;
    }

	public SymmetricSecretKey generateSecretKeyFromByteArray(byte[] tab) throws NoSuchProviderException, NoSuchAlgorithmException {
		return generateSecretKeyFromByteArray(tab, getDefaultKeySizeBits());
	}

	public SymmetricSecretKey generateSecretKeyFromByteArray(byte[] tab, short keySizeBits) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (keySizeBits<56 || keySizeBits>512)
			throw new IllegalArgumentException();
		AbstractMessageDigest md=(keySizeBits>256?MessageDigestType.SHA3_512:MessageDigestType.SHA3_256).getMessageDigestInstance();
		md.update(tab);
		byte[] d=md.digest();
		return new SymmetricSecretKey(this, Arrays.copyOfRange(d, 0, keySizeBits/8), keySizeBits);
	}
	
	
	AuthParameters getMessageDigestAuth() {
		return messageDigestAuth;
	}



	SymmetricAuthentifiedSignatureType(SymmetricAuthentifiedSignatureType other) {
		
		this(other.algorithmName, other.codeProviderForSignature, other.codeProviderForKeyGenerator, other.keySizeBits, other.keySizeBytes, other.messageDigestType, other.messageDigestAuth, other.replacer);
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

	public AbstractMac getHMacInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
		CodeProvider.encureProviderLoaded(codeProviderForSignature);
		if (codeProviderForSignature == CodeProvider.GNU_CRYPTO) {
			return new GnuMac(GnuFunctions.macGetInstance(algorithmName));
		} else if (codeProviderForSignature == CodeProvider.BCFIPS ) {
			return new BCFIPSMac(this);

		} else if (codeProviderForSignature == CodeProvider.BC) {
			return new BCMac(this);

		} else {
			try {
				return new JavaNativeMac(javax.crypto.Mac.getInstance(algorithmName, codeProviderForSignature.checkProviderWithCurrentOS().name()));
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			    if (replacer!=null)
			        return replacer.getHMacInstance();
				throw e;
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
		CodeProvider.encureProviderLoaded(codeProviderForKeyGenerator);
		AbstractKeyGenerator res ;
		if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			res = new GnuKeyGenerator(this, GnuFunctions.keyGeneratorGetInstance(algorithmName));
		} else if (codeProviderForKeyGenerator == CodeProvider.BCFIPS || codeProviderForKeyGenerator == CodeProvider.BC) {

			res = new BCKeyGenerator(this);

		} else {
			try {
				res = new JavaNativeKeyGenerator(this, javax.crypto.KeyGenerator.getInstance(algorithmName, codeProviderForKeyGenerator.checkProviderWithCurrentOS().name()));
			} catch (java.security.NoSuchAlgorithmException e) {
			    if (replacer!=null)
			        return replacer.getKeyGenerator(random, keySizeBits);
				throw new NoSuchAlgorithmException(e);
			}catch (java.security.NoSuchProviderException e) {
                if (replacer!=null)
                    return replacer.getKeyGenerator(random, keySizeBits);
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
			return new SymmetricSecretKey(this,GnuFunctions.secretKeySpecGetInstance(secretKey, getAlgorithmName()), keySizeBits);
		} else
			throw new IllegalAccessError();

	}
	Algorithm getBouncyCastleAlgorithm()
	{
		return org.bouncycastle.crypto.general.AES.ALGORITHM;
	}
	
	public boolean isPostQuantumAlgorithm(short keySizeBits) 
	{
		return keySizeBits >= 256;
	}

}
