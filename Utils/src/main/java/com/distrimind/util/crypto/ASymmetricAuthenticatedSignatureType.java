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
import org.bouncycastle.crypto.fips.FipsEC;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyPairGeneratorSpi;

import java.security.*;

/**
 * List of signature algorithms
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.4
 */
@SuppressWarnings("DeprecatedIsStillUsed")
public enum ASymmetricAuthenticatedSignatureType {
	@Deprecated
	SHA1withRSA("SHA1withRSA", "RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	SHA256withRSA("SHA256withRSA","RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	SHA384withRSA("SHA384withRSA", "RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	SHA512withRSA("SHA512withRSA", "RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA256withRSA("SHA256withRSA","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA384withRSA("SHA384withRSA","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA512withRSA("SHA512withRSA", "RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA256withRSAandMGF1("SHA256withRSAandMGF1","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA384withRSAandMGF1("SHA384withRSAandMGF1","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA512withRSAandMGF1("SHA512withRSAandMGF1", "RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 3072, 31536000000L, FipsRSA.ALGORITHM, false),
	BC_FIPS_SHA256withECDSA_P_256("SHA256withECDSA", "EC", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 256, 31536000000L, FipsEC.ALGORITHM, false, "P-256"),
	BC_FIPS_SHA384withECDSA_P_384("SHA384withECDSA", "EC", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 384, 31536000000L, FipsEC.ALGORITHM, false, "P-384"),
	BC_FIPS_SHA512withECDSA_P_521("SHA512withECDSA", "EC", CodeProvider.BCFIPS,CodeProvider.BCFIPS,(short) 521, 31536000000L, FipsEC.ALGORITHM, false, "P-521"),
	@Deprecated//prefer BC_Ed25519
	BC_SHA256withECDSA_CURVE_25519("SHA256withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)256, 31536000000L, FipsEC.ALGORITHM, false, "curve25519"),
	@Deprecated//prefer BC_Ed25519
	BC_SHA384withECDSA_CURVE_25519("SHA384withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)256, 31536000000L, FipsEC.ALGORITHM, false, "curve25519"),
	@Deprecated//prefer BC_Ed25519
	BC_SHA512withECDSA_CURVE_25519("SHA512withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)256, 31536000000L, FipsEC.ALGORITHM, false, "curve25519"),
	/*BC_SHA256withECDSA_CURVE_M_221("SHA256withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)383, 31536000000L, FipsEC.ALGORITHM, false, "M221"),
	BC_SHA384withECDSA_CURVE_M_221("SHA384withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)383, 31536000000L, FipsEC.ALGORITHM, false, "M221"),
	BC_SHA512withECDSA_CURVE_M_221("SHA512withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)383, 31536000000L, FipsEC.ALGORITHM, false, "M221"),
	BC_SHA256withECDSA_CURVE_M_383("SHA256withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)383, 31536000000L, FipsEC.ALGORITHM, false, "M383"),
	BC_SHA384withECDSA_CURVE_M_383("SHA384withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)383, 31536000000L, FipsEC.ALGORITHM, false, "M383"),
	BC_SHA512withECDSA_CURVE_M_383("SHA512withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)383, 31536000000L, FipsEC.ALGORITHM, false, "M383"),
	BC_SHA256withECDSA_CURVE_M_511("SHA256withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)511, 31536000000L, FipsEC.ALGORITHM, false, "M511"),
	BC_SHA384withECDSA_CURVE_M_511("SHA384withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)511, 31536000000L, FipsEC.ALGORITHM, false, "M511"),
	BC_SHA512withECDSA_CURVE_M_511("SHA512withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)511, 31536000000L, FipsEC.ALGORITHM, false, "M511"),
	BC_SHA256withECDSA_CURVE_41417("SHA256withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)414, 31536000000L, FipsEC.ALGORITHM, false, "curve41417"),
	BC_SHA384withECDSA_CURVE_41417("SHA384withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)414, 31536000000L, FipsEC.ALGORITHM, false, "curve41417"),
	BC_SHA512withECDSA_CURVE_41417("SHA512withECDSA", "ECDSA", CodeProvider.BCFIPS,CodeProvider.BC, (short)414, 31536000000L, FipsEC.ALGORITHM, false, "curve41417"),*/
	BCPQC_SPHINCS256_SHA2_512_256("SHA512withSPHINCS256", "SHA512withSPHINCS256", CodeProvider.BCPQC,CodeProvider.BCPQC, (short)1024, 31536000000L, null, true),
	BCPQC_SPHINCS256_SHA3_512("SHA3-512withSPHINCS256", "SHA3-256withSPHINCS256", CodeProvider.BCPQC,CodeProvider.BCPQC, (short)1024, 31536000000L, null, true),
	BC_Ed25519("EdDSA", "Ed25519", CodeProvider.BC,CodeProvider.BC, (short)256, 31536000000L, null, false, "Ed25519"),
	BC_Ed448("EdDSA", "Ed448", CodeProvider.BC,CodeProvider.BC, (short)448, 31536000000L, null, false, "Ed448"),
	/*BC_X25519("EdDSA", "X25519", CodeProvider.BC,CodeProvider.BC, (short)256, 31536000000L, null, false, "X25519"),
	BC_X448("EdDSA", "X448", CodeProvider.BC,CodeProvider.BC, (short)448, 31536000000L, null, false, "X448"),*/
	DEFAULT(BC_FIPS_SHA384withRSAandMGF1);

	private final String signatureAlgorithmName;
	private final String keyGeneratorAlgorithmName;

	private final CodeProvider codeProviderSignature, codeProviderKeyGenerator;
	
	private final short keySizeBits;

	private final long expirationTimeMilis;
	
	private final Algorithm bcAlgorithm;
	
	private final boolean isPostQuantumAlgorithm;

	private final String curveName;

	ASymmetricAuthenticatedSignatureType(String signatureAlgorithmName, String keyGeneratorAlgorithmName, CodeProvider codeProviderSignature, CodeProvider codeProviderKeyGenerator, short keySizeBits, long expirationTimeMilis, Algorithm bcAlgorithm, boolean isPostQuantumAlgorithm) {
		this(signatureAlgorithmName, keyGeneratorAlgorithmName, codeProviderSignature, codeProviderKeyGenerator, keySizeBits, expirationTimeMilis, bcAlgorithm, isPostQuantumAlgorithm, null);
	}
	ASymmetricAuthenticatedSignatureType(String signatureAlgorithmName, String keyGeneratorAlgorithmName, CodeProvider codeProviderSignature, CodeProvider codeProviderKeyGenerator, short keySizeBits, long expirationTimeMilis, Algorithm bcAlgorithm, boolean isPostQuantumAlgorithm, String curveName) {
		this.signatureAlgorithmName = signatureAlgorithmName;
		this.keyGeneratorAlgorithmName=keyGeneratorAlgorithmName;
		this.codeProviderSignature = codeProviderSignature;
		this.codeProviderKeyGenerator = codeProviderKeyGenerator;
		this.keySizeBits = keySizeBits;
		this.expirationTimeMilis=expirationTimeMilis;
		this.bcAlgorithm=bcAlgorithm;
		this.isPostQuantumAlgorithm=isPostQuantumAlgorithm;
		this.curveName=curveName;
		
	}
	ASymmetricAuthenticatedSignatureType(ASymmetricAuthenticatedSignatureType other) {
		this(other.signatureAlgorithmName, other.keyGeneratorAlgorithmName, other.codeProviderSignature, other.codeProviderKeyGenerator, other.keySizeBits, other.expirationTimeMilis, other.bcAlgorithm, other.isPostQuantumAlgorithm, other.curveName);
	}

	public String getCurveName() {
		return curveName;
	}

	public String getSignatureAlgorithmName() {
		
		return signatureAlgorithmName;
	}
	
	public String getKeyGeneratorAlgorithmName()
	{
		return keyGeneratorAlgorithmName;
	}
	
	public short getDefaultKeySize()
	{
		return keySizeBits;
	}



	public AbstractSignature getSignatureInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
		CodeProvider.encureProviderLoaded(codeProviderSignature);
		if (codeProviderSignature == CodeProvider.GNU_CRYPTO) {
			return new GnuSignature(GnuFunctions.getSignatureAlgorithm(signatureAlgorithmName));
		} else if (codeProviderSignature == CodeProvider.BCFIPS || codeProviderSignature == CodeProvider.BC || codeProviderSignature == CodeProvider.BCPQC) {

			Signature s=Signature.getInstance(signatureAlgorithmName, codeProviderSignature.name());

			return new JavaNativeSignature(s);

		} else {
			return new JavaNativeSignature(Signature.getInstance(signatureAlgorithmName, codeProviderSignature.checkProviderWithCurrentOS().name()));
		}
	}

	/**
	 * Works well only with RSA algorithms.
	 * @param keySize the size of the used key
	 * @return the signature size in bits
	 */
	@Deprecated
	public int getSignatureSizeBits(int keySize) {
		if (this==BC_FIPS_SHA256withRSAandMGF1 || this== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withRSAandMGF1 || this== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withRSAandMGF1)
			return keySize+464;
		else if (this==BC_SHA256withECDSA_CURVE_25519)
			return 560;
		else if (this==BC_SHA384withECDSA_CURVE_25519)
			return 560;
		else if (this==BC_SHA512withECDSA_CURVE_25519)
			return 560;
		else if (this==BC_Ed448)
			return 912;
		else if (this==BC_Ed25519)
			return 512;
		/*else if (this==BC_SHA256withECDSA_CURVE_41417)
			return 560;
		else if (this==BC_SHA384withECDSA_CURVE_41417)
			return 560;
		else if (this==BC_SHA512withECDSA_CURVE_41417)
			return 560;
		else if (this==BC_SHA256withECDSA_CURVE_M_511)
			return 560;
		else if (this==BC_SHA384withECDSA_CURVE_M_511)
			return 560;
		else if (this==BC_SHA512withECDSA_CURVE_M_511)
			return 560;
		else if (this==BC_SHA256withECDSA_CURVE_M_383)
			return 560;
		else if (this==BC_SHA384withECDSA_CURVE_M_383)
			return 560;
		else if (this==BC_SHA512withECDSA_CURVE_M_383)
			return 560;
		else if (this==BC_SHA256withECDSA_CURVE_M_221)
			return 560;
		else if (this==BC_SHA384withECDSA_CURVE_M_221)
			return 560;
		else if (this==BC_SHA512withECDSA_CURVE_M_221)
			return 560;*/
		else if (this==BCPQC_SPHINCS256_SHA2_512_256)
			return 328000;
		else if (this==BCPQC_SPHINCS256_SHA3_512)
			return 328000;
		else if (this== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256)
			return 1112;
		else if (this== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384 || this== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521)
			return 1104;
		return keySize;
	}
	@Deprecated
	public int getSignatureSizeBytes(int keySize) {
		return getSignatureSizeBits(keySize) / 8;
	}

	public CodeProvider getCodeProviderForSignature() {
		return codeProviderSignature;
	}
	public CodeProvider getCodeProviderForKeyGenerator() {
		return codeProviderKeyGenerator;
	}
	static ASymmetricAuthenticatedSignatureType valueOf(int ordinal) throws IllegalArgumentException {
		for (ASymmetricAuthenticatedSignatureType a : values()) {
			if (a.ordinal() == ordinal)
				return a;
		}
		throw new IllegalArgumentException();
	}
	/*public int getMaxBlockSize(int keySizeBits) {
		return keySizeBits / 8 - blockSizeDecrement;
	}*/
	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize,
			long expirationTimeUTC) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		CodeProvider.encureProviderLoaded(codeProviderSignature);
		if (codeProviderKeyGenerator == CodeProvider.GNU_CRYPTO) {
			KeyPairGenerator kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kgp);
			res.initialize(keySize, expirationTimeUTC, random);

			return res;
		} else if (codeProviderKeyGenerator == CodeProvider.BCFIPS || codeProviderKeyGenerator == CodeProvider.BC || codeProviderKeyGenerator == CodeProvider.BCPQC) {

				
					
			KeyPairGenerator kgp;
			if (this.getKeyGeneratorAlgorithmName().equals(BCPQC_SPHINCS256_SHA3_512.getKeyGeneratorAlgorithmName()) || this.getKeyGeneratorAlgorithmName().equals(BCPQC_SPHINCS256_SHA2_512_256.getKeyGeneratorAlgorithmName()))
			{
				kgp=new Sphincs256KeyPairGeneratorSpi();

			}
			else
				kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName, codeProviderKeyGenerator.name());
			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
			res.initialize(keySize, expirationTimeUTC, random);

			return res;
		} else {
			KeyPairGenerator kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName, codeProviderKeyGenerator.checkProviderWithCurrentOS().name());

			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
			res.initialize(keySize, expirationTimeUTC, random);

			return res;

		}

	}
	
	Algorithm getBouncyCastleAlgorithm()
	{
		return bcAlgorithm;
	}
	public boolean isPostQuantumAlgorithm() {
		return isPostQuantumAlgorithm;
	}



}
