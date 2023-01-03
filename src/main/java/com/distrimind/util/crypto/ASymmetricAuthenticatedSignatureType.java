/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.fips.FipsEC;
import com.distrimind.bcfips.crypto.fips.FipsRSA;
import com.distrimind.bcfips.jcajce.spec.EdDSAParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.provider.dilithium.DilithiumKeyPairGeneratorSpi;
import com.distrimind.bouncycastle.pqc.jcajce.provider.falcon.FalconKeyPairGeneratorSpi;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyPairGeneratorSpi;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyPairGeneratorSpi;
import com.distrimind.bouncycastle.pqc.jcajce.spec.DilithiumParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.spec.FalconParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.spec.SPHINCS256KeyGenParameterSpec;
import com.distrimind.bouncycastle.pqc.jcajce.spec.SPHINCSPlusParameterSpec;

import java.io.IOException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

/**
 * List of signature algorithms
 * 
 * @author Jason Mahdjoub
 * @version 5.2
 * @since Utils 1.4
 */
@SuppressWarnings({"DeprecatedIsStillUsed"})
public enum ASymmetricAuthenticatedSignatureType {
	@Deprecated
	SHA1withRSA("SHA1withRSA", "RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	SHA256withRSA("SHA256withRSA","RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	SHA384withRSA("SHA384withRSA", "RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	SHA512withRSA("SHA512withRSA", "RSA", CodeProvider.SunRsaSign,CodeProvider.SunRsaSign, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA256withRSA("SHA256withRSA","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA384withRSA("SHA384withRSA","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA512withRSA("SHA512withRSA", "RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA256withRSAandMGF1("SHA256withRSAandMGF1","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA384withRSAandMGF1("SHA384withRSAandMGF1","RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA512withRSAandMGF1("SHA512withRSAandMGF1", "RSA", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 3072, 31536000000L, FipsRSA.ALGORITHM, false, null),
	BC_FIPS_SHA256withECDSA_P_256("SHA256withECDSA", "EC", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 256, 31536000000L, FipsEC.ALGORITHM, false, new ECGenParameterSpec( "P-256")),
	BC_FIPS_SHA384withECDSA_P_384("SHA384withECDSA", "EC", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 384, 31536000000L, FipsEC.ALGORITHM, false, new ECGenParameterSpec("P-384")),
	BC_FIPS_SHA512withECDSA_P_521("SHA512withECDSA", "EC", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 528, 31536000000L, FipsEC.ALGORITHM, false, new ECGenParameterSpec("P-521")),
	@Deprecated
	BCPQC_SPHINCS256_SHA2_512_256("SHA512withSPHINCS256", "SPHINCS256", CodeProvider.BCPQC,CodeProvider.BCPQC, 1024, 31536000000L, null, true, new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA512_256)),
	@Deprecated
	BCPQC_SPHINCS256_SHA3_512("SHA3-512withSPHINCS256", "SPHINCS256", CodeProvider.BCPQC,CodeProvider.BCPQC, 1024, 31536000000L, null, true, new SPHINCS256KeyGenParameterSpec(SPHINCS256KeyGenParameterSpec.SHA3_256)),
	BC_FIPS_Ed25519("EdDSA", "Ed25519", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 256, 31536000000L, null, false, new EdDSAParameterSpec("Ed25519")),
	BC_FIPS_Ed448("EdDSA", "Ed448", CodeProvider.BCFIPS,CodeProvider.BCFIPS, 448, 31536000000L, null, false, new EdDSAParameterSpec("Ed448")),
	BCPQC_SPHINCS_PLUS_SHA256_SLOW("SPHINCSPLUS", "SPHINCSPLUS", CodeProvider.BCPQC,CodeProvider.BCPQC, 720, 31536000000L, null, true, SPHINCSPlusParameterSpec.sha2_256s),
	BCPQC_SPHINCS_PLUS_SHA256_FAST("SPHINCSPLUS", "SPHINCSPLUS", CodeProvider.BCPQC,CodeProvider.BCPQC, 720, 31536000000L, null, true, SPHINCSPlusParameterSpec.sha2_256f),
	BCPQC_SPHINCS_PLUS_SHAKE256_SLOW("SPHINCSPLUS", "SPHINCSPLUS", CodeProvider.BCPQC,CodeProvider.BCPQC, 720, 31536000000L, null, true, SPHINCSPlusParameterSpec.shake_256s),
	BCPQC_SPHINCS_PLUS_SHAKE256_FAST("SPHINCSPLUS", "SPHINCSPLUS", CodeProvider.BCPQC,CodeProvider.BCPQC, 720, 31536000000L, null, true, SPHINCSPlusParameterSpec.shake_256f),
	BCPQC_CHRYSTALS_DILITHIUM_2("Dilithium", "Dilithium", CodeProvider.BCPQC,CodeProvider.BCPQC, 10768, 31536000000L, null, true, DilithiumParameterSpec.dilithium2),
	BCPQC_CHRYSTALS_DILITHIUM_3("Dilithium", "Dilithium", CodeProvider.BCPQC,CodeProvider.BCPQC, 15888, 31536000000L, null, true, DilithiumParameterSpec.dilithium3),
	BCPQC_CHRYSTALS_DILITHIUM_5("Dilithium", "Dilithium", CodeProvider.BCPQC,CodeProvider.BCPQC, 21008, 31536000000L, null, true, DilithiumParameterSpec.dilithium5),
	BCPQC_CHRYSTALS_DILITHIUM_2_AES("Dilithium", "Dilithium", CodeProvider.BCPQC,CodeProvider.BCPQC, 10768, 31536000000L, null, true, DilithiumParameterSpec.dilithium2_aes),
	BCPQC_CHRYSTALS_DILITHIUM_3_AES("Dilithium", "Dilithium", CodeProvider.BCPQC,CodeProvider.BCPQC, 15888, 31536000000L, null, true, DilithiumParameterSpec.dilithium3_aes),
	BCPQC_CHRYSTALS_DILITHIUM_5_AES("Dilithium", "Dilithium", CodeProvider.BCPQC,CodeProvider.BCPQC, 21008, 31536000000L, null, true, DilithiumParameterSpec.dilithium5_aes),
	BCPQC_FALCON_512("Falcon", "Falcon", CodeProvider.BCPQC,CodeProvider.BCPQC, 7376, 31536000000L, null, true, FalconParameterSpec.falcon_512),
	BCPQC_FALCON_1024("Falcon", "Falcon", CodeProvider.BCPQC,CodeProvider.BCPQC, 14544, 31536000000L, null, true, FalconParameterSpec.falcon_1024),
	DEFAULT(BC_FIPS_SHA384withRSAandMGF1);

	private final String signatureAlgorithmName;

	private final String keyGeneratorAlgorithmName;

	private final CodeProvider codeProviderSignature, codeProviderKeyGenerator;
	
	private final int keySizeBits;

	private final long expirationTimeMilis;
	
	private final Algorithm bcAlgorithm;
	
	private final boolean isPostQuantumAlgorithm;

	private ASymmetricAuthenticatedSignatureType derivedType;
	private final AlgorithmParameterSpec algorithmParameterSpecForKeyGenerator;

	static final int META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY=24;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE =140+META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY =1024+META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE =140+META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY;

	static final int META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_PRIVATE_KEY=8;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE +META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY =MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY /3*2+META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY;

	public static final int META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR =27;

	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE +MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_KEY_PAIR =MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY +MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY + META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE +MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE +MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;

	static final int META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY =4;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE=MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE=MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE=MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE;

	static final int META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY =4;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE=MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY +ASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE=MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_RSA_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_SIGNATURE + META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_SIGNATURE=MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE;

	public static final int META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR =4;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_SIGNATURE+MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_SIGNATURE+ META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE =MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITHOUT_RSA_FOR_SIGNATURE+MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITHOUT_RSA_FOR_SIGNATURE+ META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_SIGNATURE+MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_SIGNATURE+ META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;

	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE =MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITHOUT_RSA_FOR_SIGNATURE;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_SIGNATURE = MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_SIGNATURE;


	public final static int MAX_SIZE_IN_BYTES_OF_NON_PQC_ASYMMETRIC_SIGNATURE =442;
	public final static int MAX_SIZE_IN_BYTES_PQC_ASYMMETRIC_SIGNATURE =50000;
	public final static int MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE =/*Math.max(MAX_NON_PQC_ASYMMETRIC_SIGNATURE_SIZE, */MAX_SIZE_IN_BYTES_PQC_ASYMMETRIC_SIGNATURE/*)*/;




	public boolean equals(ASymmetricAuthenticatedSignatureType type)
	{
		if (type==this)
			return true;
		if (type==null)
			return false;
		//noinspection StringEquality
		return type.signatureAlgorithmName==this.signatureAlgorithmName && type.keyGeneratorAlgorithmName==this.keyGeneratorAlgorithmName
				&& type.codeProviderKeyGenerator==this.codeProviderKeyGenerator && type.codeProviderSignature==this.codeProviderSignature;
	}

	long getDefaultExpirationTimeMilis() {
		return expirationTimeMilis;
	}


	ASymmetricAuthenticatedSignatureType(String signatureAlgorithmName, String keyGeneratorAlgorithmName, CodeProvider codeProviderSignature, CodeProvider codeProviderKeyGenerator, int keySizeBits, long expirationTimeMilis, Algorithm bcAlgorithm, boolean isPostQuantumAlgorithm, AlgorithmParameterSpec algorithmParameterSpecForKeyGenerator) {
		this.signatureAlgorithmName = signatureAlgorithmName;
		this.keyGeneratorAlgorithmName=keyGeneratorAlgorithmName;
		this.codeProviderSignature = codeProviderSignature;
		this.codeProviderKeyGenerator = codeProviderKeyGenerator;
		this.keySizeBits = keySizeBits;
		this.expirationTimeMilis=expirationTimeMilis;
		this.bcAlgorithm=bcAlgorithm;
		this.isPostQuantumAlgorithm=isPostQuantumAlgorithm;

		this.derivedType=this;
		this.algorithmParameterSpecForKeyGenerator = algorithmParameterSpecForKeyGenerator;
	}

	ASymmetricAuthenticatedSignatureType(ASymmetricAuthenticatedSignatureType other) {
		this(other.signatureAlgorithmName, other.keyGeneratorAlgorithmName, other.codeProviderSignature, other.codeProviderKeyGenerator, other.keySizeBits, other.expirationTimeMilis, other.bcAlgorithm, other.isPostQuantumAlgorithm, other.algorithmParameterSpecForKeyGenerator);
		this.derivedType=other;
	}

	public AlgorithmParameterSpec getAlgorithmParameterSpecForKeyGenerator() {
		return algorithmParameterSpecForKeyGenerator;
	}

	public String getSignatureAlgorithmName() {
		
		return signatureAlgorithmName;
	}
	
	public String getKeyGeneratorAlgorithmName()
	{
		return keyGeneratorAlgorithmName;
	}
	
	public int getDefaultKeySize()
	{
		return keySizeBits;
	}



	public AbstractSignature getSignatureInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
		//CodeProvider.ensureProviderLoaded(codeProviderSignature);
		if (codeProviderSignature == CodeProvider.GNU_CRYPTO) {
			return new GnuSignature(GnuFunctions.getSignatureAlgorithm(signatureAlgorithmName));
		} else if (codeProviderSignature == CodeProvider.BCFIPS || codeProviderSignature == CodeProvider.BC || codeProviderSignature == CodeProvider.BCPQC) {

			Signature s=Signature.getInstance(signatureAlgorithmName, codeProviderSignature.getCompatibleProvider());

			return new JavaNativeSignature(s, this);

		} else {
			return new JavaNativeSignature(Signature.getInstance(signatureAlgorithmName, codeProviderSignature.getCompatibleProvider()), this);
		}
	}
	/**
	 * Gets the signature size
	 * @param keySizeBits the size of the used key in bits
	 * @return the maximum signature size in bits
	 */

	public int getMaximumSignatureSizeBits(int keySizeBits) {
		return getSignatureSizeBits(keySizeBits);
	}
	/**
	 * Gets the signature size
	 * @param keySizeBits the size of the used key in bits
	 * @return the maximum signature size in bytes
	 */

	public int getMaximumSignatureSizeBytes(int keySizeBits) {
		return getSignatureSizeBits(keySizeBits)/8;
	}
	/**
	 * Works well only with RSA algorithms.
	 * @param keySizeBits the size of the used key in bits
	 * @return the signature size in bits
	 */
	@SuppressWarnings("DeprecatedIsStillUsed")
	@Deprecated
	public int getSignatureSizeBits(int keySizeBits) {
		ASymmetricAuthenticatedSignatureType dt=this.getDerivedType();
		if (dt==BC_FIPS_SHA256withRSAandMGF1 || dt== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withRSAandMGF1 || dt== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withRSAandMGF1)
			return keySizeBits+464;
		/*else if (this==BC_SHA256withECDSA_CURVE_25519)
			return 560;
		else if (this==BC_SHA384withECDSA_CURVE_25519)
			return 560;
		else if (this==BC_SHA512withECDSA_CURVE_25519)
			return 560;*/
		else if (dt== BC_FIPS_Ed448)
			return 912;
		else if (dt== BC_FIPS_Ed25519)
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
		else if (dt==BCPQC_SPHINCS256_SHA2_512_256)
			return 328000;
		else if (dt==BCPQC_SPHINCS256_SHA3_512)
			return 328000;
		else if (dt==BCPQC_SPHINCS_PLUS_SHA256_SLOW || dt==BCPQC_SPHINCS_PLUS_SHA256_FAST || dt==BCPQC_SPHINCS_PLUS_SHAKE256_SLOW || dt==BCPQC_SPHINCS_PLUS_SHAKE256_FAST)
			return 238336;
		else if (dt==BCPQC_CHRYSTALS_DILITHIUM_2 || dt==BCPQC_CHRYSTALS_DILITHIUM_2_AES) {
			return 19360;
		}
		else if (dt==BCPQC_CHRYSTALS_DILITHIUM_3 || dt==BCPQC_CHRYSTALS_DILITHIUM_3_AES) {
			return 26344;
		}
		else if (dt==BCPQC_CHRYSTALS_DILITHIUM_5 || dt==BCPQC_CHRYSTALS_DILITHIUM_5_AES) {
			return 36760;
		}
		else if (dt==BCPQC_FALCON_512) {
			return 5360;
		}
		else if (dt==BCPQC_FALCON_1024) {
			return 10320;
		}
		else if (dt== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256)
			return 1112;
		else if (dt== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384 || dt== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521)
			return 1104;
		return keySizeBits;
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
	public AbstractKeyPairGenerator<ASymmetricKeyPair> getKeyPairGenerator(AbstractSecureRandom random)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis(), System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator<ASymmetricKeyPair> getKeyPairGenerator(AbstractSecureRandom random, int keySize)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis(), System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator<ASymmetricKeyPair> getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits,
														long publicKeyValidityBeginDateUTC, long expirationTimeUTC) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		if (keySizeBits<0)
			keySizeBits= this.keySizeBits;
		//CodeProvider.ensureProviderLoaded(codeProviderSignature);
		if (codeProviderKeyGenerator == CodeProvider.GNU_CRYPTO) {
			KeyPairGenerator kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kgp);
			res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);

			return res;
		} else if (codeProviderKeyGenerator == CodeProvider.BCFIPS || codeProviderKeyGenerator == CodeProvider.BC || codeProviderKeyGenerator == CodeProvider.BCPQC) {

				
					
			KeyPairGenerator kgp;
			if (this.getKeyGeneratorAlgorithmName().equals(BCPQC_SPHINCS256_SHA3_512.getKeyGeneratorAlgorithmName()) || this.getKeyGeneratorAlgorithmName().equals(BCPQC_SPHINCS256_SHA2_512_256.getKeyGeneratorAlgorithmName()))
			{
				kgp=new Sphincs256KeyPairGeneratorSpi();

			}
			else if (this.getKeyGeneratorAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHAKE256_SLOW.getKeyGeneratorAlgorithmName()))
			{
				kgp=new SPHINCSPlusKeyPairGeneratorSpi();
			}
			else if (this.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_2.getSignatureAlgorithmName()))
			{
				kgp=new DilithiumKeyPairGeneratorSpi();
			}
			else if (this.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BCPQC_FALCON_512.getSignatureAlgorithmName()))
			{
				kgp=new FalconKeyPairGeneratorSpi();
			}
			else
				kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName, codeProviderKeyGenerator.getCompatibleProvider());
			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
			res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);

			return res;
		} else {
			KeyPairGenerator kgp = KeyPairGenerator.getInstance(keyGeneratorAlgorithmName, codeProviderKeyGenerator.getCompatibleProvider());

			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
			res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);

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

	public ASymmetricAuthenticatedSignatureType getDerivedType() {
		return derivedType;
	}
	public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		Random r=new Random(System.nanoTime());
		int maxSigSizeBits=0;
		for (ASymmetricAuthenticatedSignatureType t : ASymmetricAuthenticatedSignatureType.values())
		{
			ASymmetricKeyPair kp=t.getKeyPairGenerator(SecureRandomType.DEFAULT.getSingleton(null)).generateKeyPair();
			try
			{
				System.out.println(t+" : ");
				System.out.println("\tPublic key size in bytes : "+kp.getASymmetricPublicKey().getKeyBytes().getBytes().length);
				System.out.println("\tPublic key size in bits : "+kp.getASymmetricPublicKey().getKeyBytes().getBytes().length*8);
				ASymmetricAuthenticatedSignerAlgorithm signer=new ASymmetricAuthenticatedSignerAlgorithm(kp.getASymmetricPrivateKey());
				int maxSigLength=0;
				for (int i=0;i<40;i++)
				{
					byte[] data=new byte[r.nextInt(4096)+42];
					r.nextBytes(data);
					signer.init();
					signer.update(data);
					maxSigLength=Math.max(maxSigLength, signer.getSignature().length*8);
				}
				System.out.println("\tSignature size in bits : "+maxSigLength);
				maxSigSizeBits=Math.max(maxSigLength, maxSigSizeBits);
			}
			finally {
				kp.clean();
			}


		}
		System.out.println("Maximum signature size in bits : "+maxSigSizeBits);
	}
}
