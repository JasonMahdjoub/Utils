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

import com.distrimind.bcfips.crypto.Algorithm;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricXDHPrivateKey;
import com.distrimind.bcfips.crypto.asymmetric.AsymmetricXDHPublicKey;
import com.distrimind.bcfips.crypto.fips.FipsRSA;
import com.distrimind.bcfips.crypto.general.EdEC;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;
import com.distrimind.bouncycastle.pqc.jcajce.provider.sphincsplus.SPHINCSPlusKeyFactorySpi;
import com.distrimind.util.UtilClassLoader;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * List of asymmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 4.1
 * @since Utils 1.4
 */
@SuppressWarnings("unchecked")
public enum ASymmetricEncryptionType {
	RSA_OAEPWithSHA256AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-256ANDMGF1PADDING", ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withRSA,
			3072, 31536000000L, (short) 66, CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM, false),
	RSA_OAEPWithSHA384AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-384ANDMGF1PADDING", ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withRSA,
			3072, 31536000000L, (short) 98, CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM, false),
	RSA_OAEPWithSHA512AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-512ANDMGF1PADDING", ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withRSA,
			3072, 31536000000L, (short) 130, CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM, false),
	RSA_PKCS1Padding("RSA", "ECB", "PKCS1Padding", ASymmetricAuthenticatedSignatureType.SHA384withRSA, 3072, 31536000000L, (short) 11,
					CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM, false),
	/*BCPQC_MCELIECE_SHA256("McEliece", "ECB", "NoPadding", null, (short)2048, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_MCELIECE_SHA384("McEliece", "ECB", "NoPadding", null, (short)2048, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_MCELIECE_SHA512("McEliece", "ECB", "NoPadding", null, (short)2048, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),*/
	BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256("McElieceFujisaki", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_FUJISAKI_CCA2_SHA384("McElieceFujisaki", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_FUJISAKI_CCA2_SHA512("McElieceFujisaki", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256("McEliecePointCheval", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA384("McEliecePointCheval", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA512("McEliecePointCheval", "ECB", "NoPadding", null,1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_KOBARA_IMAI_CCA2_SHA256("McElieceKobaraImai", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_KOBARA_IMAI_CCA2_SHA384("McElieceKobaraImai", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_KOBARA_IMAI_CCA2_SHA512("McElieceKobaraImai", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BC_FIPS_RSA_OAEPWithSHA256AndMGF1Padding("RSA", "NONE", "OAEPwithSHA256andMGF1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 66,CodeProvider.BCFIPS,CodeProvider.BCFIPS, FipsRSA.ALGORITHM),
	//BC_FIPS_RSA_PKCS1Padding("RSA", "NONE", "PKCS1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 11,CodeProvider.BCFIPS,CodeProvider.BCFIPS, FipsRSA.ALGORITHM),
	BCPQC_CRYSTALS_KYBER_512("CRYSTALS-Kyber-512", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 834*8, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_CRYSTALS_KYBER_768("CRYSTALS-Kyber-768", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 1218*8, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_CRYSTALS_KYBER_1024("CRYSTALS-Kyber-1024", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 1602*8, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_CRYSTALS_KYBER_512_AES("CRYSTALS-Kyber-512-AES", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 834*8, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_CRYSTALS_KYBER_768_AES("CRYSTALS-Kyber-768-AES", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 1218*8, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_CRYSTALS_KYBER_1024_AES("CRYSTALS-Kyber-1024-AES", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST, 1602*8, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	DEFAULT(RSA_OAEPWithSHA512AndMGF1Padding);


	static final int META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY=ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION =131072+META_DATA_SIZE_IN_BYTES_NON_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION;

	static final int META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_PRIVATE_KEY=ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = 131072+META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION;

	private static final int META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR =ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PAIR_KEY_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_NON_HYBRID_KEY_PAIR_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_NON_HYBRID_KEY_PAIR;

	private static final int META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY =ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION=MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION=MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PUBLIC_KEY;

	private static final int META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY =ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_ENCRYPTION=MAX_SIZE_IN_BYTES_OF_NON_PQC_RSA_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION=MAX_SIZE_IN_BYTES_OF_NON_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +MAX_SIZE_IN_BYTES_OF_PQC_NON_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION +META_DATA_SIZE_IN_BYTES_FOR_HYBRID_PRIVATE_KEY;

	private static final int META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR =ASymmetricAuthenticatedSignatureType.META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_WITH_RSA_FOR_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_WITH_RSA_FOR_ENCRYPTION+META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;
	public static final int MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION= MAX_SIZE_IN_BYTES_OF_HYBRID_PUBLIC_KEY_FOR_ENCRYPTION+MAX_SIZE_IN_BYTES_OF_HYBRID_PRIVATE_KEY_FOR_ENCRYPTION+META_DATA_SIZE_IN_BYTES_FOR_HYBRID_KEY_PAIR;

	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION = MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_WITH_RSA_FOR_ENCRYPTION;
	public static final int MAX_SIZE_IN_BYTES_OF_KEY_PAIR_FOR_ENCRYPTION= MAX_SIZE_IN_BYTES_OF_HYBRID_KEY_PAIR_FOR_ENCRYPTION;

	static Object decodeGnuPrivateKey(byte[] encodedKey, String algorithm)
			throws NoSuchAlgorithmException, MessageExternalizationException {
		return GnuFunctions.decodeGnuPrivateKey(encodedKey, algorithm);
	}

	static Object decodeGnuPublicKey(byte[] encodedKey, String algorithm)
			throws NoSuchAlgorithmException, IOException {
		return GnuFunctions.decodeGnuPublicKey(encodedKey, algorithm);
	}



	static PrivateKey decodeNativePrivateKey(byte[] encodedKey, String algorithm, String algorithmType, boolean xdh)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		try {
			if (algorithmType.startsWith("BCPQC_SPHINCS_PLUS"))
			{
				SPHINCSPlusKeyFactorySpi kf=new SPHINCSPlusKeyFactorySpi();
				return kf.engineGeneratePrivate(new PKCS8EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.startsWith("BCPQC_SPHINCS"))
			{
				Sphincs256KeyFactorySpi kf=new Sphincs256KeyFactorySpi();
				return kf.engineGeneratePrivate(new PKCS8EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getCurveName()) || algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448.getCurveName()))
			{
				if (xdh)
				{
					AsymmetricXDHPrivateKey k=new AsymmetricXDHPrivateKey(encodedKey);
					return constructorProvXDHPrivateKey.newInstance(k);
				}
				else {
					PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(encodedKey);
					KeyFactory kf = KeyFactory.getInstance(algorithm, CodeProvider.BCFIPS.getCompatibleProvider());
					return kf.generatePrivate(pkcsKeySpec);
				}
			}
			else
			{
				PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(encodedKey);
				if (algorithm.startsWith("CRYSTALS-Kyber"))
					algorithm="Kyber";
				else if (algorithm.startsWith(ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5.getSignatureAlgorithmName()))
					algorithm=ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5.getSignatureAlgorithmName();
				else if (algorithm.startsWith(ASymmetricAuthenticatedSignatureType.BCPQC_FALCON_512.getSignatureAlgorithmName()))
					algorithm=ASymmetricAuthenticatedSignatureType.BCPQC_FALCON_512.getSignatureAlgorithmName();
				KeyFactory kf = KeyFactory.getInstance(algorithm);
				return kf.generatePrivate(pkcsKeySpec);
			}
		} catch (InvalidKeySpecException | NoSuchProviderException | IOException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
			throw new InvalidKeySpecException(e);
		}
	}

	static PublicKey decodeNativePublicKey(byte[] encodedKey, String algorithm, String algorithmType, @SuppressWarnings("unused") String curveName, boolean xdh)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);

			if (algorithmType.startsWith("BCPQC_SPHINCS_PLUS"))
			{
				SPHINCSPlusKeyFactorySpi kf=new SPHINCSPlusKeyFactorySpi();
				return kf.engineGeneratePublic(new X509EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.startsWith("BCPQC_SPHINCS"))
			{
				Sphincs256KeyFactorySpi kf=new Sphincs256KeyFactorySpi();
				return kf.engineGeneratePublic(new X509EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getCurveName()))
			{
				if (xdh)
				{
					AsymmetricXDHPublicKey k = new AsymmetricXDHPublicKey(EdEC.Algorithm.X25519, encodedKey);
					return constructorProvXDHPublicKey.newInstance(k);
				}
				else {
					AsymmetricEdDSAPublicKey k = new AsymmetricEdDSAPublicKey(EdEC.Algorithm.Ed25519, encodedKey);
					return constructorProvEdDSAPublicKey.newInstance(k);
				}
			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448.getCurveName()))
			{
				if (xdh)
				{
					AsymmetricXDHPublicKey k = new AsymmetricXDHPublicKey(EdEC.Algorithm.X448, encodedKey);
					return constructorProvXDHPublicKey.newInstance(k);
				}
				else {
					AsymmetricEdDSAPublicKey k = new AsymmetricEdDSAPublicKey(EdEC.Algorithm.Ed448, encodedKey);
					return constructorProvEdDSAPublicKey.newInstance(k);
				}
			}
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);
			if (algorithm.startsWith("CRYSTALS-Kyber"))
				algorithm="Kyber";
			else if (algorithm.startsWith(ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5.getSignatureAlgorithmName()))
				algorithm=ASymmetricAuthenticatedSignatureType.BCPQC_CHRYSTALS_DILITHIUM_5.getSignatureAlgorithmName();
			else if (algorithm.startsWith(ASymmetricAuthenticatedSignatureType.BCPQC_FALCON_512.getSignatureAlgorithmName()))
				algorithm=ASymmetricAuthenticatedSignatureType.BCPQC_FALCON_512.getSignatureAlgorithmName();
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            return kf.generatePublic(pubKeySpec);
		} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
			throw new InvalidKeySpecException(e);
		}

	}




	static byte[] encodeGnuPrivateKey(Object key) {
	    return GnuFunctions.keyGetEncoded(key);
	}
	static byte[] encodePrivateKey(PrivateKey key, @SuppressWarnings("unused") ASymmetricEncryptionType type) {

		return key.getEncoded();
	}
	@SuppressWarnings("unused")
	static byte[] encodePrivateKey(PrivateKey key, ASymmetricAuthenticatedSignatureType type, boolean xdh) {
		return key.getEncoded();
		//return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().encode(), key.getEncoded());
	}

	static byte[] encodeGnuPublicKey(Object key) {
	    return GnuFunctions.keyGetEncoded(key);
	}


	static byte[] encodePublicKey(PublicKey key, @SuppressWarnings("unused") ASymmetricEncryptionType type) {
	    return key.getEncoded();

	}


	private static final Field provEdDSAPublicKeyBaseKey;
	private static final Field provXDHPublicKeyBaseKey;
	private static final Constructor<PublicKey> constructorProvEdDSAPublicKey;
	private static final Constructor<PublicKey> constructorProvXDHPublicKey;
	private static final Constructor<PrivateKey> constructorProvXDHPrivateKey;
	static
	{
		Field tmpProvEdDSAPublicKeyBaseKey=null;
		Field tmpProvXDHPublicKeyBaseKey=null;
		Constructor<PublicKey> tmpConstructorProvEdDSAPublicKey=null;
		Constructor<PublicKey> tmpConstructorProvXDHPublicKey=null;
		Constructor<PrivateKey> tmpConstructorProvXDHPrivateKey=null;

		try {

			tmpProvEdDSAPublicKeyBaseKey= UtilClassLoader.getLoader().loadClass("com.distrimind.bcfips.jcajce.provider.ProvEdDSAPublicKey").getDeclaredField("baseKey");
			tmpProvEdDSAPublicKeyBaseKey.setAccessible(true);
			tmpProvXDHPublicKeyBaseKey=UtilClassLoader.getLoader().loadClass("com.distrimind.bcfips.jcajce.provider.ProvXDHPublicKey").getDeclaredField("baseKey");
			tmpProvXDHPublicKeyBaseKey.setAccessible(true);

			tmpConstructorProvEdDSAPublicKey= (Constructor<PublicKey>) UtilClassLoader.getLoader().loadClass("com.distrimind.bcfips.jcajce.provider.ProvEdDSAPublicKey").getDeclaredConstructor(AsymmetricEdDSAPublicKey.class);
			tmpConstructorProvEdDSAPublicKey.setAccessible(true);

			tmpConstructorProvXDHPublicKey= (Constructor<PublicKey>) UtilClassLoader.getLoader().loadClass("com.distrimind.bcfips.jcajce.provider.ProvXDHPublicKey").getDeclaredConstructor(AsymmetricXDHPublicKey.class);
			tmpConstructorProvXDHPublicKey.setAccessible(true);

			tmpConstructorProvXDHPrivateKey= (Constructor<PrivateKey>) UtilClassLoader.getLoader().loadClass("com.distrimind.bcfips.jcajce.provider.ProvXDHPrivateKey").getDeclaredConstructor(AsymmetricXDHPrivateKey.class);
			tmpConstructorProvXDHPrivateKey.setAccessible(true);

		} catch (NoSuchFieldException | NoSuchMethodException | ClassNotFoundException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		provEdDSAPublicKeyBaseKey =tmpProvEdDSAPublicKeyBaseKey;
		provXDHPublicKeyBaseKey =tmpProvXDHPublicKeyBaseKey;
		constructorProvEdDSAPublicKey=tmpConstructorProvEdDSAPublicKey;
		constructorProvXDHPublicKey=tmpConstructorProvXDHPublicKey;
		constructorProvXDHPrivateKey=tmpConstructorProvXDHPrivateKey;


	}

	static byte[] encodePublicKey(PublicKey key, ASymmetricAuthenticatedSignatureType type, boolean xdh)  {

		if (type == ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519 || type == ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448) {
			if (xdh)
			{
				AsymmetricXDHPublicKey k = null;
				try {
					k = (AsymmetricXDHPublicKey) provXDHPublicKeyBaseKey.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getPublicData();
			}
			else {
				AsymmetricEdDSAPublicKey k = null;
				try {
					k = (AsymmetricEdDSAPublicKey) provEdDSAPublicKeyBaseKey.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getPublicData();
			}
		}


		return key.getEncoded();

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

	private final ASymmetricAuthenticatedSignatureType signature;

	private final int keySizeBits;

	private final long expirationTimeMilis;

	private final short blockSizeDecrement;

	private final CodeProvider codeProviderForEncryption, codeProviderForKeyGenerator;

	private final Algorithm bcAlgorithm;

	private final boolean pqc;
	private ASymmetricEncryptionType derivedType;

	public boolean equals(ASymmetricEncryptionType type)
	{
		if (type==this)
			return true;
		if (type==null)
			return false;
		//noinspection StringEquality
		return type.algorithmName==this.algorithmName && type.blockMode==this.blockMode && type.padding==this.padding && type.codeProviderForEncryption==this.codeProviderForEncryption && type.codeProviderForKeyGenerator==this.codeProviderForKeyGenerator;
	}

	ASymmetricEncryptionType(ASymmetricEncryptionType type) {
		this(type.algorithmName, type.blockMode, type.padding, type.signature, type.keySizeBits, type.expirationTimeMilis,
				type.blockSizeDecrement, type.codeProviderForEncryption, type.codeProviderForKeyGenerator, type.bcAlgorithm, type.pqc);
		this.derivedType=type;
	}

	ASymmetricEncryptionType(String algorithmName, String blockMode, String padding,
							 ASymmetricAuthenticatedSignatureType signature, int keySizeBits, long expirationTimeMilis, short blockSizeDecrement,
							 CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenetor, Algorithm bcAlgorithm, boolean pqc) {
		this.algorithmName = algorithmName;
		this.blockMode = blockMode;
		this.padding = padding;
		this.signature = signature;
		this.keySizeBits = keySizeBits;
		this.blockSizeDecrement = blockSizeDecrement;
		this.codeProviderForEncryption = codeProviderForEncryption;
		this.codeProviderForKeyGenerator=codeProviderForKeyGenetor;
		this.expirationTimeMilis = expirationTimeMilis;
		this.bcAlgorithm=bcAlgorithm;
		this.pqc=pqc;
		this.derivedType=this;
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public String getBlockMode() {
		return blockMode;
	}

	public AbstractCipher getCipherInstance()
			throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
		//CodeProvider.ensureProviderLoaded(codeProviderForEncryption);
		String name = algorithmName+"/" + blockMode + "/" + padding;
		if (codeProviderForEncryption == CodeProvider.GNU_CRYPTO) {
			return new GnuCipher(GnuFunctions.cipherGetInstance(name));
		} else if (codeProviderForEncryption == CodeProvider.BCPQC)
		{
			if (this.getAlgorithmName().startsWith("McEliece"))
				return new BCMcElieceCipher(this);
			else if (this.getAlgorithmName().startsWith("CRYSTALS-Kyber"))
			{
				try {
					return new JavaNativeCipher(Cipher.getInstance("Kyber", codeProviderForEncryption.getCompatibleProvider()));
				} catch (NoSuchPaddingException e) {
					throw new MessageExternalizationException(Integrity.FAIL, e);
				}
			}
			else
				throw new IllegalAccessError();
		} else if (codeProviderForEncryption == CodeProvider.BCFIPS || codeProviderForEncryption == CodeProvider.BC) {
			throw new IllegalAccessError();
		} else {
			try {
				return new JavaNativeCipher(Cipher.getInstance(name, codeProviderForEncryption.getCompatibleProvider()));
			} catch (NoSuchPaddingException e) {
				throw new MessageExternalizationException(Integrity.FAIL, e);
			}
		}
	}

	public boolean canBeUsedForEncryption()
	{
		return !getAlgorithmName().startsWith("CRYSTALS-Kyber");
	}
	
	public int getDefaultKeySizeBits() {
		return keySizeBits;
	}

	public int getDefaultMaxBlockSize() {
		return getMaxBlockSize(keySizeBits);
	}

	public ASymmetricAuthenticatedSignatureType getDefaultSignatureAlgorithm() {
		return signature;
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis(), System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis(), System.currentTimeMillis() + expirationTimeMilis);
	}
	long getDefaultExpirationTimeMilis() {
		return expirationTimeMilis;
	}
	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits,
			long publicKeyValidityBeginDateUTC, long expirationTimeUTC) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		if (keySizeBits<0)
			keySizeBits= this.keySizeBits;

		//CodeProvider.ensureProviderLoaded(codeProviderForKeyGenerator);
		if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			Object kpg=GnuFunctions.getKeyPairGenerator(algorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kpg);
			res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);

			return res;
		} else if (codeProviderForKeyGenerator == CodeProvider.BCPQC) {
			if (this.getAlgorithmName().startsWith("McEliece"))
			{
				AbstractKeyPairGenerator res;
				if (this.name().contains("CCA2"))
					res=new BCMcElieceCipher.KeyPairGeneratorCCA2(this);
				else
					res=new BCMcElieceCipher.KeyPairGenerator(this);
				res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);
				return res;
			}
			else if (this.getAlgorithmName().startsWith("CRYSTALS-Kyber"))
			{

				KeyPairGenerator kgp = KeyPairGenerator.getInstance("Kyber", codeProviderForKeyGenerator.getCompatibleProvider());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);
				return res;
			}
			else
				throw new IllegalAccessError();

		} else if (codeProviderForKeyGenerator == CodeProvider.BCFIPS) {

				KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, CodeProvider.BCFIPS.getCompatibleProvider());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);

				return res;

		} else {
			KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, codeProviderForKeyGenerator.getCompatibleProvider());
			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
			res.initialize(keySizeBits, publicKeyValidityBeginDateUTC, expirationTimeUTC, random);

			return res;


		}

	}
	public int getMaxBlockSize(int keySizeBits) {
		if (name().startsWith("BCPQC_MCELIECE_"))
			return Integer.MAX_VALUE;
		else
			return keySizeBits / 8 - blockSizeDecrement;
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
	
	
	Algorithm getBouncyCastleAlgorithm()
	{
		return bcAlgorithm;
	}

	public boolean isPostQuantumAlgorithm() {
		return pqc;
	}

	public ASymmetricEncryptionType getDerivedType() {
		return derivedType;
	}

}
