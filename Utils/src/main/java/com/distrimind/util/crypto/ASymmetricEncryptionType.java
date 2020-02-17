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

import org.bouncycastle.bcasn1.x9.X9ECParameters;
import org.bouncycastle.bccrypto.ec.CustomNamedCurves;
import org.bouncycastle.bccrypto.params.*;
import org.bouncycastle.bcjcajce.provider.asymmetric.edec.BCXDHPrivateKey;
import org.bouncycastle.bcjcajce.provider.asymmetric.edec.BCXDHPublicKey;
import org.bouncycastle.bcmath.ec.ECCurve;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.asymmetric.AsymmetricEdDSAPublicKey;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.crypto.general.EdEC;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.InvocationTargetException;
import java.math.BigInteger;
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
	BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256("McElieceFujisaki", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA3_512, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_FUJISAKI_CCA2_SHA384("McElieceFujisaki", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_FUJISAKI_CCA2_SHA512("McElieceFujisaki", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256("McEliecePointCheval", "ECB", "NoPadding", ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA3_512, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA384("McEliecePointCheval", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA512("McEliecePointCheval", "ECB", "NoPadding", null,1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_KOBARA_IMAI_CCA2_SHA256("McElieceKobaraImai", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_KOBARA_IMAI_CCA2_SHA384("McElieceKobaraImai", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BCPQC_MCELIECE_KOBARA_IMAI_CCA2_SHA512("McElieceKobaraImai", "ECB", "NoPadding", null, 1048576, 31536000000L, (short)0, CodeProvider.BCPQC, CodeProvider.BCPQC, null, true),
	//BC_FIPS_RSA_OAEPWithSHA256AndMGF1Padding("RSA", "NONE", "OAEPwithSHA256andMGF1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 66,CodeProvider.BCFIPS,CodeProvider.BCFIPS, FipsRSA.ALGORITHM),
	//BC_FIPS_RSA_PKCS1Padding("RSA", "NONE", "PKCS1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 11,CodeProvider.BCFIPS,CodeProvider.BCFIPS, FipsRSA.ALGORITHM),
	DEFAULT(RSA_OAEPWithSHA512AndMGF1Padding);
	


	static Object decodeGnuPrivateKey(byte[] encodedKey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return GnuFunctions.decodeGnuPrivateKey(encodedKey, algorithm);
	}

	static Object decodeGnuPublicKey(byte[] encodedKey, String algorithm)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		return GnuFunctions.decodeGnuPublicKey(encodedKey, algorithm);
	}



	static PrivateKey decodeNativePrivateKey(byte[] encodedKey, String algorithm, String algorithmType, boolean xdh)
			throws NoSuchAlgorithmException, InvalidKeySpecException {

		try {
			if (algorithmType.contains("SPHINCS"))
			{
				Sphincs256KeyFactorySpi kf=new Sphincs256KeyFactorySpi();
				return kf.engineGeneratePrivate(new PKCS8EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.contains("CURVE_25519"))
			{
				ECPrivateKeySpec ks=deserializePrivateKey(encodedKey, false);
				return KeyFactory.getInstance(algorithm).generatePrivate(ks);

			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getCurveName()))
			{
				if (xdh)
				{
					X25519PrivateKeyParameters pk=new X25519PrivateKeyParameters(encodedKey, 0);
					return constructorBCXDHPrivateKey.newInstance(pk);

				}
				else {
					PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(encodedKey);
					KeyFactory kf = KeyFactory.getInstance(algorithm);
					return kf.generatePrivate(pkcsKeySpec);
				}
			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448.getCurveName()))
			{
				if (xdh)
				{
					X448PrivateKeyParameters pk=new X448PrivateKeyParameters(encodedKey, 0);
					return constructorBCXDHPrivateKey.newInstance(pk);

				}
				else {
					PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(encodedKey);
					KeyFactory kf = KeyFactory.getInstance(algorithm);
					return kf.generatePrivate(pkcsKeySpec);
				}
			}

			else
			{

				PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(encodedKey);
				KeyFactory kf = KeyFactory.getInstance(algorithm);
				return kf.generatePrivate(pkcsKeySpec);
			}
		} catch (InvalidKeySpecException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
			throw new InvalidKeySpecException(e);
		}
	}

	static PublicKey decodeNativePublicKey(byte[] encodedKey, String algorithm, String algorithmType, @SuppressWarnings("unused") String curveName, boolean xdh)
			throws NoSuchAlgorithmException, InvalidKeySpecException {
		try {
			//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);

			if (algorithmType.contains("SPHINCS"))
			{
				Sphincs256KeyFactorySpi kf=new Sphincs256KeyFactorySpi();
				return kf.engineGeneratePublic(new X509EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.contains("CURVE_25519"))
			{

				org.bouncycastle.jce.spec.ECPublicKeySpec ks=deserializePublicKey(encodedKey, false);
				return KeyFactory.getInstance(algorithm).generatePublic(ks);
			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getCurveName()))
			{
				if (xdh)
				{
					X25519PublicKeyParameters pk=new X25519PublicKeyParameters(encodedKey, 0);
					return constructorBCXDHPublicKey.newInstance(pk);
				}
				else {
					AsymmetricEdDSAPublicKey k= new AsymmetricEdDSAPublicKey(EdEC.Algorithm.Ed25519, encodedKey);
					return constructorProvEdDSAPublicKey.newInstance(k);
				}
			}
			else if (algorithmType.contains(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448.getCurveName()))
			{
				if (xdh)
				{
					X448PublicKeyParameters pk=new X448PublicKeyParameters(encodedKey, 0);
					return constructorBCXDHPublicKey.newInstance(pk);
				}
				else {
					AsymmetricEdDSAPublicKey k= new AsymmetricEdDSAPublicKey(EdEC.Algorithm.Ed448, encodedKey);
					return constructorProvEdDSAPublicKey.newInstance(k);
				}
			}
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            return kf.generatePublic(pubKeySpec);
		} catch (IllegalAccessException | InstantiationException | InvocationTargetException e) {
			throw new InvalidKeySpecException(e);
		}

	}
	@SuppressWarnings("SameParameterValue")
	static org.bouncycastle.jce.spec.ECPublicKeySpec deserializePublicKey(byte[] publicKey, boolean lazy) {

		if (publicKey.length <= 32) {
			if (lazy && (publicKey.length == 32)) {
				return null;
			}
			byte[] key = new byte[33];
			int offset = 33 - publicKey.length;
			for (int i = publicKey.length - 1; i >= 0; i--) {
				key[offset++] = publicKey[i];
			}
			key[0] = 3;
            ECCurve curve = getCurve25519().getCurve();
			org.bouncycastle.bcmath.ec.ECPoint q = curve.decodePoint(key);
			return new org.bouncycastle.jce.spec.ECPublicKeySpec(q, getCurve25519());
		} else if (publicKey.length == 33) { // TODO make 32 byte representation normal form
			if (lazy) {
				return null;
			}
			ECCurve curve = getCurve25519().getCurve();
			org.bouncycastle.bcmath.ec.ECPoint q = curve.decodePoint(publicKey);
			return new org.bouncycastle.jce.spec.ECPublicKeySpec(q, getCurve25519());
		} else {
			throw new IllegalArgumentException();
		}
	}

	@SuppressWarnings("SameParameterValue")
	static ECPrivateKeySpec deserializePrivateKey(byte[] privateKey, boolean lazy) {

		if (privateKey.length <= 32) {
			if (lazy) {
				return null;
			}
			BigInteger s = new BigInteger(privateKey);
			return new ECPrivateKeySpec(s, getCurve25519());
		} else {
			throw new IllegalArgumentException("privateKey.length="+privateKey.length);
		}
	}
	private static volatile ECParameterSpec curve25519;
	static org.bouncycastle.jce.spec.ECParameterSpec getCurve25519() {

		if (curve25519 == null) {
			X9ECParameters ecP = CustomNamedCurves.getByName("curve25519");
			// ECParameterSpec curve25519 = ECNamedCurveTable.getParameterSpec(algorithm);
			curve25519 = new org.bouncycastle.jce.spec.ECParameterSpec(ecP.getCurve(), ecP.getG(), ecP.getN(), ecP.getH(), ecP.getSeed());
		}
		return curve25519;
	}



	static byte[] encodeGnuPrivateKey(Object key) {
	    return GnuFunctions.keyGetEncoded(key);
		//return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().encode(), key.getEncoded());
	}
	static byte[] encodePrivateKey(PrivateKey key, @SuppressWarnings("unused") ASymmetricEncryptionType type) {
		return key.getEncoded();
	}
	static byte[] encodePrivateKey(PrivateKey key, ASymmetricAuthenticatedSignatureType type, boolean xdh) {
		/*if (type==ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_25519 || type==ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_25519 || type==ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_25519)
		{
			return ((ECPrivateKey) key).getD().toByteArray();
		}
		else */if (type==ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519)
		{
			if (xdh)
			{
				X25519PrivateKeyParameters k= null;
				try {
					k = (X25519PrivateKeyParameters)xdhPrivateKeyField.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getEncoded();
			}
			else {
				return key.getEncoded();
			}
		}
		else if (type==ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448)
		{
			if (xdh)
			{
				X448PrivateKeyParameters k= null;
				try {
					k = (X448PrivateKeyParameters)xdhPrivateKeyField.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getEncoded();
			}
			else {
				return key.getEncoded();
			}
		}
		else
	    	return key.getEncoded();
		//return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().encode(), key.getEncoded());
	}

	static byte[] encodeGnuPublicKey(Object key) {
	    return GnuFunctions.keyGetEncoded(key);
	}


	static byte[] encodePublicKey(PublicKey key, @SuppressWarnings("unused") ASymmetricEncryptionType type) {
	    return key.getEncoded();

	}


	static final Field xdhPublicKeyField;
	private static final Constructor<BCXDHPublicKey> constructorBCXDHPublicKey;
	static final Field xdhPrivateKeyField;
	private static final Constructor<BCXDHPrivateKey> constructorBCXDHPrivateKey;
	private static final Field provEdDSAPublicKeyBaseKey;
	private static final Constructor<PublicKey> constructorProvEdDSAPublicKey;
	static
	{
		Field tmpXdhPublicKeyField=null;
		Constructor<BCXDHPublicKey> tmpConstructorBCXDHPublicKey=null;
		Field tmpXdhPrivateKeyField=null;
		Constructor<BCXDHPrivateKey> tmpConstructorBCXDHPrivateKey=null;
		Field tmpProvEdDSAPublicKeyBaseKey=null;
		Constructor<PublicKey> tmpConstructorProvEdDSAPublicKey=null;

		try {
			tmpXdhPublicKeyField=BCXDHPublicKey.class.getDeclaredField("xdhPublicKey");
			tmpXdhPublicKeyField.setAccessible(true);
			tmpConstructorBCXDHPublicKey=BCXDHPublicKey.class.getDeclaredConstructor(AsymmetricKeyParameter.class);
			tmpConstructorBCXDHPublicKey.setAccessible(true);
			tmpXdhPrivateKeyField=BCXDHPrivateKey.class.getDeclaredField("xdhPrivateKey");
			tmpXdhPrivateKeyField.setAccessible(true);
			tmpConstructorBCXDHPrivateKey=BCXDHPrivateKey.class.getDeclaredConstructor(AsymmetricKeyParameter.class);
			tmpConstructorBCXDHPrivateKey.setAccessible(true);
			//noinspection unchecked
			tmpConstructorProvEdDSAPublicKey= (Constructor<PublicKey>) Class.forName("org.bouncycastle.jcajce.provider.ProvEdDSAPublicKey").getDeclaredConstructor(AsymmetricEdDSAPublicKey.class);
			tmpConstructorProvEdDSAPublicKey.setAccessible(true);
			tmpProvEdDSAPublicKeyBaseKey=Class.forName("org.bouncycastle.jcajce.provider.ProvEdDSAPublicKey").getDeclaredField("baseKey");
			tmpProvEdDSAPublicKeyBaseKey.setAccessible(true);

		} catch (NoSuchFieldException | NoSuchMethodException | ClassNotFoundException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		xdhPublicKeyField=tmpXdhPublicKeyField;
		constructorBCXDHPublicKey=tmpConstructorBCXDHPublicKey;
		xdhPrivateKeyField=tmpXdhPrivateKeyField;
		constructorBCXDHPrivateKey=tmpConstructorBCXDHPrivateKey;
		provEdDSAPublicKeyBaseKey =tmpProvEdDSAPublicKeyBaseKey;
		constructorProvEdDSAPublicKey=tmpConstructorProvEdDSAPublicKey;


	}

	static byte[] encodePublicKey(PublicKey key, ASymmetricAuthenticatedSignatureType type, boolean xdh)  {
		/*if (type==ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_25519
				|| type==ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_25519
				|| type==ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_25519
		)
		{
			return ((ECPublicKey) key).getQ().getEncoded(true);
		}
		else */if (type==ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519)
		{
			if (xdh)
			{
				X25519PublicKeyParameters k= null;
				try {
					k = (X25519PublicKeyParameters)xdhPublicKeyField.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getEncoded();
			}
			else {
				AsymmetricEdDSAPublicKey k= null;
				try {
					k = (AsymmetricEdDSAPublicKey) provEdDSAPublicKeyBaseKey.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getPublicData();
			}
		}
		else if (type==ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448)
		{
			if (xdh)
			{
				X448PublicKeyParameters k= null;
				try {
					k = (X448PublicKeyParameters)xdhPublicKeyField.get(key);
				} catch (IllegalAccessException e) {
					e.printStackTrace();
					System.exit(-1);
				}
				return k.getEncoded();
			}
			else {
				AsymmetricEdDSAPublicKey k= null;
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

	ASymmetricEncryptionType(ASymmetricEncryptionType type) {
		this(type.algorithmName, type.blockMode, type.padding, type.signature, type.keySizeBits, type.expirationTimeMilis,
				type.blockSizeDecrement, type.codeProviderForEncryption, type.codeProviderForKeyGenerator, type.bcAlgorithm, type.pqc);
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
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public String getBlockMode() {
		return blockMode;
	}

	public AbstractCipher getCipherInstance()
			throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		CodeProvider.ensureProviderLoaded(codeProviderForEncryption);
		String name = algorithmName+"/" + blockMode + "/" + padding;
		if (codeProviderForEncryption == CodeProvider.GNU_CRYPTO) {
			return new GnuCipher(GnuFunctions.cipherGetInstance(name));
		} else if (codeProviderForEncryption == CodeProvider.BCPQC)
		{
			if (this.name().startsWith("BCPQC_MCELIECE_"))
				return new BCMcElieceCipher(this);
			else
				throw new IllegalAccessError();

		} else if (codeProviderForEncryption == CodeProvider.BCFIPS || codeProviderForEncryption == CodeProvider.BC) {
			throw new IllegalAccessError();
		} else {
			return new JavaNativeCipher(Cipher.getInstance(name, codeProviderForEncryption.checkProviderWithCurrentOS().name()));
		}
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
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySizeBits, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, int keySizeBits,
			long expirationTimeUTC) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		if (keySizeBits<0)
			keySizeBits= this.keySizeBits;
		if (expirationTimeUTC==Long.MIN_VALUE)
			expirationTimeUTC=System.currentTimeMillis() + expirationTimeMilis;

		CodeProvider.ensureProviderLoaded(codeProviderForKeyGenerator);
		if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			Object kpg=GnuFunctions.getKeyPairGenerator(algorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kpg);
			res.initialize(keySizeBits, expirationTimeUTC, random);

			return res;
		} else if (codeProviderForKeyGenerator == CodeProvider.BCPQC) {
			if (this.name().startsWith("BCPQC_MCELIECE_"))
			{
				AbstractKeyPairGenerator res;
				if (this.name().contains("CCA2"))
					res=new BCMcElieceCipher.KeyPairGeneratorCCA2(this);
				else
					res=new BCMcElieceCipher.KeyPairGenerator(this);
				res.initialize(keySizeBits, expirationTimeUTC, random);
				return res;
			}
			else
				throw new IllegalAccessError();

		} else if (codeProviderForKeyGenerator == CodeProvider.BCFIPS) {

				KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, CodeProvider.BCFIPS.name());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySizeBits, expirationTimeUTC, random);

				return res;

		} else {
			KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, codeProviderForKeyGenerator.checkProviderWithCurrentOS().name());
			JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
			res.initialize(keySizeBits, expirationTimeUTC, random);

			return res;


		}

	}
	public int getMaxBlockSize(int keySize) {
		if (name().startsWith("BCPQC_MCELIECE_"))
			return Integer.MAX_VALUE;
		else
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
	
	
	Algorithm getBouncyCastleAlgorithm()
	{
		return bcAlgorithm;
	}

	public boolean isPostQuantumAlgorithm() {
		return pqc;
	}
}
