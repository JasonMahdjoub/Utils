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

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.ec.CustomNamedCurves;
import org.bouncycastle.crypto.fips.FipsRSA;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.pqc.jcajce.provider.sphincs.Sphincs256KeyFactorySpi;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * List of asymmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 3.1
 * @since Utils 1.4
 */
public enum ASymmetricEncryptionType {
	RSA_OAEPWithSHA256AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-256ANDMGF1PADDING", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSA,
			(short) 3072, 31536000000L, (short) 66, CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM),
	RSA_OAEPWithSHA384AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-384ANDMGF1PADDING", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSA,
			(short) 3072, 31536000000L, (short) 98, CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM),
	RSA_OAEPWithSHA512AndMGF1Padding("RSA", "ECB", "OAEPWITHSHA-512ANDMGF1PADDING", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withRSA,
			(short) 3072, 31536000000L, (short) 130, CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM),
	RSA_PKCS1Padding("RSA", "ECB", "PKCS1Padding", ASymmetricAuthentifiedSignatureType.SHA384withRSA, (short) 3072, 31536000000L, (short) 11,
					CodeProvider.SunJCE,CodeProvider.SunRsaSign, FipsRSA.ALGORITHM),
	//BC_FIPS_RSA_OAEPWithSHA256AndMGF1Padding("RSA", "NONE", "OAEPwithSHA256andMGF1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 66,CodeProvider.BCFIPS,CodeProvider.BCFIPS, FipsRSA.ALGORITHM),
	//BC_FIPS_RSA_PKCS1Padding("RSA", "NONE", "PKCS1Padding", ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1, (short) 3072, 31536000000l, (short) 11,CodeProvider.BCFIPS,CodeProvider.BCFIPS, FipsRSA.ALGORITHM),
	DEFAULT(RSA_OAEPWithSHA512AndMGF1Padding);
	


	/*static gnu.vm.jgnu.security.KeyPair decodeGnuKeyPair(byte[] encodedKeyPair)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		return decodeGnuKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
	}

	static gnu.vm.jgnu.security.KeyPair decodeGnuKeyPair(byte[] encodedKeyPair, int off, int len)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
		return new gnu.vm.jgnu.security.KeyPair(decodeGnuPublicKey(parts[0]), decodeGnuPrivateKey(parts[1]));
	}*/

	static gnu.vm.jgnu.security.PrivateKey decodeGnuPrivateKey(byte[] encodedKey, String algorithm)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
		gnu.vm.jgnu.security.spec.PKCS8EncodedKeySpec pkcsKeySpec = new gnu.vm.jgnu.security.spec.PKCS8EncodedKeySpec(
				encodedKey);
		gnu.vm.jgnu.security.KeyFactory kf = gnu.vm.jgnu.security.KeyFactory.getInstance(algorithm);
		return kf.generatePrivate(pkcsKeySpec);
	}

	static gnu.vm.jgnu.security.PublicKey decodeGnuPublicKey(byte[] encodedKey, String algorithm)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
		gnu.vm.jgnu.security.spec.X509EncodedKeySpec pubKeySpec = new gnu.vm.jgnu.security.spec.X509EncodedKeySpec(
				encodedKey);
		gnu.vm.jgnu.security.KeyFactory kf = gnu.vm.jgnu.security.KeyFactory.getInstance(algorithm);
		return kf.generatePublic(pubKeySpec);
	}

	/*static KeyPair decodeNativeKeyPair(byte[] encodedKeyPair)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		return decodeNativeKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
	}*/

	/*static KeyPair decodeNativeKeyPair(byte[] encodedKeyPair, int off, int len)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
		return new KeyPair(decodeNativePublicKey(parts[0]), decodeNativePrivateKey(parts[1]));
	}*/

	static PrivateKey decodeNativePrivateKey(byte[] encodedKey, String algorithm, String algorithmType)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {

		try {
			if (algorithmType.contains("SPHINCS"))
			{
				Sphincs256KeyFactorySpi kf=new Sphincs256KeyFactorySpi();
				return kf.engineGeneratePrivate(new PKCS8EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.contains("25519"))
			{

				ECPrivateKeySpec ks=deserializePrivateKey(encodedKey, false);
				return KeyFactory.getInstance(algorithm).generatePrivate(ks);

			}
			else
			{

				PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(encodedKey);
				KeyFactory kf = KeyFactory.getInstance(algorithm);
				return kf.generatePrivate(pkcsKeySpec);
			}
		} catch (NoSuchAlgorithmException e) {
			throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
		} catch (InvalidKeySpecException e) {
			throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
		}
	}

	static PublicKey decodeNativePublicKey(byte[] encodedKey, String algorithm, String algorithmType, @SuppressWarnings("unused") String curveName)
            throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.spec.InvalidKeySpecException {
		try {
			//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);

			if (algorithmType.contains("SPHINCS"))
			{
				Sphincs256KeyFactorySpi kf=new Sphincs256KeyFactorySpi();
				return kf.engineGeneratePublic(new X509EncodedKeySpec(encodedKey));
			}
			else if (algorithmType.contains("25519"))
			{

				org.bouncycastle.jce.spec.ECPublicKeySpec ks=deserializePublicKey(encodedKey, false);
				return KeyFactory.getInstance(algorithm).generatePublic(ks);
			}
			/*else if (algorithm.equalsIgnoreCase("ECDSA") && curveName!=null)
            {
                return getPubKeyFromCurve(encodedKey, curveName);

            }*/
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(encodedKey);
            KeyFactory kf = KeyFactory.getInstance(algorithm);
            return kf.generatePublic(pubKeySpec);
		} catch (NoSuchAlgorithmException e) {
			throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
		} catch (InvalidKeySpecException e) {
			throw new gnu.vm.jgnu.security.spec.InvalidKeySpecException(e);
		}

    }
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
			org.bouncycastle.math.ec.ECPoint q = curve.decodePoint(key);
			return new org.bouncycastle.jce.spec.ECPublicKeySpec(q, getCurve25519());
		} else if (publicKey.length == 33) { // TODO make 32 byte representation normal form
			if (lazy) {
				return null;
			}
			ECCurve curve = getCurve25519().getCurve();
			org.bouncycastle.math.ec.ECPoint q = curve.decodePoint(publicKey);
			return new org.bouncycastle.jce.spec.ECPublicKeySpec(q, getCurve25519());
		} else {
			throw new IllegalArgumentException();
		}
	}

	static ECPrivateKeySpec deserializePrivateKey(byte[] privateKey, boolean lazy) {

		if (privateKey.length <= 32) {
			if (lazy) {
				return null;
			}
			BigInteger s = new BigInteger(privateKey);
			return new ECPrivateKeySpec(s, getCurve25519());
		} else {
			throw new IllegalArgumentException();
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

	/*static byte[] encodeKeyPair(gnu.vm.jgnu.security.KeyPair keyPair) {
		return Bits.concateEncodingWithShortSizedTabs(encodePublicKey(keyPair.getPublic()),
				encodePrivateKey(keyPair.getPrivate()));
	}

	static byte[] encodeKeyPair(KeyPair keyPair) {
		return Bits.concateEncodingWithShortSizedTabs(encodePublicKey(keyPair.getPublic()),
				encodePrivateKey(keyPair.getPrivate()));
	}*/

	static byte[] encodePrivateKey(gnu.vm.jgnu.security.PrivateKey key) {
	    return key.getEncoded();
		//return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	}
	static byte[] encodePrivateKey(PrivateKey key, @SuppressWarnings("unused") ASymmetricEncryptionType type) {
		return key.getEncoded();
	}
	static byte[] encodePrivateKey(PrivateKey key, ASymmetricAuthentifiedSignatureType type) {
		if (type==ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_25519 || type==ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_25519 || type==ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_25519)
		{
			return ((ECPrivateKey) key).getD().toByteArray();
		}
		else
	    	return key.getEncoded();
		//return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	}

	static byte[] encodePublicKey(gnu.vm.jgnu.security.PublicKey key) {
	    return key.getEncoded();
	}


	static byte[] encodePublicKey(PublicKey key, @SuppressWarnings("unused") ASymmetricEncryptionType type) {
	    return key.getEncoded();

	}
	static byte[] encodePublicKey(PublicKey key, ASymmetricAuthentifiedSignatureType type) {
		if (type==ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_25519 || type==ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_25519 || type==ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_25519)
		{
			return ((ECPublicKey) key).getQ().getEncoded(true);
		}
		/*else if (type.getKeyGeneratorAlgorithmName().contains("ECDSA"))
		{
		    try {
                if (key instanceof BCECPublicKey)
                    return getKeyAsRawBytes((BCECPublicKey) key);
                else if (key instanceof ECPublicKey)
                    return getKeyAsRawBytes((ECPublicKey) key);
            }
            catch(Exception e)
            {
                e.printStackTrace();
            }


		}*/

		return key.getEncoded();

	}
    /*private static byte[] getKeyAsRawBytes(
            org.bouncycastle.jce.interfaces.ECPublicKey pub) throws IOException {
        byte[] raw;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(65);

        bos.write(0x04);
        bos.write(asUnsignedByteArray(pub.getQ().getX().toBigInteger()));
        bos.write(asUnsignedByteArray(pub.getQ().getY().toBigInteger()));
        raw = bos.toByteArray();
        return raw;
    }
    private static byte[] asUnsignedByteArray(BigInteger value) {
        byte[] bytes = value.toByteArray();

        if (bytes[0] == 0) {
            byte[] tmp = new byte[bytes.length - 1];

            System.arraycopy(bytes, 1, tmp, 0, tmp.length);

            return tmp;
        }

        return bytes;
    }
    private static byte[] getKeyAsRawBytes(BCECPublicKey pub) throws IOException {
        byte[] raw;
        ByteArrayOutputStream bos = new ByteArrayOutputStream(65);

        bos.write(0x04);
        bos.write(pub.getQ().getXCoord().getEncoded());
        bos.write(pub.getQ().getYCoord().getEncoded());
        raw = bos.toByteArray();
        return raw;
    }
    private static PublicKey getPubKeyFromCurve(byte[] pubKey, String curveName)
            throws InvalidKeySpecException, NoSuchAlgorithmException,
            java.security.NoSuchProviderException {

        ECNamedCurveParameterSpec spec = ECNamedCurveTable
                .getParameterSpec(curveName);
        KeyFactory kf = KeyFactory.getInstance("ECDSA",
                "BC");
        ECNamedCurveSpec params = new ECNamedCurveSpec(curveName,
                spec.getCurve(), spec.getG(), spec.getN());
        ECPoint point = ECPointUtil.decodePoint(params.getCurve(), pubKey);
        ECPublicKeySpec pubKeySpec = new ECPublicKeySpec(point, params);
        ECPublicKey pk = (ECPublicKey) kf.generatePublic(pubKeySpec);
        return pk;
    }*/
    /*private static ECPublicKey decodeECPublicKey(java.security.spec.ECParameterSpec params,
                                                 final byte[] pubkey) throws NoSuchAlgorithmException,
            InvalidKeySpecException {
        int keySizeBytes = params.getOrder().bitLength() / Byte.SIZE;

        int offset = 0;
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(pubkey, offset,
                offset + keySizeBytes));
        offset += keySizeBytes;
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(pubkey, offset,
                offset + keySizeBytes));
        ECPoint w = new ECPoint(x, y);


        java.security.spec.ECPublicKeySpec otherKeySpec = new java.security.spec.ECPublicKeySpec(w, params);
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        ECPublicKey otherKey = (ECPublicKey) keyFactory
                .generatePublic(otherKeySpec);
        return otherKey;
    }
    private static byte[] encodeECPublicKey(java.security.interfaces.ECPublicKey pubKey) {
        int keyLengthBytes = pubKey.getParams().getOrder().bitLength()
                / Byte.SIZE;
        byte[] publicKeyEncoded = new byte[2 * keyLengthBytes];

        int offset = 0;

        BigInteger x = pubKey.getW().getAffineX();
        byte[] xba = x.toByteArray();
        if (xba.length > keyLengthBytes + 1 || xba.length == keyLengthBytes + 1
                && xba[0] != 0) {
            throw new IllegalStateException(
                    "X coordinate of EC public key has wrong size");
        }

        if (xba.length == keyLengthBytes + 1) {
            System.arraycopy(xba, 1, publicKeyEncoded, offset, keyLengthBytes);
        } else {
            System.arraycopy(xba, 0, publicKeyEncoded, offset + keyLengthBytes
                    - xba.length, xba.length);
        }
        offset += keyLengthBytes;

        BigInteger y = pubKey.getW().getAffineY();
        byte[] yba = y.toByteArray();
        if (yba.length > keyLengthBytes + 1 || yba.length == keyLengthBytes + 1
                && yba[0] != 0) {
            throw new IllegalStateException(
                    "Y coordinate of EC public key has wrong size");
        }

        if (yba.length == keyLengthBytes + 1) {
            System.arraycopy(yba, 1, publicKeyEncoded, offset, keyLengthBytes);
        } else {
            System.arraycopy(yba, 0, publicKeyEncoded, offset + keyLengthBytes
                    - yba.length, yba.length);
        }

        return publicKeyEncoded;
    }*/

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

	private final ASymmetricAuthentifiedSignatureType signature;

	private final short keySize;

	private final long expirationTimeMilis;

	private final short blockSizeDecrement;

	private final CodeProvider codeProviderForEncryption, codeProviderForKeyGenerator;

	private final Algorithm bcAlgorithm;
	
	ASymmetricEncryptionType(ASymmetricEncryptionType type) {
		this(type.algorithmName, type.blockMode, type.padding, type.signature, type.keySize, type.expirationTimeMilis,
				type.blockSizeDecrement, type.codeProviderForEncryption, type.codeProviderForKeyGenerator, type.bcAlgorithm);
	}

	ASymmetricEncryptionType(String algorithmName, String blockMode, String padding,
			ASymmetricAuthentifiedSignatureType signature, short keySize, long expirationTimeMilis, short blockSizeDecrement,
			CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenetor, Algorithm bcAlgorithm) {
		this.algorithmName = algorithmName;
		this.blockMode = blockMode;
		this.padding = padding;
		this.signature = signature;
		this.keySize = keySize;
		this.blockSizeDecrement = blockSizeDecrement;
		this.codeProviderForEncryption = codeProviderForEncryption;
		this.codeProviderForKeyGenerator=codeProviderForKeyGenetor;
		this.expirationTimeMilis = expirationTimeMilis;
		this.bcAlgorithm=bcAlgorithm;
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public String getBlockMode() {
		return blockMode;
	}

	public AbstractCipher getCipherInstance()
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnux.crypto.NoSuchPaddingException, NoSuchProviderException {
		String name = algorithmName+"/" + blockMode + "/" + padding;
		if (codeProviderForEncryption == CodeProvider.GNU_CRYPTO) {
			return new GnuCipher(gnu.vm.jgnux.crypto.Cipher.getInstance(name));
		} else if (codeProviderForEncryption == CodeProvider.BCFIPS || codeProviderForEncryption == CodeProvider.BC) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			throw new IllegalAccessError();
		} else {
			try {
				
				return new JavaNativeCipher(Cipher.getInstance(name, codeProviderForEncryption.checkProviderWithCurrentOS().name()));
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (NoSuchPaddingException e) {
				throw new gnu.vm.jgnux.crypto.NoSuchPaddingException(e.getMessage());
			}catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
		}
	}

	
	
	public short getDefaultKeySize() {
		return keySize;
	}

	public int getDefaultMaxBlockSize() {
		return getMaxBlockSize(keySize);
	}

	public ASymmetricAuthentifiedSignatureType getDefaultSignatureAlgorithm() {
		return signature;
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize)
			throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		return getKeyPairGenerator(random, keySize, System.currentTimeMillis() + expirationTimeMilis);
	}

	public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize,
			long expirationTimeUTC) throws gnu.vm.jgnu.security.NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		if (codeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			gnu.vm.jgnu.security.KeyPairGenerator kgp = gnu.vm.jgnu.security.KeyPairGenerator
					.getInstance(algorithmName);
			GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kgp);
			res.initialize(keySize, expirationTimeUTC, random);

			return res;
		} else if (codeProviderForKeyGenerator == CodeProvider.BCFIPS) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, CodeProvider.BCFIPS.name());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySize, expirationTimeUTC, random);

				return res;
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
		} else {
			try {
				KeyPairGenerator kgp = KeyPairGenerator.getInstance(algorithmName, codeProviderForKeyGenerator.checkProviderWithCurrentOS().name());
				JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(this, kgp);
				res.initialize(keySize, expirationTimeUTC, random);

				return res;
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			} catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}

		}

	}
	public int getMaxBlockSize(int keySize) {
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
}
