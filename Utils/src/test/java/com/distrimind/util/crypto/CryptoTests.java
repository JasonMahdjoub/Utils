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

import java.io.IOException;
import java.security.*;
import java.util.ArrayList;
import java.util.Random;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;


import com.distrimind.util.DecentralizedValue;
import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.distrimind.util.Bits;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.4
 */
public class CryptoTests {
	private static final byte[][] messagesToEncrypt;

	private static final byte[] salt;
	static {
		System.out.println("Generatring messages");
		Random rand = new Random(System.currentTimeMillis());
		messagesToEncrypt = new byte[30][];
		for (int i = 0; i < messagesToEncrypt.length; i++) {
			byte[] b = new byte[50 + rand.nextInt(20000)];
			for (int j = 0; j < b.length; j++)
				b[j] = (byte) rand.nextInt();

			messagesToEncrypt[i] = b;
		}
		salt = new byte[rand.nextInt(10) + 30];
		for (int j = 0; j < salt.length; j++)
			salt[j] = (byte) rand.nextInt();

	}

	private static final int[] keySizes = { 1024, 2048, 3072, 4096 };

	@DataProvider(name = "provideDataForHybridASymetricEncryptions", parallel = true)
	public Object[][] provideDataForHybridASymetricEncryptions() {
		ArrayList<Object[]> res = new ArrayList<>();


		for (ASymmetricEncryptionType v : ASymmetricEncryptionType.values()) {
			if (v.isPostQuantumAlgorithm())
				continue;
			for (ASymmetricEncryptionType v2 : ASymmetricEncryptionType.values()) {
				if (v2.isPostQuantumAlgorithm())
				{
					Object[] o = new Object[1];
					o[0] = new HybridASymmetricEncryptionType(v, v2);

					res.add(o);
				}
			}
		}
		Object[][] res2=new Object[res.size()][];
		for (int i=0;i<res.size();i++)
			res2[i]=res.get(i);
		return res2;
	}
	@DataProvider(name = "provideDataForHybridASymetricSignatures", parallel = true)
	public Object[][] provideDataForHybridASymetricSignatures() {
		ArrayList<Object[]> res = new ArrayList<>();


		for (ASymmetricAuthenticatedSignatureType v : ASymmetricAuthenticatedSignatureType.values()) {
			if (v.isPostQuantumAlgorithm())
				continue;
			for (ASymmetricAuthenticatedSignatureType v2 : ASymmetricAuthenticatedSignatureType.values()) {
				if (v2.isPostQuantumAlgorithm())
				{
					Object[] o = new Object[2];
					o[0] = v;
					o[1] = v2;
					res.add(o);
				}
			}
		}
		Object[][] res2=new Object[res.size()][];
		for (int i=0;i<res.size();i++)
			res2[i]=res.get(i);
		return res2;
	}
	@DataProvider(name = "provideDataForASymetricEncryptions", parallel = true)
	public Object[][] provideDataForASymetricEncryptions() {
		Object[][] res = new Object[ASymmetricEncryptionType.values().length][];
		int i = 0;
		for (ASymmetricEncryptionType v : ASymmetricEncryptionType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}

	
	@DataProvider(name = "provideDataForASymetricSignatures")
	public Object[][] provideDataForASymetricSignatures() {
		Object[][] res = new Object[ASymmetricAuthenticatedSignatureType.values().length][];
		int i = 0;
		for (ASymmetricAuthenticatedSignatureType v : ASymmetricAuthenticatedSignatureType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}


	@DataProvider(name = "provideDataForHybridEncryptions", parallel = true)
	public Object[][] provideDataForHybridEncryptions() {
		Object[][] res = new Object[SymmetricEncryptionType.values().length
				* ASymmetricEncryptionType.values().length][];
		int index = 0;
		for (SymmetricEncryptionType vS : SymmetricEncryptionType.values()) {
			for (ASymmetricEncryptionType vAS : ASymmetricEncryptionType.values()) {
				if ((vS.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)==(vAS.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO))
				{
					Object[] o = new Object[2];
					o[0] = vAS;
					o[1] = vS;
					res[index++] = o;
				}
			}
		}
		Object[][] res2;
		res2 = new Object[index][];
		System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}

	@DataProvider(name = "provideDataForASymmetricSignatureTest", parallel = true)
	public Object[][] provideDataForASymmetricSignatureTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		ArrayList<Object[]> res = new ArrayList<>();

		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (ASymmetricAuthenticatedSignatureType st : ASymmetricAuthenticatedSignatureType.values()) {
			if (st.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384.getSignatureAlgorithmName()))
			{
				Object[] o = new Object[4];
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand,  384).generateKeyPair();
				o[3] = 384;
				res.add(o);
			}
			else if (st.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256.getSignatureAlgorithmName()))
			{
				Object[] o = new Object[4];
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand, 256).generateKeyPair();
				o[3] = 256;
				res.add(o);
			}
			else if (st.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521.getSignatureAlgorithmName()))
			{
				Object[] o = new Object[4];
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand, 512).generateKeyPair();
				o[3] = 512;
				res.add(o);
			}
			else if (st.isPostQuantumAlgorithm())
			{
				Object[] o = new Object[4];
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand).generateKeyPair();
				o[3] = 512;
				res.add(o);
			}
			else
			{
				for (int keySize : keySizes) {
					Object[] o = new Object[4];
					o[0]=st;
					o[1]=null;
					o[2] = st.getKeyPairGenerator(rand, keySize).generateKeyPair();
					o[3] = keySize;
					res.add(o);
				}
			}
		}
		for (ASymmetricAuthenticatedSignatureType st : ASymmetricAuthenticatedSignatureType.values()) {
			if (st.isPostQuantumAlgorithm())
				continue;
			Object[] o = new Object[4];
			if (st.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384.getSignatureAlgorithmName()))
			{
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand,  384).generateKeyPair();
				o[3] = 384;
			}
			else if (st.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256.getSignatureAlgorithmName()))
			{
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand, 256).generateKeyPair();
				o[3] = 256;
			}
			else if (st.getSignatureAlgorithmName().equals(ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521.getSignatureAlgorithmName()))
			{
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand, 512).generateKeyPair();
				o[3] = 512;
			}
			else
			{
				o[0]=st;
				o[1]=null;
				o[2] = st.getKeyPairGenerator(rand, keySizes[0]).generateKeyPair();
				o[3] = keySizes[0];
			}
			for (ASymmetricAuthenticatedSignatureType st2 : ASymmetricAuthenticatedSignatureType.values()) {
				if (!st2.isPostQuantumAlgorithm())
					continue;
				Object[] o2=o.clone();
				o2[1]=st2;
				assert o[2] != null;
				o2[2] = new HybridASymmetricKeyPair((ASymmetricKeyPair)o[2], st2.getKeyPairGenerator(rand).generateKeyPair());
				res.add(o2);
			}
		}
		Object[][] res2=new Object[res.size()][];
		for (int i=0;i<res.size();i++)
			res2[i]=res.get(i);
		return res2;
	}

	@DataProvider(name = "provideDataForSymmetricSignatureTest", parallel = true)
	public Object[][] provideDataForSymmetricSignatureTest() throws NoSuchAlgorithmException, NoSuchProviderException {
		Object[][] res = new Object[SymmetricAuthentifiedSignatureType.values().length*2][];
		int i = 0;
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (SymmetricAuthentifiedSignatureType ast : SymmetricAuthentifiedSignatureType.values()) {
			Object[] o = new Object[2];
			o[0] = ast;
			
			o[1] = ast.getKeyGenerator(rand, (short)256).generateKey();
			res[i++] = o;
		}
		for (SymmetricAuthentifiedSignatureType ast : SymmetricAuthentifiedSignatureType.values()) {
			Object[] o = new Object[2];
			o[0] = ast;
			
			o[1] = ast.getKeyGenerator(rand, (short)128).generateKey();
			res[i++] = o;
		}
		return res;
	}

	@DataProvider(name = "provideDataForSymetricEncryptions", parallel = true)
	public Object[][] provideDataForSymetricEncryptions() {
		Object[][] res = new Object[SymmetricEncryptionType.values().length][];
		int i = 0;
		for (SymmetricEncryptionType v : SymmetricEncryptionType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}

    @DataProvider(name = "symmetricSignatures", parallel = true)
    public Object[][] provideDataForSymetricSignatures() {
        Object[][] res = new Object[SymmetricAuthentifiedSignatureType.values().length][];
        int i = 0;
        for (SymmetricAuthentifiedSignatureType v : SymmetricAuthentifiedSignatureType.values()) {
			Object[] o = new Object[1];
            o[0] = v;
            res[i++] = o;
        }
        return res;
    }
	@DataProvider(name = "provideDataForTestSymmetricEncryptionCompatibility", parallel = true)
	public Object[][] provideDataForTestSymmetricEncryptionCompatibility() {
		Object[][] res = new Object[][] {
			{SymmetricEncryptionType.AES_CBC_PKCS5Padding, SymmetricEncryptionType.BC_FIPS_AES_CBC_PKCS7Padding},
			{SymmetricEncryptionType.AES_GCM, SymmetricEncryptionType.BC_FIPS_AES_GCM},
			{SymmetricEncryptionType.GNU_AES_CBC_PKCS5Padding, SymmetricEncryptionType.BC_FIPS_AES_CBC_PKCS7Padding},
			{SymmetricEncryptionType.GNU_TWOFISH_CBC_PKCS5Padding, SymmetricEncryptionType.BC_TWOFISH_CBC_PKCS7Padding},
			{SymmetricEncryptionType.GNU_SERPENT_CBC_PKCS5Padding, SymmetricEncryptionType.BC_SERPENT_CBC_PKCS7Padding},
			{SymmetricEncryptionType.GNU_AES_CBC_PKCS5Padding, SymmetricEncryptionType.AES_CBC_PKCS5Padding}
		};
		Object[][] res2 = new Object[res.length*2][2];
		int j=0;
        for (Object[] re : res) {
            res2[j][0] = re[0];
            res2[j++][1] = re[1];
            res2[j][0] = re[1];
            res2[j++][1] = re[0];
        }
		return res2;
	}
	

	@DataProvider(name = "provideMessageDigestType", parallel = true)
	public Object[][] provideMessageDigestType() {
		Object[][] res = new Object[MessageDigestType.values().length][];
		int i = 0;
		for (MessageDigestType v : MessageDigestType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}

	@DataProvider(name = "providePasswordHashTypes", parallel = true)
	public Object[][] providePasswordHashTypes() {
		Object[][] res = new Object[PasswordHashType.values().length][1];
		int index = 0;
		for (PasswordHashType type : PasswordHashType.values()) {
			res[index++][0] = type;
		}
		return res;
	}

	@DataProvider(name = "provideSecureRandomType", parallel = true)
	public Object[][] provideSecureRandomType() {
		Object[][] res = new Object[SecureRandomType.values().length][];
		int i = 0;
		for (SecureRandomType v : SecureRandomType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}
	@Test(dataProvider = "provideDataForHybridASymetricEncryptions")
	public void testHybridASymmetricKeyPairEncodingForSignature(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		System.out.println("Testing HybridASymmetricKeyPairEncoding " + type);

		HybridASymmetricKeyPair kpd=type.generateKeyPair(SecureRandomType.DEFAULT.getSingleton(null), 1024 );

		byte[] b = kpd.encode(false);
		HybridASymmetricKeyPair kpd2=(HybridASymmetricKeyPair)DecentralizedValue.decode(b);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey(), kpd.getASymmetricPublicKey());
		Assert.assertEquals(kpd2.getPQCASymmetricKeyPair().getEncryptionAlgorithmType(), kpd.getPQCASymmetricKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCASymmetricKeyPair().getEncryptionAlgorithmType(), kpd.getNonPQCASymmetricKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getNonPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType());

		b = kpd.getASymmetricPublicKey().encode(false);
		Assert.assertEquals(b.length, kpd.getASymmetricPublicKey().encode(true).length-16);
		HybridASymmetricPublicKey pk=(HybridASymmetricPublicKey) DecentralizedValue.decode(b);
		Assert.assertEquals(pk, kpd.getASymmetricPublicKey());
		Assert.assertEquals(pk.getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getNonPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.getPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.getTimeExpirationUTC(), Long.MAX_VALUE);


		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPublicKey().encode(true)),
				kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPrivateKey().encode()),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.encode(true)), kpd);
		Assert.assertEquals(((HybridASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPrivateKey(),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(((HybridASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPublicKey(),
				kpd.getASymmetricPublicKey());
		System.out.println(type+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());

	}


	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricKeyPairEncodingForEncryption(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);

		ASymmetricKeyPair kpd=generateKeyPair(type);

		byte[] b = kpd.encode(false);
		ASymmetricKeyPair kpd2=(ASymmetricKeyPair)DecentralizedValue.decode(b);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().toJavaNativeKey().getEncoded(), kpd.getASymmetricPublicKey().toJavaNativeKey().getEncoded());
		Assert.assertEquals(kpd2.getEncryptionAlgorithmType(), kpd.getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getAuthenticatedSignatureAlgorithmType(), kpd.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getEncryptionAlgorithmType());

		b = kpd.getASymmetricPublicKey().encode(false);
		Assert.assertEquals(b.length, kpd.getASymmetricPublicKey().encode(true).length-8);
		ASymmetricPublicKey pk=(ASymmetricPublicKey) DecentralizedValue.decode(b);
		Assert.assertEquals(pk.toJavaNativeKey().getEncoded(), kpd.getASymmetricPublicKey().toJavaNativeKey().getEncoded());
		Assert.assertEquals(pk.getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.getTimeExpirationUTC(), Long.MAX_VALUE);


		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPublicKey().encode(true)),
				kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPrivateKey().encode()),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.encode(true)), kpd);
		Assert.assertEquals(((ASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPrivateKey(),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(((ASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPublicKey(),
				kpd.getASymmetricPublicKey());
		System.out.println(type+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());
	}


	private ASymmetricKeyPair generateKeyPair(ASymmetricAuthenticatedSignatureType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);

		boolean isECDSA=type== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384
				|| 	type== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256
				|| type== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521;

		return type.getKeyPairGenerator(rand, isECDSA?type.getDefaultKeySize():(short)1024).generateKeyPair();
	}

	private ASymmetricKeyPair generateKeyPair(ASymmetricEncryptionType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		return type.getKeyPairGenerator(rand, (short)1024).generateKeyPair();
	}

	@Test(dataProvider = "provideDataForHybridASymetricSignatures")
	public void testHybridASymmetricKeyPairEncodingForEncryption(ASymmetricAuthenticatedSignatureType nonPQCType, ASymmetricAuthenticatedSignatureType PQCType)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		System.out.println("Testing HybridASymmetricKeyPairEncoding " + nonPQCType+" ; "+PQCType);

		ASymmetricKeyPair nonPQC=generateKeyPair(nonPQCType);
		ASymmetricKeyPair PQC=generateKeyPair(PQCType);
		HybridASymmetricKeyPair kpd=new HybridASymmetricKeyPair(nonPQC, PQC);

		byte[] b = kpd.encode(false);
		HybridASymmetricKeyPair kpd2=(HybridASymmetricKeyPair)DecentralizedValue.decode(b);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey(), kpd.getASymmetricPublicKey());
		Assert.assertEquals(kpd2.getPQCASymmetricKeyPair().getEncryptionAlgorithmType(), kpd.getPQCASymmetricKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCASymmetricKeyPair().getEncryptionAlgorithmType(), kpd.getNonPQCASymmetricKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getNonPQCASymmetricKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType());

		b = kpd.getASymmetricPublicKey().encode(false);
		Assert.assertEquals(b.length, kpd.getASymmetricPublicKey().encode(true).length-16);
		HybridASymmetricPublicKey pk=(HybridASymmetricPublicKey) DecentralizedValue.decode(b);
		Assert.assertEquals(pk, kpd.getASymmetricPublicKey());
		Assert.assertEquals(pk.getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getNonPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.getPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.getTimeExpirationUTC(), Long.MAX_VALUE);


		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPublicKey().encode(true)),
				kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPrivateKey().encode()),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.encode(true)), kpd);
		Assert.assertEquals(((HybridASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPrivateKey(),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(((HybridASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPublicKey(),
				kpd.getASymmetricPublicKey());
		System.out.println(nonPQCType+"; "+PQCType+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());

	}

	@Test(dataProvider = "provideDataForASymetricSignatures")
	public void testASymmetricKeyPairEncodingForSignature(ASymmetricAuthenticatedSignatureType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);

		ASymmetricKeyPair kpd=generateKeyPair(type);

		byte[] b = kpd.encode(false);
		Assert.assertEquals(b.length, kpd.encode(true).length-8);

		ASymmetricKeyPair kpd2=(ASymmetricKeyPair)DecentralizedValue.decode(b);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getKeySizeBits(), kpd.getASymmetricPrivateKey().getKeySizeBits());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getBytesPublicKey(), kpd.getASymmetricPublicKey().getBytesPublicKey());
		Assert.assertEquals(kpd2.getEncryptionAlgorithmType(), kpd.getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getAuthenticatedSignatureAlgorithmType(), kpd.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getEncryptionAlgorithmType());

		b = kpd.getASymmetricPublicKey().encode(false);
		Assert.assertEquals(b.length, kpd.getASymmetricPublicKey().encode(true).length-8);
		ASymmetricPublicKey pk=(ASymmetricPublicKey)DecentralizedValue.decode(b);
		Assert.assertEquals(pk.getBytesPublicKey(), kpd.getASymmetricPublicKey().getBytesPublicKey());
		Assert.assertEquals(pk.getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.getTimeExpirationUTC(), Long.MAX_VALUE);

		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPublicKey().encode(true)),
				kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.getASymmetricPrivateKey().encode()),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(DecentralizedValue.decode(kpd.encode(true)), kpd);
		Assert.assertEquals(((ASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPrivateKey(),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(((ASymmetricKeyPair)DecentralizedValue.decode(kpd.encode(true))).getASymmetricPublicKey(),
				kpd.getASymmetricPublicKey());
        System.out.println(type+" :");
        System.out.println("\tKey pair encoding : "+kpd.toString());
        System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tJava naviteve public key encoding length : "+kpd.getASymmetricPublicKey().toJavaNativeKey().getEncoded().length);
        System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());

	}
	@Test(dataProvider = "provideDataForASymetricSignatures")
	public void testASymmetricKeyExpirationTimeChange(ASymmetricAuthenticatedSignatureType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		testASymmetricKeyExpirationTimeChange(generateKeyPair(type));
	}
	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricKeyExpirationTimeChange(ASymmetricEncryptionType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		testASymmetricKeyExpirationTimeChange(generateKeyPair(type));
	}

	private void testASymmetricKeyExpirationTimeChange(ASymmetricKeyPair keyPair)
	{

		ASymmetricKeyPair newKeyPair=keyPair.getKeyPairWithNewExpirationTime(-1);
		ASymmetricPublicKey pk=keyPair.getASymmetricPublicKey().getPublicKeyWithNewExpirationTime(-1);
		Assert.assertEquals(newKeyPair.getASymmetricPrivateKey(), keyPair.getASymmetricPrivateKey());
		Assert.assertEquals(newKeyPair.getASymmetricPublicKey().getBytesPublicKey(), keyPair.getASymmetricPublicKey().getBytesPublicKey());
		Assert.assertEquals(newKeyPair.getASymmetricPrivateKey().getBytesPrivateKey(), keyPair.getASymmetricPrivateKey().getBytesPrivateKey());
		Assert.assertEquals(newKeyPair.getKeySizeBits(), keyPair.getKeySizeBits());
		Assert.assertEquals(newKeyPair.getASymmetricPublicKey().getKeySizeBits(), keyPair.getASymmetricPublicKey().getKeySizeBits());
		Assert.assertEquals(newKeyPair.getASymmetricPrivateKey().getKeySizeBits(), keyPair.getASymmetricPrivateKey().getKeySizeBits());
		Assert.assertEquals(newKeyPair.getASymmetricPublicKey().getTimeExpirationUTC(), -1);
		Assert.assertEquals(newKeyPair.getTimeExpirationUTC(), -1);
		Assert.assertEquals(newKeyPair.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType(), keyPair.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(newKeyPair.getASymmetricPublicKey().getEncryptionAlgorithmType(), keyPair.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(newKeyPair.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType(), keyPair.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(newKeyPair.getASymmetricPrivateKey().getEncryptionAlgorithmType(), keyPair.getASymmetricPrivateKey().getEncryptionAlgorithmType());
		Assert.assertEquals(newKeyPair.getAuthenticatedSignatureAlgorithmType(), keyPair.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(newKeyPair.getEncryptionAlgorithmType(), keyPair.getEncryptionAlgorithmType());
		Assert.assertEquals(newKeyPair.hashCode(), keyPair.hashCode());


		Assert.assertEquals(pk.getBytesPublicKey(), keyPair.getASymmetricPublicKey().getBytesPublicKey());
		Assert.assertEquals(pk.getKeySizeBits(), keyPair.getASymmetricPublicKey().getKeySizeBits());
		Assert.assertEquals(pk.getTimeExpirationUTC(), -1);
		Assert.assertEquals(pk.getAuthenticatedSignatureAlgorithmType(), keyPair.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(pk.getEncryptionAlgorithmType(), keyPair.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(pk.hashCode(), keyPair.getASymmetricPublicKey().hashCode());

	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncodingForEncryption",
			"testReadWriteDataPackaged" })
	public void testASymmetricSecretMessageExchanger(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalAccessException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, IllegalStateException {
		System.out.println("Testing ASymmetricSecretMessageExchanger " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (short keySize = 2048; keySize <= 4096; keySize += 1024) {
			ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, keySize).generateKeyPair();
			ASymmetricKeyPair kpl = type.getKeyPairGenerator(rand, keySize).generateKeyPair();

			P2PASymmetricSecretMessageExchanger algoLocal = new P2PASymmetricSecretMessageExchanger(rand,
					kpl.getASymmetricPublicKey());
			P2PASymmetricSecretMessageExchanger algoDistant = new P2PASymmetricSecretMessageExchanger(rand,
					kpd.getASymmetricPublicKey());
			algoLocal.setDistantPublicKey(algoDistant.encodeMyPublicKey());
			algoDistant.setDistantPublicKey(algoLocal.encodeMyPublicKey());
			algoLocal.setCost((byte)11);
			algoDistant.setCost((byte)11);

			byte[] falseMessage = new byte[10];
			rand.nextBytes(falseMessage);

			for (byte[] m : messagesToEncrypt) {
				byte[] localCrypt = algoLocal.encode(m, salt, true);
				Assert.assertTrue(localCrypt.length != 0);
				Assert.assertTrue(algoDistant.verifyDistantMessage(m, salt, localCrypt, true));
				Assert.assertFalse(algoDistant.verifyDistantMessage(m, salt, falseMessage, true));
				Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, salt, localCrypt, true));

				byte[] distantCrypt = algoDistant.encode(m, salt, true);
				Assert.assertTrue(distantCrypt.length != 0);
				Assert.assertTrue(algoLocal.verifyDistantMessage(m, salt, distantCrypt, true));
				Assert.assertFalse(algoLocal.verifyDistantMessage(m, salt, falseMessage, true));
				Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, salt, distantCrypt, true));
			}

			for (byte[] m : messagesToEncrypt) {
				byte[] localCrypt = algoLocal.encode(m, salt, false);
				Assert.assertTrue(localCrypt.length != 0);
				Assert.assertTrue(algoDistant.verifyDistantMessage(m, salt, localCrypt, false));
				Assert.assertFalse(algoDistant.verifyDistantMessage(m, salt, falseMessage, false));
				Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, salt, localCrypt, false));

				byte[] distantCrypt = algoDistant.encode(m, salt, false);
				Assert.assertTrue(distantCrypt.length != 0);
				Assert.assertTrue(algoLocal.verifyDistantMessage(m, salt, distantCrypt, false));
				Assert.assertFalse(algoLocal.verifyDistantMessage(m, salt, falseMessage, false));
				Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, salt, distantCrypt, false));
			}
			for (byte[] m : messagesToEncrypt) {
				byte[] localCrypt = algoLocal.encode(m, null, true);
				Assert.assertTrue(localCrypt.length != 0);
				Assert.assertTrue(algoDistant.verifyDistantMessage(m, null, localCrypt, true));
				Assert.assertFalse(algoDistant.verifyDistantMessage(m, null, falseMessage, true));
				Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, null, localCrypt, true));

				byte[] distantCrypt = algoDistant.encode(m, null, true);
				Assert.assertTrue(distantCrypt.length != 0);
				Assert.assertTrue(algoLocal.verifyDistantMessage(m, null, distantCrypt, true));
				Assert.assertFalse(algoLocal.verifyDistantMessage(m, null, falseMessage, true));
				Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, null, distantCrypt, true));
			}
			for (byte[] m : messagesToEncrypt) {
				byte[] localCrypt = algoLocal.encode(m, null, false);
				Assert.assertTrue(localCrypt.length != 0);
				Assert.assertTrue(algoDistant.verifyDistantMessage(m, null, localCrypt, false));
				Assert.assertFalse(algoDistant.verifyDistantMessage(m, null, falseMessage, false));
				Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, null, localCrypt, false));

				byte[] distantCrypt = algoDistant.encode(m, null, false);
				Assert.assertTrue(distantCrypt.length != 0);
				Assert.assertTrue(algoLocal.verifyDistantMessage(m, null, distantCrypt, false));
				Assert.assertFalse(algoLocal.verifyDistantMessage(m, null, falseMessage, false));
				Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, null, distantCrypt, false));
			}
			String password = "password";
			String falsePassword = "falsePassword";
			byte[] localCrypt = algoLocal.encode(password, salt);
			Assert.assertTrue(localCrypt.length != 0);
			Assert.assertTrue(algoDistant.verifyDistantMessage(password, salt, localCrypt));
			Assert.assertFalse(algoDistant.verifyDistantMessage(password, salt, falseMessage));
			Assert.assertFalse(algoDistant.verifyDistantMessage(falsePassword, salt, localCrypt));

			byte[] distantCrypt = algoDistant.encode(password, salt);
			Assert.assertTrue(distantCrypt.length != 0);
			Assert.assertTrue(algoLocal.verifyDistantMessage(password, salt, distantCrypt));
			Assert.assertFalse(algoLocal.verifyDistantMessage(password, salt, falseMessage));
			Assert.assertFalse(algoLocal.verifyDistantMessage(falsePassword, salt, distantCrypt));

		}
	}

	@DataProvider(name = "provideDataForP2PJPAKEPasswordExchanger", parallel = true)
	public Object[][] provideDataForP2PJPAKEPasswordExchanger() {
		byte[] salt = new byte[] { (byte) 21, (byte) 5645, (byte) 512, (byte) 42310, (byte) 24, (byte) 0, (byte) 1,
				(byte) 1231, (byte) 34 };

		Object[][] res = new Object[8][];

		res[0] = new Object[] {Boolean.TRUE, salt, Boolean.TRUE};
		res[1] = new Object[] {Boolean.TRUE, salt, Boolean.FALSE};
		res[2] = new Object[] {Boolean.FALSE, salt, Boolean.FALSE};
		res[3] = new Object[] {Boolean.FALSE, salt, Boolean.TRUE};
		res[4] = new Object[] {Boolean.TRUE, null, Boolean.TRUE};
		res[5] = new Object[] {Boolean.TRUE, null, Boolean.FALSE};
		res[6] = new Object[] {Boolean.FALSE, null, Boolean.FALSE};
		res[7] = new Object[] {Boolean.FALSE, null, Boolean.TRUE};

		return res;
	}

	@Test(dataProvider = "provideDataForP2PJPAKEPasswordExchanger", dependsOnMethods = { "testMessageDigest",
			"testPasswordHash" })
	public void testP2PJPAKEPasswordExchanger(boolean expectedVerify, byte[] salt, boolean messageIsKey)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException{
		char[] password = "password".toCharArray();
		char[] falsePassword = "falsePassword".toCharArray();
		AbstractSecureRandom random=SecureRandomType.DEFAULT.getSingleton(null);
		P2PJPAKESecretMessageExchanger exchanger1 = new P2PJPAKESecretMessageExchanger(random, "participant id 1".getBytes(), password,
				salt, 0, salt == null ? 0 : salt.length);
		P2PJPAKESecretMessageExchanger exchanger2 = new P2PJPAKESecretMessageExchanger(random, "participant id 2".getBytes(),
				expectedVerify ? password : falsePassword, salt, 0, salt == null ? 0 : salt.length);
		try {

			byte[] step11 = exchanger1.getDataToSend();
			byte[] step21 = exchanger2.getDataToSend();

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReception());
			Assert.assertFalse(exchanger2.hasFinishedReception());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			exchanger1.receiveData(step21);
			exchanger2.receiveData(step11);

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReception());
			Assert.assertFalse(exchanger2.hasFinishedReception());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());
			
			byte[] step12 = exchanger1.getDataToSend();
			byte[] step22 = exchanger2.getDataToSend();
			
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReception());
			Assert.assertFalse(exchanger2.hasFinishedReception());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			exchanger1.receiveData(step22);
			exchanger2.receiveData(step12);

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReception());
			Assert.assertFalse(exchanger2.hasFinishedReception());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			byte[] step13 = exchanger1.getDataToSend();
			byte[] step23 = exchanger2.getDataToSend();

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReception());
			Assert.assertFalse(exchanger2.hasFinishedReception());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
			
			exchanger1.receiveData(step23);
			exchanger2.receiveData(step13);
			
			Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify);
			Assert.assertEquals(exchanger2.isAgreementProcessValid(), expectedVerify);
			Assert.assertTrue(exchanger1.hasFinishedReception());
			Assert.assertTrue(exchanger2.hasFinishedReception());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
		} catch (Exception e) {
			if (expectedVerify)
				Assert.fail("Unexpected exception", e);
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
		}
	}

	@SuppressWarnings("deprecation")
	@DataProvider(name = "provideDataForP2PLoginAgreement", parallel = true)
	public Object[][] provideDataForP2PLoginAgreement() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		byte[] salt = new byte[] { (byte) 21, (byte) 5645, (byte) 512, (byte) 42310, (byte) 24, (byte) 0, (byte) 1,
				(byte) 1231, (byte) 34 };

		ArrayList<Object[]> res = new ArrayList<>();
		SymmetricSecretKey secretKey=SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_384.getKeyGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKey();
		ASymmetricKeyPair keyPair= ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_25519.getKeyPairGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKeyPair();
		for (byte[] m : messagesToEncrypt) {
			for (boolean expectedVerify : new boolean[] { true, false }) {
				for (byte[] s : new byte[][] { null, salt }) {
					for (boolean messageIsKey : new boolean[] { true, false }) {
						for (P2PLoginAgreementType t : P2PLoginAgreementType.values())
						{
							res.add(new Object[] { t, null, expectedVerify, messageIsKey, s, m , secretKey, null});
							if (t==P2PLoginAgreementType.JPAKE_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE || t==P2PLoginAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE)
								res.add(new Object[] { t, null, expectedVerify, messageIsKey, s, m , null, null});
						}
						for (ASymmetricLoginAgreementType t : ASymmetricLoginAgreementType.values())
						{
							res.add(new Object[] { null, t, expectedVerify, messageIsKey, s, m , null, keyPair});
						}
					}
				}
			}
		}

		Object[][] res2 = new Object[res.size()][];
		for (int i = 0; i < res.size(); i++)
			res2[i] = res.get(i);
		return res2;
	}

	@Test(dataProvider = "provideDataForP2PLoginAgreement", dependsOnMethods = { "testMessageDigest" })
	public void testP2PLoginAgreement(P2PLoginAgreementType type, ASymmetricLoginAgreementType asType, boolean expectedVerify, boolean messageIsKey, byte[] salt, byte[] m, SymmetricSecretKey secretKey, ASymmetricKeyPair keyPair)
			throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, InvalidAlgorithmParameterException, NoSuchPaddingException, InvalidKeyException {
		AbstractSecureRandom r = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] falseMessage = new byte[10];
		r.nextBytes(falseMessage);
		SymmetricSecretKey falseSecretKey=secretKey==null?null:secretKey.getAuthenticatedSignatureAlgorithmType().getKeyGenerator(r).generateKey();
		P2PLoginAgreement exchanger1;
		P2PLoginAgreement exchanger2;
		if (asType!=null)
		{
			exchanger1=asType.getAgreementAlgorithmForASymmetricSignatureRequester(r, keyPair);
			exchanger2=asType.getAgreementAlgorithmForASymmetricSignatureReceiver(r, keyPair.getASymmetricPublicKey());

		}
		else {
			exchanger1 = type.getAgreementAlgorithm(r, "participant id 1".getBytes(), m, 0,
					m.length, salt, 0, salt == null ? 0 : salt.length, messageIsKey, (expectedVerify ? secretKey : falseSecretKey));
			exchanger2 = type.getAgreementAlgorithm(r, "participant id 2".getBytes(),
					expectedVerify ? m : falseMessage, 0, (expectedVerify ? m : falseMessage).length, salt, 0,
					salt == null ? 0 : salt.length, messageIsKey, (expectedVerify ? secretKey : falseSecretKey));
		}
		try {
			int send=0, received=0;
			while (!exchanger1.hasFinishedSend())
			{
				byte[] step1 = exchanger1.getDataToSend();
				byte[] step2 = exchanger2.getDataToSend();
				send++;
				if (!expectedVerify)
				{
					for (int i=0;i<step1.length;i++)
						step1[i]=(byte)~step1[i];
					for (int i=0;i<step1.length;i++)
						step2[i]=(byte)~step2[i];
				}
				Assert.assertFalse(exchanger1.isAgreementProcessValid());
				Assert.assertFalse(exchanger2.isAgreementProcessValid());
				Assert.assertEquals(exchanger1.hasFinishedReception(), received==exchanger1.getStepsNumberForReception());
				Assert.assertEquals(exchanger2.hasFinishedReception(), received==exchanger2.getStepsNumberForReception());
				Assert.assertEquals(exchanger1.hasFinishedSend(), send==exchanger1.getStepsNumberForReception());
				Assert.assertEquals(exchanger2.hasFinishedSend(), send==exchanger2.getStepsNumberForReception());
				
				exchanger1.receiveData(step2);
				exchanger2.receiveData(step1);
				received++;
				if (exchanger1.hasFinishedReception())
				{
					Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify);
					Assert.assertEquals(exchanger2.isAgreementProcessValid(), expectedVerify);
				}
				else
				{
					Assert.assertEquals(exchanger1.hasFinishedReception(), received==exchanger1.getStepsNumberForReception(), ""+received+" ; "+exchanger1.getStepsNumberForReception());
					Assert.assertEquals(exchanger2.hasFinishedReception(), received==exchanger2.getStepsNumberForReception());
					Assert.assertEquals(exchanger1.hasFinishedSend(), send==exchanger1.getStepsNumberForReception());
					Assert.assertEquals(exchanger2.hasFinishedSend(), send==exchanger2.getStepsNumberForReception());
				}
			}
			Assert.assertEquals(send, received);
			Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify);
			Assert.assertEquals(exchanger2.isAgreementProcessValid(), expectedVerify);
			Assert.assertTrue(exchanger1.hasFinishedReception());
			Assert.assertTrue(exchanger2.hasFinishedReception());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
		} catch (Exception e) {
			if (expectedVerify)
			{
				e.printStackTrace();
				Assert.fail("Unexpected exception", e);
			}
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
		}
	}

	@Test(dataProvider = "provideDataForHybridASymetricEncryptions", dependsOnMethods = { "testHybridASymmetricKeyPairEncodingForEncryption" })
	public void testClientServerASymetricEncryptions(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpnonpqc = type.getNonPQCASymmetricEncryptionType().getKeyPairGenerator(rand, type.getNonPQCASymmetricEncryptionType().name().startsWith("BCPQC_MCELIECE_")?type.getNonPQCASymmetricEncryptionType().getDefaultKeySizeBits():2048).generateKeyPair();
		ASymmetricKeyPair kppqc = type.getPQCASymmetricEncryptionType().getKeyPairGenerator(rand, type.getPQCASymmetricEncryptionType().getDefaultKeySizeBits()).generateKeyPair();
		testClientServerASymetricEncryptions(new HybridASymmetricKeyPair(kpnonpqc, kppqc));

	}

	public void testClientServerASymetricEncryptions(AbstractKeyPair kp)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);

		ClientASymmetricEncryptionAlgorithm algoClient = new ClientASymmetricEncryptionAlgorithm(rand,
				kp.getASymmetricPublicKey());
		ServerASymmetricEncryptionAlgorithm algoServer = new ServerASymmetricEncryptionAlgorithm(kp);

		for (byte[] m : messagesToEncrypt) {
			byte[] encodedBytes = algoClient.encode(m);
			Assert.assertTrue(encodedBytes.length>0);
			if (!kp.isPostQuantumKey())
				Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeForEncryption(m.length));
			byte[] decodedBytes = algoServer.decode(encodedBytes);
			Assert.assertEquals(m, decodedBytes);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encodedBytes = algoClient.encode(m, off, size);
			if (!kp.isPostQuantumKey())
				Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeForEncryption(size));
			decodedBytes = algoServer.decode(encodedBytes);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(decodedBytes[i], m[i + off]);

		}

	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncodingForEncryption" })
	public void testClientServerASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp = type.getKeyPairGenerator(rand, type.name().startsWith("BCPQC_MCELIECE_")?type.getDefaultKeySizeBits():2048).generateKeyPair();

		testClientServerASymetricEncryptions(kp);

	}

	@Test(invocationCount = 20, threadPoolSize = 16)
	public void testEncodeAndSeparateEncoding() {
		Random rand = new Random(System.currentTimeMillis());
		byte[] t1 = new byte[rand.nextInt(100) + 20];
		byte[] t2 = new byte[rand.nextInt(100) + 20];
		byte[] encoded = Bits.concatenateEncodingWithShortSizedTabs(t1, t2);
		byte[][] decoded = Bits.separateEncodingsWithShortSizedTabs(encoded);
		Assert.assertEquals(t1, decoded[0]);
		Assert.assertEquals(t2, decoded[1]);
		encoded = Bits.concatenateEncodingWithIntSizedTabs(t1, t2);
		decoded = Bits.separateEncodingsWithIntSizedTabs(encoded);
		Assert.assertEquals(t1, decoded[0]);
		Assert.assertEquals(t2, decoded[1]);
	}

	@Test(dataProvider = "provideDataForHybridEncryptions")
	public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, InvalidKeySpecException, IllegalStateException, IllegalArgumentException, InvalidWrappingException, ShortBufferException {
		System.out.println("Testing " + astype + "/" + stype);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = astype.getKeyPairGenerator(rand, (short)1024).generateKeyPair();

		SymmetricSecretKey localKey = stype.getKeyGenerator(rand).generateKey();
		SymmetricEncryptionAlgorithm algoLocalS = new SymmetricEncryptionAlgorithm(rand, localKey);
		ASymmetricKeyWrapperType kw;
		if (astype.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)
			kw=ASymmetricKeyWrapperType.GNU_RSA_OAEP_SHA2_384;
		else if (astype.name().startsWith("BCPQC_MCELIECE_"))
			kw=ASymmetricKeyWrapperType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256;
		else
			kw=ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP_SHA3_512;
		
			
		byte[] localEncryptedKey = kw.wrapKey(rand, kpd.getASymmetricPublicKey(), localKey);
		SymmetricSecretKey decryptedKey=kw.unwrapKey(kpd.getASymmetricPrivateKey(), localEncryptedKey);
		Assert.assertEquals(localKey.getAuthenticatedSignatureAlgorithmType(), decryptedKey.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(localKey.getEncryptionAlgorithmType(), decryptedKey.getEncryptionAlgorithmType());
		Assert.assertEquals(localKey.getKeySizeBits(), decryptedKey.getKeySizeBits());
		SymmetricEncryptionAlgorithm algoDistantS = new SymmetricEncryptionAlgorithm(rand, decryptedKey);

		for (byte[] m : messagesToEncrypt) {
			byte[] md = algoDistantS.decode(algoLocalS.encode(m));
			Assert.assertEquals(md.length, m.length, "Testing size " + astype + "/" + stype);
			Assert.assertEquals(md, m, "Testing " + astype + "/" + stype);

			md = algoLocalS.decode(algoDistantS.encode(m));
			Assert.assertEquals(md.length, m.length, "Testing size " + astype + "/" + stype);
			Assert.assertEquals(md, m, "Testing " + astype + "/" + stype);
		}

	}

	@Test(dataProvider = "provideMessageDigestType")
	public void testMessageDigest(MessageDigestType type) throws NoSuchAlgorithmException, NoSuchProviderException {
		System.out.println("Testing message digest " + type);

		AbstractMessageDigest md = type.getMessageDigestInstance();
		for (byte[] m : messagesToEncrypt) {
			byte[] b1 = md.digest(m);
			md.reset();
			byte[] b2 = md.digest(m);

			Assert.assertEquals(b1, b2);

		}

	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncodingForEncryption" })
	public void testP2PASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, ShortBufferException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kpl = type.getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		P2PASymmetricEncryptionAlgorithm algoDistant = new P2PASymmetricEncryptionAlgorithm(kpd,
				kpl.getASymmetricPublicKey());
		P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(kpl,
				kpd.getASymmetricPublicKey());

		testP2PASymetricEncryptionsImpl(rand, type, algoDistant, algoLocal);

	}
	@Test(dataProvider = "provideDataForHybridASymetricEncryptions", dependsOnMethods = { "testHybridASymmetricKeyPairEncodingForEncryption" })
	public void testHybridP2PASymetricEncryptions(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, ShortBufferException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpdnonpqc = type.getNonPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kplnonpqc = type.getNonPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kpdpqc = type.getPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kplpqc = type.getPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		HybridASymmetricKeyPair kpd=new HybridASymmetricKeyPair(kpdnonpqc, kpdpqc);
		HybridASymmetricKeyPair kpl=new HybridASymmetricKeyPair(kplnonpqc, kplpqc);
		P2PASymmetricEncryptionAlgorithm algoDistant = new P2PASymmetricEncryptionAlgorithm(kpd,
				kpl.getASymmetricPublicKey());
		P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(kpl,
				kpd.getASymmetricPublicKey());

		testP2PASymetricEncryptionsImpl(rand, type, algoDistant, algoLocal);

	}

	public void testP2PASymetricEncryptionsImpl(AbstractSecureRandom rand, Object type, P2PASymmetricEncryptionAlgorithm algoDistant, P2PASymmetricEncryptionAlgorithm algoLocal)
			throws NoSuchAlgorithmException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, ShortBufferException, IllegalStateException {


		for (byte[] m : messagesToEncrypt) {
			byte[] encoded = algoLocal.encode(m);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(m.length));
			byte[] md = algoDistant.decode(encoded);
			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);

			encoded = algoDistant.encode(m);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(m.length));
			md = algoLocal.decode(encoded);

			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);


			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encoded = algoLocal.encode(m, off, size);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(size));
			md = algoDistant.decode(encoded);
			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(md[i], m[i + off]);

			encoded = algoDistant.encode(m, off, size);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(size));
			md = algoLocal.decode(encoded);

			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(md[i], m[i + off]);


		}

	}

	@Test(dataProvider = "providePasswordHashTypes")
	public void testPasswordHash(PasswordHashType type) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		SecureRandom random = new SecureRandom();
		PasswordHash ph = new PasswordHash(type, random);
		String password = "password";
		String invalidPassword = "invalid password";
		ph.setCost((byte)7);
		byte[] hashedValue = ph.hash(password);
		Assert.assertTrue(PasswordHash.checkValidHashedPassword(password, hashedValue));
		Assert.assertFalse(PasswordHash.checkValidHashedPassword(invalidPassword, hashedValue));
		Assert.assertEquals(PasswordHashType.getPasswordHashLengthBytes(hashedValue), type.getDefaultHashLengthBytes());
		Assert.assertEquals(PasswordHashType.getSaltSizeBytes(hashedValue), ph.getSaltSizeBytes());
		byte[] staticSalt = new byte[20];
		random.nextBytes(staticSalt);
		hashedValue = ph.hash(password, staticSalt);
		Assert.assertTrue(PasswordHash.checkValidHashedPassword(password, hashedValue, staticSalt));
		Assert.assertFalse(PasswordHash.checkValidHashedPassword(password, hashedValue));
		Assert.assertFalse(PasswordHash.checkValidHashedPassword(invalidPassword, hashedValue, staticSalt));
	}
	@Test(dataProvider = "providePasswordKeyDerivationTypesForSymmetricEncryptions", dependsOnMethods="testPasswordHash")
	public void testPasswordKeyDerivation(PasswordBasedKeyGenerationType derivationType, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		String password = "password";
		String invalidPassword = "invalid password";
		Random r=new Random(System.currentTimeMillis());
		byte[] salt=new byte[32];
		r.nextBytes(salt);
		SymmetricSecretKey key1=derivationType.derivateKey(password.toCharArray(), salt, (byte)7, encryptionType);
		Assert.assertEquals(key1.getKeySizeBits(), encryptionType.getDefaultKeySizeBits());
		Assert.assertEquals(key1.getEncryptionAlgorithmType(), encryptionType);
		Assert.assertEquals(key1.encode(), derivationType.derivateKey(password.toCharArray(), salt, (byte)7, encryptionType).encode());
		Assert.assertNotEquals(key1.encode(), derivationType.derivateKey(invalidPassword.toCharArray(), salt,(byte) 7, encryptionType).encode());
	}
	@Test(dataProvider = "providePasswordKeyDerivationTypesForSymmetricSignatures", dependsOnMethods="testPasswordHash")
	public void testPasswordKeyDerivation(PasswordBasedKeyGenerationType derivationType, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		String password = "password";
		String invalidPassword = "invalid password";
		Random r=new Random(System.currentTimeMillis());
		byte[] salt=new byte[32];
		r.nextBytes(salt);
		SymmetricSecretKey key1=derivationType.derivateKey(password.toCharArray(), salt, (byte)7, signatureType);
		Assert.assertEquals(key1.getKeySizeBits(), signatureType.getDefaultKeySizeBits());
		Assert.assertEquals(key1.getAuthenticatedSignatureAlgorithmType(), signatureType);
		Assert.assertEquals(key1.encode(), derivationType.derivateKey(password.toCharArray(), salt, (byte)7, signatureType).encode());
		Assert.assertNotEquals(key1.encode(), derivationType.derivateKey(invalidPassword.toCharArray(), salt, (byte)7, signatureType).encode());
	}

	@DataProvider(name="providePasswordKeyDerivationTypesForSymmetricEncryptions", parallel=true)
	public Object[][] providePasswordKeyDerivationTypesForSymmetricEncryptions()
	{
		Object[][] res=new Object[PasswordBasedKeyGenerationType.values().length*SymmetricEncryptionType.values().length][];
		int index=0;
		for (PasswordBasedKeyGenerationType p : PasswordBasedKeyGenerationType.values())
		{
			for (SymmetricEncryptionType s : SymmetricEncryptionType.values())
			{
				if ((p.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(s.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO))
				{
					Object[] params = new Object[2];
					params[0]=p;
					params[1]=s;
					res[index++]=params;
				}
			}
		}
		Object[][] res2 = new Object[index][];
        System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}
	
	@DataProvider(name="providePasswordKeyDerivationTypesForSymmetricSignatures", parallel=true)
	public Object[][] providePasswordKeyDerivationTypesForSymmetricSignatures()
	{
		Object[][] res=new Object[PasswordBasedKeyGenerationType.values().length*SymmetricAuthentifiedSignatureType.values().length][];
		int index=0;
		for (PasswordBasedKeyGenerationType p : PasswordBasedKeyGenerationType.values())
		{
			for (SymmetricAuthentifiedSignatureType s : SymmetricAuthentifiedSignatureType.values())
			{
				if ((p.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(s.getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))
				{
					Object[] params = new Object[2];
					params[0]=p;
					params[1]=s;
					res[index++]=params;
				}
			}
		}
		Object[][] res2 = new Object[index][];
        System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}
	
	@Test(dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods = "testEncodeAndSeparateEncoding")
	public void testSecretKeyEncoding(SymmetricEncryptionType type) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException,
			IllegalArgumentException, InvalidKeySpecException {
		System.out.println("Testing " + type);
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey key = type.getKeyGenerator(random).generateKey();
		Assert.assertEquals(DecentralizedValue.decode(key.encode()), key);
		new SymmetricEncryptionAlgorithm(random, key);
		Assert.assertEquals(DecentralizedValue.decode(key.encode()), key);

	}

	@Test(dataProvider = "provideSecureRandomType")
	public void testSecureRandom(SecureRandomType type) throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom random;
		System.out.println("Test "+type);
		random = type.getSingleton("nonce".getBytes(), "parameter".getBytes());
		System.out.println(type+" instantiated");
		random.nextBytes(new byte[10]);
		if (type!=SecureRandomType.NativePRNG && type!=SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG && type!=SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG && type!=SecureRandomType.GNU_DEFAULT && type!=SecureRandomType.SHA1PRNG && type.getProvider()!=CodeProvider.BCFIPS)
		{
			
			int nb= 110000;
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
		}
		System.out.println("End test "+type);
	}

	@SuppressWarnings("deprecation")
	@Test(dataProvider = "provideDataForASymmetricSignatureTest")
	public void testAsymmetricSignatures(ASymmetricAuthenticatedSignatureType type, ASymmetricAuthenticatedSignatureType typePQC, AbstractKeyPair kpd, int keySize)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException,
			NoSuchProviderException, IllegalStateException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException {
		System.out.println("Testing asymmetric signature : " +type+", "+ keySize+", "+kpd.getASymmetricPublicKey().getKeyBytes().length);
		byte[] b = kpd.encode(true);
		AbstractKeyPair kpd2=(AbstractKeyPair)DecentralizedValue.decode(b);
		Assert.assertEquals(kpd2, kpd);
		ASymmetricAuthenticatedSignerAlgorithm signer = new ASymmetricAuthenticatedSignerAlgorithm(kpd.getASymmetricPrivateKey());
		ASymmetricAuthenticatedSignatureCheckerAlgorithm checker = new ASymmetricAuthenticatedSignatureCheckerAlgorithm(kpd.getASymmetricPublicKey());
		byte[] signature=testSignature(signer, checker);
		if (type==null) {
			ASymmetricKeyPair kpd3=(ASymmetricKeyPair)kpd;
			if (kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_25519
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_25519
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_25519
				/*&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_M_511
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_M_511
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_M_511
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_M_221
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_M_221
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_M_221
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_M_383
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_M_383
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_M_383
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_41417
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_41417
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_41417	*/
			)
				Assert.assertEquals(kpd3.getAuthenticatedSignatureAlgorithmType().getSignatureSizeBits(kpd3.getKeySizeBits()), signature.length * 8);
		}
	}
	
	@Test(dataProvider="provideDataSymmetricKeyWrapperForEncryption")
	public void testSymmetricKeyWrapperForEncryption(SymmetricKeyWrapperType typeWrapper, SymmetricEncryptionType asetype, SymmetricEncryptionType setype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey kp=asetype.getKeyGenerator(rand, asetype.getDefaultKeySizeBits()).generateKey();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, setype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(kp, sk, rand);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp, wrappedKey);
		Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
		Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
        Assert.assertEquals(sk.getKeyBytes(), sk2.getKeyBytes());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
		Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());
	}
	@Test(dataProvider="provideDataSymmetricKeyWrapperForSignature")
	public void testSymmetricKeyWrapperForSignature(SymmetricKeyWrapperType typeWrapper, SymmetricEncryptionType asetype, SymmetricAuthentifiedSignatureType setype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey kp=asetype.getKeyGenerator(rand, (short)128).generateKey();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, (short)128).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(kp, sk, rand);

		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp, wrappedKey);
		Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
		Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());

        Assert.assertEquals(sk.getKeyBytes(), sk2.getKeyBytes(), sk+" , "+sk2+" , "+Base64.encodeBase64URLSafeString(wrappedKey));
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
		Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());
	}
	@DataProvider(name="provideDataSymmetricKeyWrapperForEncryption")
	public Object[][] provideDataSymmetricKeyWrapperForEncryption()
	{
		Object [][] res=new Object[SymmetricKeyWrapperType.values().length*SymmetricEncryptionType.values().length*SymmetricEncryptionType.values().length][];
		int index=0;
		for (SymmetricKeyWrapperType akpw : SymmetricKeyWrapperType.values())
		{
			for (SymmetricEncryptionType aet : SymmetricEncryptionType.values())
			{
				for (SymmetricEncryptionType set : SymmetricEncryptionType.values())
				{
					if ((akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(aet.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO) && (akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(set.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)
							&& akpw.getAlgorithmName().startsWith(aet.getAlgorithmName()))
					{
						Object[] params = new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
        System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}
	@DataProvider(name="provideDataSymmetricKeyWrapperForSignature", parallel=true)
	public Object[][] provideDataSymmetricKeyWrapperForSignature()
	{
		Object [][] res=new Object[SymmetricKeyWrapperType.values().length*SymmetricEncryptionType.values().length*SymmetricAuthentifiedSignatureType.values().length][];
		int index=0;
		for (SymmetricKeyWrapperType akpw : SymmetricKeyWrapperType.values())
		{
			for (SymmetricEncryptionType aet : SymmetricEncryptionType.values())
			{
				for (SymmetricAuthentifiedSignatureType set : SymmetricAuthentifiedSignatureType.values())
				{
					if ((akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(aet.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO) && (akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(set.getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO)
							&& akpw.getAlgorithmName().startsWith(aet.getAlgorithmName()))
					{
						Object[] params = new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
        System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}

	
	@Test(dataProvider="provideDataASymmetricKeyWrapperForEncryption")
	public void testASymmetricKeyWrapperForEncryption(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricEncryptionType setype)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp=asetype.getKeyPairGenerator(rand, (short)2048).generateKeyPair();

		testASymmetricKeyWrapperForEncryption(rand, kp, typeWrapper, asetype, setype);
		if (typeWrapper.isPostQuantumKeyAlgorithm())
			return;
		ASymmetricKeyPair kppqc= ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getKeyPairGenerator(rand, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getDefaultKeySizeBits(), Long.MAX_VALUE).generateKeyPair();
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), typeWrapper, asetype, setype);

	}
	public void testASymmetricKeyWrapperForEncryption(AbstractSecureRandom rand, AbstractKeyPair kp,  ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricEncryptionType setype)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, setype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(rand, kp.getASymmetricPublicKey(), sk);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp.getASymmetricPrivateKey(), wrappedKey);
		Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
		Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
		Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());
	}
	@Test(dataProvider="provideDataASymmetricKeyWrapperForSignature")
	public void testASymmetricKeyWrapperForSignature(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricAuthentifiedSignatureType ssigtype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp=asetype.getKeyPairGenerator(rand, (short)2048).generateKeyPair();

		testASymmetricKeyWrapperForSignature(rand, kp, typeWrapper, asetype, ssigtype);
		if (typeWrapper.isPostQuantumKeyAlgorithm())
			return;
		ASymmetricKeyPair kppqc= ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getKeyPairGenerator(rand, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getDefaultKeySizeBits(), Long.MAX_VALUE).generateKeyPair();
		testASymmetricKeyWrapperForSignature(rand, new HybridASymmetricKeyPair(kp, kppqc), typeWrapper, asetype, ssigtype);
	}

	public void testASymmetricKeyWrapperForSignature(AbstractSecureRandom rand, AbstractKeyPair kp, ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricAuthentifiedSignatureType ssigtype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		SymmetricSecretKey sk= ssigtype.getKeyGenerator(rand, ssigtype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(rand, kp.getASymmetricPublicKey(), sk);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp.getASymmetricPrivateKey(), wrappedKey);
		Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
		Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
		Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());

	}

	@DataProvider(name="provideDataASymmetricKeyWrapperForEncryption", parallel=true)
	public Object[][] provideDataASymmetricKeyWrapperForEncryption()
	{
		Object [][] res=new Object[ASymmetricKeyWrapperType.values().length*ASymmetricEncryptionType.values().length*SymmetricEncryptionType.values().length][];
		int index=0;
		for (ASymmetricKeyWrapperType akpw : ASymmetricKeyWrapperType.values())
		{
			for (ASymmetricEncryptionType aet : ASymmetricEncryptionType.values())
			{
				for (SymmetricEncryptionType set : SymmetricEncryptionType.values())
				{
					if (akpw.getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getCodeProvider().equals(set.getCodeProviderForEncryption()))
					{
						Object[] params = new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
        System.arraycopy(res, 0, res2, 0, index);
		return res2;

	}
	@DataProvider(name="provideDataASymmetricKeyWrapperForSignature", parallel=true)
	public Object[][] provideDataASymmetricKeyWrapperForSignature()
	{
		Object [][] res=new Object[ASymmetricKeyWrapperType.values().length*ASymmetricEncryptionType.values().length*SymmetricAuthentifiedSignatureType.values().length][];
		int index=0;
		for (ASymmetricKeyWrapperType akpw : ASymmetricKeyWrapperType.values())
		{
			for (ASymmetricEncryptionType aet : ASymmetricEncryptionType.values())
			{
				for (SymmetricAuthentifiedSignatureType set : SymmetricAuthentifiedSignatureType.values())
				{
					if (akpw.getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getCodeProvider().equals(set.getCodeProviderForSignature()))
					{
						Object[] params = new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
        System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}
	
	private byte[] testSignature(AbstractAuthenticatedSignerAlgorithm signer, AbstractAuthenticatedCheckerAlgorithm checker) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, IllegalStateException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException
	{
		byte[] m = new byte[100000];
		Random r=new Random(System.currentTimeMillis());
		r.nextBytes(m);

		byte[] signature = signer.sign(m);
		if (signer instanceof SymmetricAuthenticatedSignerAlgorithm)
			Assert.assertEquals(signer.getMacLengthBytes(), signature.length);
		Assert.assertTrue(checker.verify(m, signature));
		Assert.assertTrue(checker.verify(m, signature));
		Assert.assertTrue(checker.verify(m, 0, m.length, signature, 0, signature.length));

		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) ~m[i];
		}

		Assert.assertFalse(checker.verify(m, signature));
		return signature;
		
	}

	@Test(dataProvider = "provideDataForSymmetricSignatureTest")
	public void testSymmetricSignatures(SymmetricAuthentifiedSignatureType type, SymmetricSecretKey secretKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException,
			NoSuchProviderException, IllegalStateException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException {
		System.out.println("Testing symmetric signature : " + secretKey.getAuthenticatedSignatureAlgorithmType());
		SymmetricAuthenticatedSignerAlgorithm signer = new SymmetricAuthenticatedSignerAlgorithm(secretKey);
		SymmetricAuthenticatedSignatureCheckerAlgorithm checker = new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKey);
		byte[] signature=testSignature(signer, checker);
		Assert.assertEquals(signature.length*8, secretKey.getAuthenticatedSignatureAlgorithmType().getSignatureSizeInBits());
	}

	@Test(dataProvider = "provideDataForSymetricEncryptions")
	public void testSymmetricEncryptions(SymmetricEncryptionType type) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
		testSymmetricEncryptionsCompatibility(type, type);

	}


	@Test(dataProvider = "provideDataForTestSymmetricEncryptionCompatibility", dependsOnMethods = "testSymmetricEncryptions")
	public void testSymmetricEncryptionsCompatibility(SymmetricEncryptionType type1, SymmetricEncryptionType type2) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException, IllegalStateException, ShortBufferException {
		System.out.println("Testing " + type1+", "+type2);
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);

		SymmetricSecretKey key1 = type1.getKeyGenerator(random).generateKey();
		SymmetricSecretKey key2;

		if (type2.getCodeProviderForEncryption()!=CodeProvider.GNU_CRYPTO && type2.getCodeProviderForEncryption()!=CodeProvider.BC && type2.getCodeProviderForEncryption()==CodeProvider.BCFIPS)
			key2=new SymmetricSecretKey(type2, key1.toJavaNativeKey(), key1.getKeySizeBits());
		else 
			key2=new SymmetricSecretKey(type2, key1.getKeyBytes(), key1.getKeySizeBits());

		byte counterSizeBytes=(byte)random.nextInt(key1.getEncryptionAlgorithmType().getMaxCounterSizeInBytesUsedWithBlockMode()+1);
		SymmetricEncryptionAlgorithm algoDistant;
		if (type1.isBlockModeSupportingCounter())
		{
			algoDistant = new SymmetricEncryptionAlgorithm(random, key1, counterSizeBytes, true);
			Assert.assertEquals(algoDistant.getBlockModeCounterBytes(), counterSizeBytes);
            Assert.assertFalse(algoDistant.useExternalCounter());
			Assert.assertEquals(algoDistant.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);
			Assert.assertEquals(algoDistant.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);
		}
		
		
		algoDistant = new SymmetricEncryptionAlgorithm(random, key1, counterSizeBytes, false);
		Assert.assertEquals(algoDistant.getBlockModeCounterBytes(), counterSizeBytes);
		Assert.assertEquals(algoDistant.useExternalCounter(), counterSizeBytes>0);
		Assert.assertEquals(algoDistant.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes());
		Assert.assertEquals(algoDistant.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);
		SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(random, key2, counterSizeBytes, false);
		Assert.assertEquals(algoLocal.getBlockModeCounterBytes(), counterSizeBytes);
		Assert.assertEquals(algoLocal.useExternalCounter(), counterSizeBytes>0);
		Assert.assertEquals(algoLocal.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes());
		Assert.assertEquals(algoLocal.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);

		
		
		byte[] counter=new byte[counterSizeBytes];
		Random rand = new Random(System.currentTimeMillis());

		for (byte[] m : messagesToEncrypt) {
			rand.nextBytes(counter);
			byte[] encrypted = algoLocal.encode(m, null, counter);
			int mlength=m.length;
			
			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(mlength), "length=" + m.length);

			Assert.assertTrue(encrypted.length >= m.length);
			byte[] decrypted = algoDistant.decode(encrypted, null, counter);
			Assert.assertEquals(decrypted.length, m.length, "Testing size " + type1+", "+type2);
			Assert.assertEquals(decrypted, m, "Testing " + type1+", "+type2);
			byte[] md = decrypted;
			Assert.assertEquals(md.length, m.length, "Testing size " + type1+", "+type2);
			Assert.assertEquals(md, m, "Testing " + type1+", "+type2);
			mlength=m.length;
			encrypted = algoDistant.encode(m, null, counter);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeForEncryption(mlength));
			Assert.assertTrue(encrypted.length >= m.length);
			md = algoLocal.decode(encrypted, null, counter);
			Assert.assertEquals(md.length, m.length, "Testing size " + type1+", "+type2);
			Assert.assertEquals(md, m, "Testing " + type1+", "+type2);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			byte[] associatedData = new byte[random.nextInt(128) + 127];
			if (type1.supportAssociatedData())
				encrypted = algoLocal.encode(m, off, size, associatedData, 0, associatedData.length, counter);
			else
				encrypted = algoLocal.encode(m, off, size, null, 0, 0, counter);

			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(size));
			Assert.assertTrue(encrypted.length >= size);
			if (type1.supportAssociatedData())
				decrypted = algoDistant.decode(encrypted, associatedData, counter);
			else
				decrypted = algoDistant.decode(encrypted, null, counter);
			Assert.assertEquals(decrypted.length, size, "Testing size " + type1+", "+type2);
			Assert.assertTrue(algoDistant.getOutputSizeForDecryption(encrypted.length)>=size, "Testing size " + type1+", "+type2);
			for (int i = 0; i < decrypted.length; i++)
				Assert.assertEquals(decrypted[i], m[i + off]);
			if (type1.supportAssociatedData())
				md = algoDistant.decode(encrypted, associatedData, counter);
			else
				md = algoDistant.decode(encrypted, null, counter);

			Assert.assertEquals(md.length, size, "Testing size " + type1+", "+type2);
			Assert.assertTrue(algoDistant.getOutputSizeForDecryption(encrypted.length)>=size, "Testing size " + type1+", "+type2);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

			encrypted = algoDistant.encode(m, off, size, null, 0, 0, counter);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeForEncryption(size));
			Assert.assertTrue(encrypted.length >= size);

			md = algoLocal.decode(encrypted, null, counter);
			Assert.assertEquals(md.length, size, "Testing size " + type1+", "+type2);
			Assert.assertTrue(algoDistant.getOutputSizeForDecryption(encrypted.length)>=size, "Testing size " + type1+", "+type2);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

		}

	}
	
	@Test(invocationCount = 4000, threadPoolSize = 16)
	public void testReadWriteDataPackaged() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		Random rand = new Random(System.currentTimeMillis());
		byte[] originalBytes = new byte[50 + rand.nextInt(10000)];
		rand.nextBytes(originalBytes);
		int randNb = rand.nextInt(10000);
		byte[] encodedBytes = OutputDataPackagerWithRandomValues.encode(originalBytes, randNb);
		// Assert.assertTrue(encodedBytes.length>originalBytes.length);
		Assert.assertTrue(encodedBytes.length >= originalBytes.length, "invalid size : " + encodedBytes.length
				+ " (originalBytes size=" + originalBytes.length + ", randNb=" + randNb + ") ");
		byte[] decodedBytes = InputDataPackagedWithRandomValues.decode(encodedBytes);
		Assert.assertEquals(decodedBytes.length, originalBytes.length);
		for (int i = 0; i < decodedBytes.length; i++)
			Assert.assertEquals(decodedBytes[i], originalBytes[i]);
	}

	
	
	private void testEncryptionAfterKeyExchange(AbstractSecureRandom random, SymmetricEncryptionType type, SymmetricSecretKey key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException, BadPaddingException, IllegalStateException, IllegalBlockSizeException, IOException, ShortBufferException
	{
		SymmetricEncryptionAlgorithm algoDistant = new SymmetricEncryptionAlgorithm(random, key);
		SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(random, key);

		Random rand = new Random(System.currentTimeMillis());

		for (byte[] m : messagesToEncrypt) {
			byte[] encrypted = algoLocal.encode(m);
			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(m.length), "length=" + m.length);

			Assert.assertTrue(encrypted.length >= m.length);
			byte[] decrypted = algoDistant.decode(encrypted);
			Assert.assertEquals(decrypted.length, m.length, "Testing size " + type);
			Assert.assertEquals(decrypted, m, "Testing " + type);
			byte[] md = decrypted;
			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);
			encrypted = algoDistant.encode(m);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeForEncryption(m.length));
			Assert.assertTrue(encrypted.length >= m.length);
			md = algoLocal.decode(encrypted);
			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encrypted = algoLocal.encode(m, off, size);

			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(size));
			Assert.assertTrue(encrypted.length >= size);
			decrypted = algoDistant.decode(encrypted);
			Assert.assertEquals(decrypted.length, size, "Testing size " + type);
			for (int i = 0; i < decrypted.length; i++)
				Assert.assertEquals(decrypted[i], m[i + off]);

			md = algoDistant.decode(encrypted);

			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

			encrypted = algoDistant.encode(m, off, size);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeForEncryption(size));
			Assert.assertTrue(encrypted.length >= size);

			md = algoLocal.decode(encrypted);
			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

		}
	}







	@Test(invocationCount = 5, dataProvider = "provideDataForHybridKeyAgreementsSignature", dependsOnMethods = "testMessageDigest")
	public void testKeyAgreementsForSignature(HybridKeyAgreementType keyAgreementType, SymmetricAuthentifiedSignatureType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);

		KeyAgreement client=keyAgreementType.getKeyAgreementClient(random, type, (short)256, keyingMaterial);
		KeyAgreement server=keyAgreementType.getKeyAgreementServer(random, type, (short)256, keyingMaterial);

		testKeyAgreementsForSignature(client, server, type);
	}

	@Test(invocationCount = 5, dataProvider = "provideDataForKeyAgreementsSignature", dependsOnMethods = "testMessageDigest")
	public void testKeyAgreementsForSignature(KeyAgreementType keyAgreementType, SymmetricAuthentifiedSignatureType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);
		
		KeyAgreement client=keyAgreementType.getKeyAgreementClient(random, type, (short)256, keyingMaterial);
		KeyAgreement server=keyAgreementType.getKeyAgreementServer(random, type, (short)256, keyingMaterial);

		testKeyAgreementsForSignature(client, server, type);
	}
	public void testKeyAgreementsForSignature(KeyAgreement client, KeyAgreement server, SymmetricAuthentifiedSignatureType type)
			throws Exception {

		do
		{
			if (!client.hasFinishedSend())
			{
				byte[] clientData=client.getDataToSend();

				server.receiveData(clientData);

			}
			if (!server.hasFinishedSend())
			{
				byte[] serverData=server.getDataToSend();

				client.receiveData(serverData);

			}
		} while(!server.hasFinishedReception() || !server.hasFinishedSend() || !client.hasFinishedReception() || !client.hasFinishedSend() );

		Assert.assertTrue(client.hasFinishedSend());
		Assert.assertTrue(server.hasFinishedReception());

		if (client instanceof HybridKeyAgreement)
		{
			HybridKeyAgreement ka=(HybridKeyAgreement)client;
			Assert.assertTrue(ka.getPQCKeyAgreement().isAgreementProcessValidImpl());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().isAgreementProcessValidImpl());
			Assert.assertTrue(ka.getPQCKeyAgreement().hasFinishedSend());
			Assert.assertTrue(ka.getPQCKeyAgreement().hasFinishedReception());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().hasFinishedSend());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().hasFinishedReception());
			Assert.assertTrue(ka.getPQCKeyAgreement().isAgreementProcessValid());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().isAgreementProcessValid());
		}
		if (server instanceof HybridKeyAgreement)
		{
			HybridKeyAgreement ka=(HybridKeyAgreement)server;
			Assert.assertTrue(ka.getPQCKeyAgreement().isAgreementProcessValidImpl());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().isAgreementProcessValidImpl());
			Assert.assertTrue(ka.getPQCKeyAgreement().hasFinishedSend());
			Assert.assertTrue(ka.getPQCKeyAgreement().hasFinishedReception());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().hasFinishedSend());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().hasFinishedReception());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().isAgreementProcessValid());
			Assert.assertTrue(ka.getPQCKeyAgreement().isAgreementProcessValid());
		}

		Assert.assertTrue(client.isAgreementProcessValid());
		Assert.assertTrue(server.isAgreementProcessValid());



		SymmetricSecretKey keyClient=client.getDerivedKey();
		SymmetricSecretKey keyServer=server.getDerivedKey();


		Assert.assertEquals(keyClient,keyServer);
		Assert.assertEquals(keyClient.getKeySizeBits(), 256, keyClient.toString());
		testSignatureAfterKeyExchange(keyClient, keyServer);
	}
	@Test(invocationCount = 5, dataProvider = "provideDataForKeyAgreementsEncryption", dependsOnMethods = "testMessageDigest")
	public void testKeyAgreementsForEncryption(KeyAgreementType keyAgreementType, SymmetricEncryptionType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);
		
		KeyAgreement client=keyAgreementType.getKeyAgreementClient(random, type, (short)256, keyingMaterial);
		KeyAgreement server=keyAgreementType.getKeyAgreementServer(random, type, (short)256, keyingMaterial);
		testKeyAgreementsForEncryption(client, server, type);
	}
	@Test(invocationCount = 5, dataProvider = "provideDataForHybridKeyAgreementsEncryption", dependsOnMethods = "testMessageDigest")
	public void testHybridKeyAgreementsForEncryption(HybridKeyAgreementType keyAgreementType, SymmetricEncryptionType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);

		KeyAgreement client=keyAgreementType.getKeyAgreementClient(random, type, (short)256, keyingMaterial);
		KeyAgreement server=keyAgreementType.getKeyAgreementServer(random, type, (short)256, keyingMaterial);
		testKeyAgreementsForEncryption(client, server, type);
	}

	public void testKeyAgreementsForEncryption(KeyAgreement client, KeyAgreement server, SymmetricEncryptionType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);

		do
		{
			if (!client.hasFinishedSend())
			{
				byte[] clientData=client.getDataToSend();

				server.receiveData(clientData);

			}
			if (!server.hasFinishedSend())
			{
				byte[] serverData=server.getDataToSend();

				client.receiveData(serverData);

			}
		} while(!server.hasFinishedReception() || !server.hasFinishedSend() || !client.hasFinishedReception() || !client.hasFinishedSend() );

		Assert.assertTrue(client.isAgreementProcessValid());
		Assert.assertTrue(server.isAgreementProcessValid());

		SymmetricSecretKey keyClient=client.getDerivedKey();
		SymmetricSecretKey keyServer=server.getDerivedKey();


		Assert.assertEquals(keyClient,keyServer);
		Assert.assertEquals(keyClient.getKeySizeBits(), 256);
		testEncryptionAfterKeyExchange(random, type, keyClient);
	}
	private void testSignatureAfterKeyExchange(SymmetricSecretKey keySigner, SymmetricSecretKey keyChecker) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, SignatureException, InvalidKeySpecException, IllegalStateException, InvalidAlgorithmParameterException, IOException, InvalidParameterSpecException
	{
		SymmetricAuthenticatedSignatureCheckerAlgorithm checker=new SymmetricAuthenticatedSignatureCheckerAlgorithm(keyChecker);
		SymmetricAuthenticatedSignerAlgorithm signer=new SymmetricAuthenticatedSignerAlgorithm(keySigner);

		for (byte[] m : messagesToEncrypt) {
			byte[] signature=signer.sign(m);
			Assert.assertTrue(checker.verify(m, signature));
			for (int i=0;i<signature.length;i++)
				signature[i]=(byte)~signature[i];
			Assert.assertFalse(checker.verify(m, signature));
		}
	}
	
	
	
	@DataProvider(name = "provideDataForKeyAgreementsEncryption", parallel = true)
	public Object[][] provideDataForKeyAgreementsEncryption() {
		ArrayList<Object[]> l=new ArrayList<>();
		
		
		for (KeyAgreementType type : KeyAgreementType.values()) {
			for (SymmetricEncryptionType etype : SymmetricEncryptionType.values())
			{
				if (etype.isPostQuantumAlgorithm((short)256) && etype.getCodeProviderForEncryption()!=CodeProvider.GNU_CRYPTO)
				{
					Object[] o = new Object[2];
					o[0]=type;
					o[1]=etype;
					l.add(o);
				}
			}
		}
		Object[][] res = new Object[l.size()][];
		int index=0;
		for (Object[] o : l)
			res[index++]=o;
		return res;
	}
	@DataProvider(name = "provideDataForHybridKeyAgreementsEncryption", parallel = true)
	public Object[][] provideDataForHybridKeyAgreementsEncryption() {
		ArrayList<Object[]> l=new ArrayList<>();


		for (KeyAgreementType type : KeyAgreementType.values()) {
			if (type.isPostQuantumAlgorithm())
				continue;
			for (KeyAgreementType type2 : KeyAgreementType.values()) {
				if (!type2.isPostQuantumAlgorithm())
					continue;
				Object[] o = new Object[2];
				o[0]=new HybridKeyAgreementType(type, type2);
				o[1]=SymmetricEncryptionType.AES_CBC_PKCS5Padding;
				l.add(o);

			}
		}
		Object[][] res = new Object[l.size()][];
		int index=0;
		for (Object[] o : l)
			res[index++]=o;
		return res;
	}
	@DataProvider(name = "provideDataForKeyAgreementsSignature", parallel = true)
	public Object[][] provideDataForKeyAgreementsSignature() {
		ArrayList<Object[]> l=new ArrayList<>();
		
		
		for (KeyAgreementType type : KeyAgreementType.values()) {
			for (SymmetricAuthentifiedSignatureType etype : SymmetricAuthentifiedSignatureType.values())
			{
				if (!type.isPostQuantumAlgorithm() || etype.isPostQuantumAlgorithm((short)256))
				{
					Object[] o = new Object[2];
					o[0]=type;
					o[1]=etype;
					l.add(o);
				}
			}
		}
		Object[][] res = new Object[l.size()][];
		int index=0;
		for (Object[] o : l)
			res[index++]=o;
		return res;
	}

	@DataProvider(name = "provideDataForHybridKeyAgreementsSignature", parallel = true)
	public Object[][] provideDataForHybridKeyAgreementsSignature() {
		ArrayList<Object[]> l=new ArrayList<>();


		for (KeyAgreementType type : KeyAgreementType.values()) {
			if (type.isPostQuantumAlgorithm())
				continue;
			for (KeyAgreementType type2 : KeyAgreementType.values()) {
				if (!type2.isPostQuantumAlgorithm())
					continue;

				Object[] o = new Object[2];
				o[0]=new HybridKeyAgreementType(type, type2);
				o[1]=SymmetricAuthentifiedSignatureType.HMAC_SHA2_256;
				l.add(o);
			}
		}
		Object[][] res = new Object[l.size()][];
		int index=0;
		for (Object[] o : l)
			res[index++]=o;
		return res;
	}

	@Test(dataProvider = "provideDataForSymetricEncryptions")
	public void testBase64(SymmetricEncryptionType encryptionType) throws NoSuchProviderException, NoSuchAlgorithmException {

		SymmetricSecretKey key1=encryptionType.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), encryptionType.getDefaultKeySizeBits()).generateKey();

		Assert.assertEquals(key1.getKeySizeBits(), encryptionType.getDefaultKeySizeBits());
		System.out.println("Key encryption : \n\t"+ Base64.encodeBase64URLSafeString(key1.getKeyBytes()));
		System.out.println("Key encryption (complete): \n\t"+ Base64.encodeBase64URLSafeString(key1.encode()));
		Assert.assertEquals(key1.getKeyBytes().length, encryptionType.getDefaultKeySizeBytes());
	}

    @Test(dataProvider = "symmetricSignatures")
    public void testBase64(SymmetricAuthentifiedSignatureType signatureType) throws NoSuchProviderException, NoSuchAlgorithmException {

        SymmetricSecretKey key1=signatureType.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), signatureType.getDefaultKeySizeBits()).generateKey();

        Assert.assertEquals(key1.getKeySizeBits(), signatureType.getDefaultKeySizeBits());
        System.out.println("Key encryption : \n\t"+ Base64.encodeBase64URLSafeString(key1.getKeyBytes()));
        System.out.println("Key encryption (complete): \n\t"+ Base64.encodeBase64URLSafeString(key1.encode()));
        Assert.assertEquals(key1.getKeyBytes().length, signatureType.getDefaultKeySizeBytes());
    }
}
