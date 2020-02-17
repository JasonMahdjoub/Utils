package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import com.distrimind.util.DecentralizedValue;
import org.bouncycastle.crypto.InvalidWrappingException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.ArrayList;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.7.0
 */
public class TestASymmetricSignatures {
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
	@SuppressWarnings("deprecation")
	@Test(dataProvider = "provideDataForASymmetricSignatureTest")
	public void testAsymmetricSignatures(ASymmetricAuthenticatedSignatureType type, ASymmetricAuthenticatedSignatureType typePQC, AbstractKeyPair kpd, int keySize)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException,
			NoSuchProviderException, IllegalStateException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException {
		System.out.println("Testing asymmetric signature : " +type+", "+ keySize+", "+kpd.getASymmetricPublicKey().getKeyBytes().length);
		byte[] b = kpd.encode(true);
		AbstractKeyPair kpd2=(AbstractKeyPair) DecentralizedValue.decode(b);
		Assert.assertEquals(kpd2, kpd);
		ASymmetricAuthenticatedSignerAlgorithm signer = new ASymmetricAuthenticatedSignerAlgorithm(kpd.getASymmetricPrivateKey());
		ASymmetricAuthenticatedSignatureCheckerAlgorithm checker = new ASymmetricAuthenticatedSignatureCheckerAlgorithm(kpd.getASymmetricPublicKey());
		byte[] signature=VariousTests.testSignature(signer, checker);
		if (type==null) {
			ASymmetricKeyPair kpd3=(ASymmetricKeyPair)kpd;
			if (kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521
					/*&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_25519
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_SHA384withECDSA_CURVE_25519
					&& kpd3.getAuthenticatedSignatureAlgorithmType() != ASymmetricAuthenticatedSignatureType.BC_SHA512withECDSA_CURVE_25519
				&& kpd.getAuthenticatedSignatureAlgorithmType()!=ASymmetricAuthenticatedSignatureType.BC_SHA256withECDSA_CURVE_M_511
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



	@Test(dataProvider = "provideDataForASymetricSignatures")
	public void testASymmetricKeyPairEncodingForSignature(ASymmetricAuthenticatedSignatureType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);

		ASymmetricKeyPair kpd=generateKeyPair(type);

		byte[] b = kpd.encode(false);
		Assert.assertEquals(b.length, kpd.encode(true).length-8);


		ASymmetricKeyPair kpd2=(ASymmetricKeyPair)DecentralizedValue.decode(b);
		testASymmetricKeyPairEqualityForSignature(kpd, kpd2);
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);
		testASymmetricKeyPairEqualityForSignature(kpd, (ASymmetricKeyPair)DecentralizedValue.valueOf(kpd.encodeString()));



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
		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPublicKey().encodeString()), kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPrivateKey().encodeString()), kpd.getASymmetricPrivateKey());
		System.out.println(type+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPublic key encoding length : "+kpd.getASymmetricPublicKey().toString().length());
		System.out.println("\tJava naviteve public key encoding length : "+kpd.getASymmetricPublicKey().toJavaNativeKey().getEncoded().length);
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());

	}
	@Test(dataProvider = "provideDataForASymetricSignatures")
	public void testASymmetricKeyExpirationTimeChange(ASymmetricAuthenticatedSignatureType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		testASymmetricKeyExpirationTimeChange(generateKeyPair(type));
	}
	private void testASymmetricKeyPairEqualityForSignature(ASymmetricKeyPair kpd, ASymmetricKeyPair kpd2)
	{
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getKeySizeBits(), kpd.getASymmetricPrivateKey().getKeySizeBits());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getBytesPublicKey(), kpd.getASymmetricPublicKey().getBytesPublicKey());
		Assert.assertEquals(kpd2.getEncryptionAlgorithmType(), kpd.getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getAuthenticatedSignatureAlgorithmType(), kpd.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getEncryptionAlgorithmType());

	}

	private ASymmetricKeyPair generateKeyPair(ASymmetricAuthenticatedSignatureType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);

		boolean isECDSA=type== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withECDSA_P_384
				|| 	type== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withECDSA_P_256
				|| type== ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withECDSA_P_521;

		return type.getKeyPairGenerator(rand, isECDSA?type.getDefaultKeySize():(short)1024).generateKeyPair();
	}

	static void testASymmetricKeyExpirationTimeChange(ASymmetricKeyPair keyPair)
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
				for (int keySize : VariousTests.keySizes) {
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
				o[2] = st.getKeyPairGenerator(rand, VariousTests.keySizes[0]).generateKeyPair();
				o[3] = VariousTests.keySizes[0];
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

	@Test(dataProvider = "provideDataForHybridASymetricSignatures")
	public void testHybridASymmetricKeyPairEncodingForEncryption(ASymmetricAuthenticatedSignatureType nonPQCType, ASymmetricAuthenticatedSignatureType PQCType)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		System.out.println("Testing HybridASymmetricKeyPairEncoding " + nonPQCType+" ; "+PQCType);

		ASymmetricKeyPair nonPQC=generateKeyPair(nonPQCType);
		ASymmetricKeyPair PQC=generateKeyPair(PQCType);
		HybridASymmetricKeyPair kpd=new HybridASymmetricKeyPair(nonPQC, PQC);

		byte[] b = kpd.encode(false);
		HybridASymmetricKeyPair kpd2=(HybridASymmetricKeyPair) DecentralizedValue.decode(b);
		testHybridASymmetricKeyPairEqualityForEncryption(kpd, kpd2);
		testHybridASymmetricKeyPairEqualityForEncryption(kpd, (HybridASymmetricKeyPair)DecentralizedValue.valueOf(kpd.encodeString()));
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);

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

		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPublicKey().encodeString()), kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPrivateKey().encodeString()), kpd.getASymmetricPrivateKey());

		System.out.println(nonPQCType+"; "+PQCType+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());

	}
	private void testHybridASymmetricKeyPairEqualityForEncryption(HybridASymmetricKeyPair kpd, HybridASymmetricKeyPair kpd2)
	{
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey(), kpd.getASymmetricPublicKey());
		Assert.assertEquals(kpd2.getPQCKeyPair().getEncryptionAlgorithmType(), kpd.getPQCKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getPQCKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getPQCKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCKeyPair().getEncryptionAlgorithmType(), kpd.getNonPQCKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getNonPQCKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType());

		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType());

	}

	@DataProvider(name = "provideDataForHybridASymmetricSignature", parallel = true)
	public Object[][] provideDataForHybridASymmetricSignature() {
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
	@Test(dataProvider = "provideDataForHybridASymmetricSignature")
	public void testHybridASymmetricKeyPairEncodingForSignature(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException {
		System.out.println("Testing HybridASymmetricKeyPairEncoding " + type);

		HybridASymmetricKeyPair kpd=type.generateKeyPair(SecureRandomType.DEFAULT.getSingleton(null), 1024 );

		byte[] b = kpd.encode(false);
		HybridASymmetricKeyPair kpd2=(HybridASymmetricKeyPair) DecentralizedValue.decode(b);
		testHybridASymmetricKeyPairEqualityForSignatureHybridASymmetricKeyPair(kpd, kpd2);
		testHybridASymmetricKeyPairEqualityForSignatureHybridASymmetricKeyPair(kpd, (HybridASymmetricKeyPair)DecentralizedValue.valueOf(kpd.encodeString()));
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);

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

		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPublicKey().encodeString()), kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPrivateKey().encodeString()), kpd.getASymmetricPrivateKey());

		System.out.println(type+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());

	}

	private void testHybridASymmetricKeyPairEqualityForSignatureHybridASymmetricKeyPair(HybridASymmetricKeyPair kpd, HybridASymmetricKeyPair kpd2)
	{
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey(), kpd.getASymmetricPublicKey());
		Assert.assertEquals(kpd2.getPQCKeyPair().getEncryptionAlgorithmType(), kpd.getPQCKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getPQCKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getPQCKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCKeyPair().getEncryptionAlgorithmType(), kpd.getNonPQCKeyPair().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getNonPQCKeyPair().getAuthenticatedSignatureAlgorithmType(), kpd.getNonPQCKeyPair().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getNonPQCPublicKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getPQCPublicKey().getEncryptionAlgorithmType());

		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getNonPQCPrivateKey().getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getPQCPrivateKey().getEncryptionAlgorithmType());


	}

}
