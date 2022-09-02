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
import com.distrimind.util.data_buffers.WrappedData;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.7.0
 */
public class TestASymmetricEncryption {
	@DataProvider(name="provideDataKeyWrapperForSymmetricSecretKey", parallel=true)
	public Object[][] provideDataKeyWrapperForSymmetricSecretKey()
	{
		Object [][] res=new Object[ASymmetricKeyWrapperType.values().length*ASymmetricEncryptionType.values().length*ASymmetricAuthenticatedSignatureType.values().length][];
		int index=0;
		for (ASymmetricKeyWrapperType akpw : ASymmetricKeyWrapperType.values())
		{
			for (ASymmetricEncryptionType aet : ASymmetricEncryptionType.values())
			{
				for (ASymmetricAuthenticatedSignatureType ast : ASymmetricAuthenticatedSignatureType.values()) {

					if ((akpw.isHybrid() && akpw.getNonPQCWrapper().getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getNonPQCWrapper().getCodeProvider().equals(SymmetricEncryptionType.DEFAULT.getCodeProviderForEncryption())) || (!akpw.isHybrid() && akpw.getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getCodeProvider().equals(SymmetricEncryptionType.DEFAULT.getCodeProviderForEncryption()))) {
						Object[] params = new Object[5];
						params[0] = akpw;
						params[1] = aet;
						params[2] = ast;
						params[3] = SymmetricEncryptionType.DEFAULT;
						params[4] = SymmetricAuthenticatedSignatureType.DEFAULT;
						res[index++] = params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
		System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}

	@DataProvider(name="provideDataKeyWrapperForASymmetricKeyForEncryption", parallel=true)
	public Object[][] provideDataKeyWrapperForASymmetricKeyForEncryption()
	{
		Object [][] res=new Object[ASymmetricKeyWrapperType.values().length*ASymmetricEncryptionType.values().length*ASymmetricAuthenticatedSignatureType.values().length][];
		int index=0;
		for (ASymmetricKeyWrapperType akpw : ASymmetricKeyWrapperType.values())
		{
			for (ASymmetricEncryptionType aet : ASymmetricEncryptionType.values())
			{
				for (ASymmetricAuthenticatedSignatureType ast : ASymmetricAuthenticatedSignatureType.values()) {
					if ((akpw.isHybrid() && akpw.getNonPQCWrapper().getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getNonPQCWrapper().getCodeProvider().equals(SymmetricEncryptionType.DEFAULT.getCodeProviderForEncryption())) || (!akpw.isHybrid() && akpw.getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getCodeProvider().equals(SymmetricEncryptionType.DEFAULT.getCodeProviderForEncryption()))) {
						Object[] params = new Object[5];
						params[0] = akpw;
						params[1] = aet;
						params[2] = ast;
						params[3] = aet;
						params[4] = SymmetricAuthenticatedSignatureType.DEFAULT;
						res[index++] = params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
		System.arraycopy(res, 0, res2, 0, index);
		return res2;

	}

	@DataProvider(name="provideDataKeyWrapperForASymmetricKeyForSignature", parallel=true)
	public Object[][] provideDataKeyWrapperForASymmetricKeyForSignature()
	{
		Object [][] res=new Object[ASymmetricKeyWrapperType.values().length*ASymmetricEncryptionType.values().length*ASymmetricAuthenticatedSignatureType.values().length][];
		int index=0;
		for (ASymmetricKeyWrapperType akpw : ASymmetricKeyWrapperType.values())
		{
			for (ASymmetricEncryptionType aet : ASymmetricEncryptionType.values())
			{
				for (ASymmetricAuthenticatedSignatureType set : ASymmetricAuthenticatedSignatureType.values())
				{

					if ((akpw.isHybrid() && akpw.getNonPQCWrapper().getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getNonPQCWrapper().getCodeProvider().equals(SymmetricEncryptionType.DEFAULT.getCodeProviderForEncryption())) || (!akpw.isHybrid() && akpw.getCodeProvider().equals(aet.getCodeProviderForEncryption()) && akpw.getCodeProvider().equals(SymmetricEncryptionType.DEFAULT.getCodeProviderForEncryption()))) {
						Object[] params = new Object[4];
						params[0] = akpw;
						params[1] = aet;
						params[2] = set;
						params[3] = SymmetricAuthenticatedSignatureType.DEFAULT;
						res[index++] = params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
		System.arraycopy(res, 0, res2, 0, index);
		return res2;

	}
	@Test(dataProvider= "provideDataKeyWrapperForSymmetricSecretKey")
	public void testKeyWrapperForSymmetricKey(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, ASymmetricAuthenticatedSignatureType asstype, SymmetricEncryptionType seetype, SymmetricAuthenticatedSignatureType sestype)
			throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException, IllegalArgumentException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpe=asetype.getKeyPairGenerator(rand, (short)2048).generateKeyPair();

		SymmetricSecretKey secretKeyForSignature=sestype.getKeyGenerator(rand).generateKey();
		ASymmetricKeyPair keyPairForSignature=asstype.getKeyPairGenerator(rand).generateKeyPair();
		ASymmetricKeyPair kppqc=null;
		if (typeWrapper.isHybrid())
		{
			if (typeWrapper.getPqcWrapper()==ASymmetricKeyWrapperType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256)
				kppqc= ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getKeyPairGenerator(rand).generateKeyPair();
			else
				kppqc= ASymmetricEncryptionType.BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256.getKeyPairGenerator(rand).generateKeyPair();
		}

		ASymmetricKeyPair keyPairForSignaturePQC=ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA2_512_256.getKeyPairGenerator(rand).generateKeyPair();
		testASymmetricKeyWrapperForEncryption(rand, kpe,kppqc, null, typeWrapper, asetype, seetype, null);
		testASymmetricKeyWrapperForEncryption(rand, kpe,kppqc, null, typeWrapper, asetype, seetype, secretKeyForSignature);
		testASymmetricKeyWrapperForEncryption(rand, kpe,kppqc, keyPairForSignature, typeWrapper, asetype, seetype, null);
		testASymmetricKeyWrapperForEncryption(rand, kpe,kppqc, keyPairForSignature, typeWrapper, asetype, seetype, secretKeyForSignature);
		if (keyPairForSignature.isPostQuantumKey() || kpe.isPostQuantumKey())
			return;
		testASymmetricKeyWrapperForEncryption(rand, kpe,kppqc, new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, seetype, null);
		testASymmetricKeyWrapperForEncryption(rand, kpe,kppqc, new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, seetype, secretKeyForSignature);


		/*testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kpe, kppqc), null, typeWrapper, asetype, seetype, null);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kpe, kppqc), null, typeWrapper, asetype, seetype, secretKeyForSignature);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kpe, kppqc), new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, seetype, null);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kpe, kppqc), new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, seetype, secretKeyForSignature);*/

	}

	@Test(dataProvider="provideDataKeyWrapperForASymmetricKeyForEncryption")
	public void testKeyWrapperForASymmetricKeyForEncryption(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, ASymmetricAuthenticatedSignatureType asstype, ASymmetricEncryptionType asetypeToCode, SymmetricAuthenticatedSignatureType sestype)
			throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException, IllegalArgumentException, InvalidKeySpecException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp=asetype.getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		SymmetricSecretKey secretKeyForSignature=sestype.getKeyGenerator(rand).generateKey();
		ASymmetricKeyPair keyPairForSignature=asstype.getKeyPairGenerator(rand).generateKeyPair();

		testASymmetricKeyWrapperForEncryption(rand, kp, null, typeWrapper, asetype, asetypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, kp, null, typeWrapper, asetype, asetypeToCode, secretKeyForSignature);
		testASymmetricKeyWrapperForEncryption(rand, kp, keyPairForSignature, typeWrapper, asetype, asetypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, kp, keyPairForSignature, typeWrapper, asetype, asetypeToCode, secretKeyForSignature);
		if (keyPairForSignature.isPostQuantumKey() || kp.isPostQuantumKey())
			return;
		ASymmetricKeyPair kppqc= ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getKeyPairGenerator(rand, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getDefaultKeySizeBits(), System.currentTimeMillis(), Long.MAX_VALUE).generateKeyPair();
		ASymmetricKeyPair keyPairForSignaturePQC=ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA2_512_256.getKeyPairGenerator(rand).generateKeyPair();
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), null, typeWrapper, asetype, asetypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), null, typeWrapper, asetype, asetypeToCode, secretKeyForSignature);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, asetypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, asetypeToCode, secretKeyForSignature);

	}
	@Test(dataProvider="provideDataKeyWrapperForASymmetricKeyForSignature")
	public void testKeyWrapperForASymmetricKeyForSignature(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, ASymmetricAuthenticatedSignatureType asstypeToCode, SymmetricAuthenticatedSignatureType sestype)
			throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException, IllegalArgumentException, InvalidKeySpecException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp=asetype.getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		SymmetricSecretKey secretKeyForSignature=sestype.getKeyGenerator(rand).generateKey();
		ASymmetricKeyPair keyPairForSignature=asstypeToCode.getKeyPairGenerator(rand).generateKeyPair();

		testASymmetricKeyWrapperForEncryption(rand, kp, null, typeWrapper, asetype, asstypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, kp, null, typeWrapper, asetype, asstypeToCode, secretKeyForSignature);
		testASymmetricKeyWrapperForEncryption(rand, kp, keyPairForSignature, typeWrapper, asetype, asstypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, kp, keyPairForSignature, typeWrapper, asetype, asstypeToCode, secretKeyForSignature);
		if (keyPairForSignature.isPostQuantumKey() || kp.isPostQuantumKey())
			return;
		ASymmetricKeyPair kppqc= ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getKeyPairGenerator(rand, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256.getDefaultKeySizeBits(), System.currentTimeMillis(), Long.MAX_VALUE).generateKeyPair();
		ASymmetricKeyPair keyPairForSignaturePQC=ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA2_512_256.getKeyPairGenerator(rand).generateKeyPair();
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), null, typeWrapper, asetype, asstypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), null, typeWrapper, asetype, asstypeToCode, secretKeyForSignature);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, asstypeToCode, null);
		testASymmetricKeyWrapperForEncryption(rand, new HybridASymmetricKeyPair(kp, kppqc), new HybridASymmetricKeyPair(keyPairForSignature, keyPairForSignaturePQC), typeWrapper, asetype, asstypeToCode, secretKeyForSignature);
	}

	public void testASymmetricKeyWrapperForEncryption(AbstractSecureRandom rand, ASymmetricKeyPair nonpqckpe, ASymmetricKeyPair pqckpe, AbstractKeyPair<?,?> kps,  ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricEncryptionType setype, SymmetricSecretKey secretKeyForSignature)
			throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException, IllegalArgumentException {
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, setype.getDefaultKeySizeBits()).generateKey();
		AbstractKeyPair<?, ?> kpe;
		if (typeWrapper.isHybrid())
		{
			kpe=new HybridASymmetricKeyPair(nonpqckpe, pqckpe);
		}
		else
			kpe=nonpqckpe;
		KeyWrapperAlgorithm keyWrapper;
		try {
			if (secretKeyForSignature != null) {
				if (kps == null)
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, secretKeyForSignature);
				else
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, kps, secretKeyForSignature);
			} else {
				if (kps == null)
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe);
				else
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, kps);
			}
			Assert.assertTrue(secretKeyForSignature!=null || kps!=null || typeWrapper.wrappingIncludeSignature());
			WrappedEncryptedSymmetricSecretKey wrappedKey=keyWrapper.wrap(rand, sk);
			SymmetricSecretKey sk2=keyWrapper.unwrap(wrappedKey);
			Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
			Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
			Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
			Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
			Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());
		}
		catch (IllegalArgumentException e)
		{
			if (!(secretKeyForSignature==null && kps==null && !typeWrapper.wrappingIncludeSignature()))
			{
				e.printStackTrace();
				Assert.fail();
			}
		}

	}
	public void testASymmetricKeyWrapperForEncryption(AbstractSecureRandom rand, AbstractKeyPair<?,?> kpe, AbstractKeyPair<?,?> kps,  ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, ASymmetricEncryptionType asetypeToCode, SymmetricSecretKey secretKeyForSignature)
			throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException, IllegalArgumentException, InvalidKeySpecException {

		AbstractKeyPair<?, ?> kpToCode= asetypeToCode.getKeyPairGenerator(rand, asetypeToCode.getDefaultKeySizeBits()).generateKeyPair();
		KeyWrapperAlgorithm keyWrapper;
		try {
			if (secretKeyForSignature != null) {
				if (kps == null)
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, secretKeyForSignature);
				else
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, kps, secretKeyForSignature);
			} else {
				if (kps == null)
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe);
				else
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, kps);
			}
			Assert.assertTrue(secretKeyForSignature!=null || kps!=null || typeWrapper.wrappingIncludeSignature());
			WrappedEncryptedASymmetricPrivateKey wrappedKey=keyWrapper.wrap(rand, kpToCode.getASymmetricPrivateKey());
			IASymmetricPrivateKey kp2=keyWrapper.unwrap(wrappedKey);
			WrappedData wd=kpToCode.getASymmetricPrivateKey().encode();
			Assert.assertEquals(wd.getBytes(), kp2.encode().getBytes());
			Assert.assertEquals(kpToCode.getASymmetricPrivateKey().toJavaNativeKey().getEncoded(), kp2.toJavaNativeKey().getEncoded());
		}
		catch (IllegalArgumentException ignored)
		{
			Assert.assertTrue(secretKeyForSignature==null && kps==null && !typeWrapper.wrappingIncludeSignature());
		}

	}
	public void testASymmetricKeyWrapperForEncryption(AbstractSecureRandom rand, AbstractKeyPair<?,?> kpe, AbstractKeyPair<?,?> kps,  ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, ASymmetricAuthenticatedSignatureType asstypeToCode, SymmetricSecretKey secretKeyForSignature)
			throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException, IllegalArgumentException, InvalidKeySpecException {
		AbstractKeyPair<?, ?> kpToCode= asstypeToCode.getKeyPairGenerator(rand).generateKeyPair();
		KeyWrapperAlgorithm keyWrapper;
		try {
			if (secretKeyForSignature != null) {
				if (kps == null)
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, secretKeyForSignature);
				else
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, kps, secretKeyForSignature);
			} else {
				if (kps == null)
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe);
				else
					keyWrapper = new KeyWrapperAlgorithm(typeWrapper, kpe, kps);
			}
			Assert.assertTrue(secretKeyForSignature!=null || kps!=null || typeWrapper.wrappingIncludeSignature());
			WrappedEncryptedASymmetricPrivateKey wrappedKey=keyWrapper.wrap(rand, kpToCode.getASymmetricPrivateKey());
			IASymmetricPrivateKey kp2=keyWrapper.unwrap(wrappedKey);
			Assert.assertEquals(kpToCode.getASymmetricPrivateKey().encode(), kp2.encode());
			Assert.assertEquals(kpToCode.getASymmetricPrivateKey().toJavaNativeKey().getEncoded(), kp2.toJavaNativeKey().getEncoded());
		}
		catch (IllegalArgumentException ignored)
		{
			Assert.assertTrue(secretKeyForSignature==null && kps==null && !typeWrapper.wrappingIncludeSignature());
		}

	}
	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncodingForEncryption" })
	public void testP2PASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kpl = type.getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		P2PASymmetricEncryptionAlgorithm algoDistant = new P2PASymmetricEncryptionAlgorithm(kpd,
				kpl.getASymmetricPublicKey(), FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);
		P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(kpl,
				kpd.getASymmetricPublicKey(), FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);

		testP2PASymetricEncryptionsImpl(rand, type, algoDistant, algoLocal);

	}
	@Test(dataProvider = "provideDataForHybridASymetricEncryptions")
	public void testHybridP2PASymetricEncryptions(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpdnonpqc = type.getNonPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kplnonpqc = type.getNonPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kpdpqc = type.getPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		ASymmetricKeyPair kplpqc = type.getPQCASymmetricEncryptionType().getKeyPairGenerator(rand, (short)2048).generateKeyPair();
		HybridASymmetricKeyPair kpd=new HybridASymmetricKeyPair(kpdnonpqc, kpdpqc);
		HybridASymmetricKeyPair kpl=new HybridASymmetricKeyPair(kplnonpqc, kplpqc);
		P2PASymmetricEncryptionAlgorithm algoDistant = new P2PASymmetricEncryptionAlgorithm(kpd,
				kpl.getASymmetricPublicKey(), FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);
		P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(kpl,
				kpd.getASymmetricPublicKey(), FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);

		testP2PASymetricEncryptionsImpl(rand, type, algoDistant, algoLocal);

	}
	public void testP2PASymetricEncryptionsImpl(AbstractSecureRandom rand, Object type, P2PASymmetricEncryptionAlgorithm algoDistant, P2PASymmetricEncryptionAlgorithm algoLocal)
			throws
			IOException,
			IllegalStateException {


		for (byte[] m : VariousTests.messagesToEncrypt) {
			byte[] encoded = algoLocal.encode(m);
			Assert.assertTrue(encoded.length>0);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeAfterEncryption(m.length));
			byte[] md = algoDistant.decode(encoded);
			Assert.assertEquals(md.length, m.length, "Testing size " + type+", encryptedLength="+encoded.length);
			Assert.assertEquals(md, m, "Testing " + type);

			encoded = algoDistant.encode(m);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeAfterEncryption(m.length));
			md = algoLocal.decode(encoded);

			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);


			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encoded = algoLocal.encode(m, off, size);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeAfterEncryption(size));
			md = algoDistant.decode(encoded);
			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(md[i], m[i + off]);

			encoded = algoDistant.encode(m, off, size);
			if (!type.toString().startsWith("BCPQC_MCELIECE_") && type.getClass()!=HybridASymmetricEncryptionType.class)
				Assert.assertEquals(encoded.length, algoLocal.getOutputSizeAfterEncryption(size));
			md = algoLocal.decode(encoded);

			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(md[i], m[i + off]);


		}

	}

	@Test(dataProvider = "provideDataForHybridEncryptions")
	public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype)
			throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException, IllegalArgumentException {
		System.out.println("Testing " + astype + "/" + stype);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = astype.getKeyPairGenerator(rand, (short)1024).generateKeyPair();

		SymmetricSecretKey localKey = stype.getKeyGenerator(rand).generateKey();
		SymmetricEncryptionAlgorithm algoLocalS = new SymmetricEncryptionAlgorithm(rand, localKey, FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);
		ASymmetricKeyWrapperType kw;
		if (astype.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)
			kw=ASymmetricKeyWrapperType.GNU_RSA_OAEP_SHA2_384;
		else if (astype.name().startsWith("BCPQC_MCELIECE_FUJISAKI"))
			kw=ASymmetricKeyWrapperType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256;
		else if (astype.name().startsWith("BCPQC_MCELIECE_POINTCHEVAL"))
			kw=ASymmetricKeyWrapperType.BCPQC_MCELIECE_POINTCHEVAL_CCA2_SHA256;
		else
			kw=ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP_WITH_SHA3_512;


		WrappedEncryptedSymmetricSecretKey localEncryptedKey = kw.wrapKey(rand, kpd.getASymmetricPublicKey(), localKey);
		SymmetricSecretKey decryptedKey=kw.unwrapKey(kpd.getASymmetricPrivateKey(), localEncryptedKey);
		Assert.assertEquals(localKey.getAuthenticatedSignatureAlgorithmType(), decryptedKey.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(localKey.getEncryptionAlgorithmType(), decryptedKey.getEncryptionAlgorithmType());
		Assert.assertEquals(localKey.getKeySizeBits(), decryptedKey.getKeySizeBits());
		SymmetricEncryptionAlgorithm algoDistantS = new SymmetricEncryptionAlgorithm(rand, decryptedKey, FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);

		for (byte[] m : VariousTests.messagesToEncrypt) {
			byte[] md = algoDistantS.decode(algoLocalS.encode(m));
			Assert.assertEquals(md.length, m.length, "Testing size " + astype + "/" + stype);
			Assert.assertEquals(md, m, "Testing " + astype + "/" + stype);

			md = algoLocalS.decode(algoDistantS.encode(m));
			Assert.assertEquals(md.length, m.length, "Testing size " + astype + "/" + stype);
			Assert.assertEquals(md, m, "Testing " + astype + "/" + stype);
		}

	}
	@Test(dataProvider = "provideDataForHybridASymetricEncryptions")
	public void testClientServerASymetricEncryptions(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpnonpqc = type.getNonPQCASymmetricEncryptionType().getKeyPairGenerator(rand, type.getNonPQCASymmetricEncryptionType().name().startsWith("BCPQC_MCELIECE_")?type.getNonPQCASymmetricEncryptionType().getDefaultKeySizeBits():2048).generateKeyPair();
		ASymmetricKeyPair kppqc = type.getPQCASymmetricEncryptionType().getKeyPairGenerator(rand, type.getPQCASymmetricEncryptionType().getDefaultKeySizeBits()).generateKeyPair();
		testClientServerASymetricEncryptions(new HybridASymmetricKeyPair(kpnonpqc, kppqc));

	}

	public void testClientServerASymetricEncryptions(AbstractKeyPair<?,?> kp)
			throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);

		ClientASymmetricEncryptionAlgorithm algoClient = new ClientASymmetricEncryptionAlgorithm(rand,
				kp.getASymmetricPublicKey(), FalseCPUUsageType.ADDITIONAL_CPU_USAGE_AFTER_THE_BLOCK_ENCRYPTION);
		ServerASymmetricEncryptionAlgorithm algoServer = new ServerASymmetricEncryptionAlgorithm(kp);

		for (byte[] m : VariousTests.messagesToEncrypt) {
			byte[] encodedBytes = algoClient.encode(m);
			Assert.assertTrue(encodedBytes.length>0, ""+m.length);
			if (!kp.isPostQuantumKey())
				Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeAfterEncryption(m.length));
			byte[] decodedBytes = algoServer.decode(encodedBytes);
			Assert.assertEquals(decodedBytes, m);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encodedBytes = algoClient.encode(m, off, size);
			if (!kp.isPostQuantumKey())
				Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeAfterEncryption(size));
			decodedBytes = algoServer.decode(encodedBytes);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(decodedBytes[i], m[i + off]);

		}

	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncodingForEncryption" })
	public void testClientServerASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp = type.getKeyPairGenerator(rand, type.name().startsWith("BCPQC_MCELIECE_")?type.getDefaultKeySizeBits():2048).generateKeyPair();

		testClientServerASymetricEncryptions(kp);

	}
	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricKeyExpirationTimeChange(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		TestASymmetricSignatures.testASymmetricKeyExpirationTimeChange(generateKeyPair(type));
	}
	private ASymmetricKeyPair generateKeyPair(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		return type.getKeyPairGenerator(rand, (short)1024).generateKeyPair();
	}


	private void testASymmetricKeyPairEqualityForEncryption(ASymmetricKeyPair kpd, ASymmetricKeyPair kpd2) throws InvalidKeySpecException, NoSuchAlgorithmException {
		Assert.assertEquals(kpd2.getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().toJavaNativeKey().getEncoded(), kpd.getASymmetricPublicKey().toJavaNativeKey().getEncoded());
		Assert.assertEquals(kpd2.getEncryptionAlgorithmType(), kpd.getEncryptionAlgorithmType());
		Assert.assertEquals(kpd2.getAuthenticatedSignatureAlgorithmType(), kpd.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPublicKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getEncryptionAlgorithmType(), kpd.getASymmetricPublicKey().getEncryptionAlgorithmType());

		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType(), kpd.getASymmetricPrivateKey().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(kpd2.getASymmetricPrivateKey().getEncryptionAlgorithmType(), kpd.getASymmetricPrivateKey().getEncryptionAlgorithmType());

	}
	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricKeyPairEncodingForEncryption(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeySpecException, IOException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);

		ASymmetricKeyPair kpd=generateKeyPair(type);

		WrappedData b = kpd.encode(false);
		ASymmetricKeyPair kpd2=(ASymmetricKeyPair)DecentralizedValue.decode(b);
		testASymmetricKeyPairEqualityForEncryption(kpd, kpd2);
		testASymmetricKeyPairEqualityForEncryption(kpd, (ASymmetricKeyPair)DecentralizedValue.valueOf(kpd.encodeString()));
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);

		b = kpd.getASymmetricPublicKey().encode(false);
		Assert.assertEquals(b.getBytes().length, kpd.getASymmetricPublicKey().encode(true).getBytes().length-16);
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

		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPublicKey().encodeString()), kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPrivateKey().encodeString()), kpd.getASymmetricPrivateKey());

		System.out.println(type+" :");
		System.out.println("\tKey pair encoding : "+ kpd);
		System.out.println("\tPublic key encoding : "+kpd.getASymmetricPublicKey().toString());
		System.out.println("\tPrivate key encoding : "+kpd.getASymmetricPrivateKey().toString());
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

	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricSecretMessageExchanger(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, InvalidKeySpecException,
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
			algoLocal.setDistantPublicKey(algoDistant.encodeMyPublicKey().getBytes());
			algoDistant.setDistantPublicKey(algoLocal.encodeMyPublicKey().getBytes());
			algoLocal.setCost((byte)11);
			algoDistant.setCost((byte)11);

			byte[] falseMessage = new byte[10];
			rand.nextBytes(falseMessage);

			for (byte[] m : VariousTests.messagesToEncrypt) {
				byte[] localCrypt = algoLocal.encode(m, VariousTests.salt, true);
				Assert.assertTrue(localCrypt.length != 0);
				Assert.assertTrue(algoDistant.verifyDistantMessage(m, VariousTests.salt, localCrypt, true));
				Assert.assertFalse(algoDistant.verifyDistantMessage(m, VariousTests.salt, falseMessage, true));
				Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, VariousTests.salt, localCrypt, true));

				byte[] distantCrypt = algoDistant.encode(m, VariousTests.salt, true);
				Assert.assertTrue(distantCrypt.length != 0);
				Assert.assertTrue(algoLocal.verifyDistantMessage(m, VariousTests.salt, distantCrypt, true));
				Assert.assertFalse(algoLocal.verifyDistantMessage(m, VariousTests.salt, falseMessage, true));
				Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, VariousTests.salt, distantCrypt, true));
			}

			for (byte[] m : VariousTests.messagesToEncrypt) {
				byte[] localCrypt = algoLocal.encode(m, VariousTests.salt, false);
				Assert.assertTrue(localCrypt.length != 0);
				Assert.assertTrue(algoDistant.verifyDistantMessage(m, VariousTests.salt, localCrypt, false));
				Assert.assertFalse(algoDistant.verifyDistantMessage(m, VariousTests.salt, falseMessage, false));
				Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, VariousTests.salt, localCrypt, false));

				byte[] distantCrypt = algoDistant.encode(m, VariousTests.salt, false);
				Assert.assertTrue(distantCrypt.length != 0);
				Assert.assertTrue(algoLocal.verifyDistantMessage(m, VariousTests.salt, distantCrypt, false));
				Assert.assertFalse(algoLocal.verifyDistantMessage(m, VariousTests.salt, falseMessage, false));
				Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, VariousTests.salt, distantCrypt, false));
			}
			for (byte[] m : VariousTests.messagesToEncrypt) {
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
			for (byte[] m : VariousTests.messagesToEncrypt) {
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
			byte[] localCrypt = algoLocal.encode(password, VariousTests.salt);
			Assert.assertTrue(localCrypt.length != 0);
			Assert.assertTrue(algoDistant.verifyDistantMessage(password, VariousTests.salt, localCrypt));
			Assert.assertFalse(algoDistant.verifyDistantMessage(password, VariousTests.salt, falseMessage));
			Assert.assertFalse(algoDistant.verifyDistantMessage(falsePassword, VariousTests.salt, localCrypt));

			byte[] distantCrypt = algoDistant.encode(password, VariousTests.salt);
			Assert.assertTrue(distantCrypt.length != 0);
			Assert.assertTrue(algoLocal.verifyDistantMessage(password, VariousTests.salt, distantCrypt));
			Assert.assertFalse(algoLocal.verifyDistantMessage(password, VariousTests.salt, falseMessage));
			Assert.assertFalse(algoLocal.verifyDistantMessage(falsePassword, VariousTests.salt, distantCrypt));

		}
	}

}
