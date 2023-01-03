package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.7.0
 */
public class KeyAgreementsTests {


	@Test(invocationCount = 5, dataProvider = "provideDataForKeyAgreementsSignature")
	public void testKeyAgreementsForSignature(KeyAgreementType keyAgreementType, SymmetricAuthenticatedSignatureType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);

		ISimpleKeyAgreement client=keyAgreementType.getKeyAgreementClient(random, type, (short)256, keyingMaterial);
		ISimpleKeyAgreement server=keyAgreementType.getKeyAgreementServer(random, type, (short)256, keyingMaterial);

		testKeyAgreementsForSignature(client, server, type);
	}
	public void testKeyAgreementsForSignature(ISimpleKeyAgreement client, ISimpleKeyAgreement server, SymmetricAuthenticatedSignatureType type)
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

		if (client instanceof AbstractHybridKeyAgreement)
		{
			AbstractHybridKeyAgreement<?> ka=(AbstractHybridKeyAgreement<?>)client;
			Assert.assertTrue(ka.getPQCKeyAgreement().isAgreementProcessValidImpl());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().isAgreementProcessValidImpl());
			Assert.assertTrue(ka.getPQCKeyAgreement().hasFinishedSend());
			Assert.assertTrue(ka.getPQCKeyAgreement().hasFinishedReception());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().hasFinishedSend());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().hasFinishedReception());
			Assert.assertTrue(ka.getPQCKeyAgreement().isAgreementProcessValid());
			Assert.assertTrue(ka.getNonPQCKeyAgreement().isAgreementProcessValid());
		}
		if (server instanceof AbstractHybridKeyAgreement)
		{
			AbstractHybridKeyAgreement<?> ka=(AbstractHybridKeyAgreement<?>)server;
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



		SymmetricSecretKey keyClient=client.getDerivedSecretKey();
		SymmetricSecretKey keyServer=server.getDerivedSecretKey();


		Assert.assertEquals(keyClient,keyServer);
		Assert.assertEquals(keyClient.getKeySizeBits(), 256, keyClient.toString());
		testSignatureAfterKeyExchange(keyClient, keyServer);
	}
	@Test(invocationCount = 5, dataProvider = "provideDataForKeyAgreementsEncryption")
	public void testKeyAgreementsForEncryption(KeyAgreementType keyAgreementType, SymmetricEncryptionType type)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);

		ISimpleKeyAgreement client=keyAgreementType.getKeyAgreementClient(random, type, (short)256, keyingMaterial);
		ISimpleKeyAgreement server=keyAgreementType.getKeyAgreementServer(random, type, (short)256, keyingMaterial);
		testKeyAgreementsForEncryption(client, server, type);
	}
	@Test(invocationCount = 5, dataProvider = "provideDataForKeyAgreementsEncryptionAndSignature")
	public void testKeyAgreementsForEncryptionAndSignature(KeyAgreementType keyAgreementType, SymmetricAuthenticatedSignatureType symmetricAuthenticatedSignatureType, SymmetricEncryptionType symmetricEncryptionType)
			throws Exception {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);

		IDualKeyAgreement client=keyAgreementType.getDualKeyAgreementClient(random, symmetricAuthenticatedSignatureType, symmetricEncryptionType, (short)256, keyingMaterial);
		IDualKeyAgreement server=keyAgreementType.getDualKeyAgreementServer(random, symmetricAuthenticatedSignatureType, symmetricEncryptionType, (short)256, keyingMaterial);

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

		SymmetricSecretKeyPair keyClient=client.getDerivedSecretKeyPair();
		SymmetricSecretKeyPair keyServer=server.getDerivedSecretKeyPair();


		Assert.assertEquals(keyClient,keyServer);
		Assert.assertEquals(keyClient.getSecretKeyForEncryption().getKeySizeBits(), 256);
		Assert.assertEquals(keyClient.getSecretKeyForSignature().getKeySizeBits(), 256);
		testEncryptionAfterKeyExchange(random, keyClient.getSecretKeyForEncryption().getEncryptionAlgorithmType(), keyClient.getSecretKeyForEncryption());
		testSignatureAfterKeyExchange(keyClient.getSecretKeyForSignature(), keyServer.getSecretKeyForSignature());
	}


	public void testKeyAgreementsForEncryption(ISimpleKeyAgreement client, ISimpleKeyAgreement server, SymmetricEncryptionType type)
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

		SymmetricSecretKey keyClient=client.getDerivedSecretKey();
		SymmetricSecretKey keyServer=server.getDerivedSecretKey();


		Assert.assertEquals(keyClient,keyServer);
		Assert.assertEquals(keyClient.getKeySizeBits(), 256);
		testEncryptionAfterKeyExchange(random, type, keyClient);
	}

	private void testSignatureAfterKeyExchange(SymmetricSecretKey keySigner, SymmetricSecretKey keyChecker) throws NoSuchAlgorithmException, NoSuchProviderException, IllegalStateException, IOException {
		SymmetricAuthenticatedSignatureCheckerAlgorithm checker=new SymmetricAuthenticatedSignatureCheckerAlgorithm(keyChecker);
		SymmetricAuthenticatedSignerAlgorithm signer=new SymmetricAuthenticatedSignerAlgorithm(keySigner);

		for (byte[] m : VariousTests.messagesToEncrypt) {
			byte[] signature=signer.sign(m);
			Assert.assertTrue(checker.verify(m, signature));
			for (int i=0;i<signature.length;i++)
				signature[i]=(byte)~signature[i];
			Assert.assertFalse(checker.verify(m, signature));
		}
	}

	@DataProvider(name = "provideDataForKeyAgreementsEncryptionAndSignature", parallel = true)
	public Object[][] provideDataForKeyAgreementsEncryptionAndSignature() {
		ArrayList<Object[]> l=new ArrayList<>();


		for (KeyAgreementType type : KeyAgreementType.values()) {
			for (SymmetricAuthenticatedSignatureType etype : SymmetricAuthenticatedSignatureType.values())
			{
				if (!type.isPostQuantumAlgorithm() || etype.isPostQuantumAlgorithm((short)256))
				{
					for (SymmetricEncryptionType setype : SymmetricEncryptionType.values())
					{
						if (setype.isPostQuantumAlgorithm((short)256) && setype.getCodeProviderForEncryption()!=CodeProvider.GNU_CRYPTO)
						{
							Object[] o = new Object[3];
							o[0]=type;
							o[1]=etype;
							o[2]=setype;
							l.add(o);
						}
					}
				}
			}

		}
		Object[][] res = new Object[l.size()][];
		int index=0;
		for (Object[] o : l)
			res[index++]=o;
		return res;
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
		return l.toArray(new Object[0][]);
	}

	@DataProvider(name = "provideDataForKeyAgreementsSignature", parallel = true)
	public Object[][] provideDataForKeyAgreementsSignature() {
		ArrayList<Object[]> l=new ArrayList<>();


		for (KeyAgreementType type : KeyAgreementType.values()) {
			for (SymmetricAuthenticatedSignatureType etype : SymmetricAuthenticatedSignatureType.values())
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



	private void testEncryptionAfterKeyExchange(AbstractSecureRandom random, SymmetricEncryptionType type, SymmetricSecretKey key) throws IllegalStateException, IOException {
		SymmetricEncryptionAlgorithm algoDistant = new SymmetricEncryptionAlgorithm(random, key);
		SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(random, key);

		Random rand = new Random(System.currentTimeMillis());

		for (byte[] m : VariousTests.messagesToEncrypt) {
			byte[] encrypted = algoLocal.encode(m);
			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeAfterEncryption(m.length), "length=" + m.length);

			Assert.assertTrue(encrypted.length >= m.length);
			byte[] decrypted = algoDistant.decode(encrypted);
			Assert.assertEquals(decrypted.length, m.length, "Testing size " + type);
			Assert.assertEquals(decrypted, m, "Testing " + type);
			byte[] md = decrypted;
			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);
			encrypted = algoDistant.encode(m);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeAfterEncryption(m.length));
			Assert.assertTrue(encrypted.length >= m.length);
			md = algoLocal.decode(encrypted);
			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encrypted = algoLocal.encode(m, off, size);

			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeAfterEncryption(size));
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
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeAfterEncryption(size));
			Assert.assertTrue(encrypted.length >= size);

			md = algoLocal.decode(encrypted);
			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

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

	@Test(dataProvider = "provideDataForP2PJPAKEPasswordExchanger")
	public void testP2PJPAKEPasswordExchanger(boolean expectedVerify, byte[] salt, boolean messageIsKey)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
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


	@DataProvider(name = "provideDataForP2PLoginAgreement", parallel = true)
	public Object[][] provideDataForP2PLoginAgreement() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		byte[] salt = new byte[] { (byte) 21, (byte) 5645, (byte) 512, (byte) 42310, (byte) 24, (byte) 0, (byte) 1,
				(byte) 1231, (byte) 34 };

		ArrayList<Object[]> res = new ArrayList<>();
		SymmetricSecretKey secretKey= SymmetricAuthenticatedSignatureType.BC_FIPS_HMAC_SHA2_384.getKeyGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKey();
		ASymmetricKeyPair keyPair= ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getKeyPairGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKeyPair();
		ASymmetricKeyPair distantKeyPair= ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getKeyPairGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKeyPair();
		for (byte[] m : VariousTests.messagesToEncrypt) {
			for (boolean expectedVerify : new boolean[] { true, false }) {
				for (byte[] s : new byte[][] { null, salt }) {
					for (boolean messageIsKey : new boolean[] { true, false }) {
						for (P2PLoginAgreementType t : P2PLoginAgreementType.values())
						{
							res.add(new Object[] { t, null, expectedVerify, messageIsKey, s, m , secretKey, keyPair, distantKeyPair});
							if (t==P2PLoginAgreementType.JPAKE_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE || t==P2PLoginAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE)
								res.add(new Object[] { t, null, expectedVerify, messageIsKey, s, m , secretKey, null, null});
						}
						for (UnidirectionalASymmetricLoginAgreementType t : UnidirectionalASymmetricLoginAgreementType.values())
						{
							res.add(new Object[] { null, t, expectedVerify, messageIsKey, s, m , null, keyPair, distantKeyPair});
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

	@Test(dataProvider = "provideDataForP2PLoginAgreement")
	public void testP2PLoginAgreement(P2PLoginAgreementType type, UnidirectionalASymmetricLoginAgreementType asType, boolean expectedVerify, boolean messageIsKey, byte[] salt, byte[] m, SymmetricSecretKey secretKey, ASymmetricKeyPair keyPair, ASymmetricKeyPair distantKeyPair)
			throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		System.out.println(type+";"+asType);
		AbstractSecureRandom r = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] falseMessage = new byte[10];
		r.nextBytes(falseMessage);
		SymmetricSecretKey falseSecretKey=secretKey==null?null:secretKey.getAuthenticatedSignatureAlgorithmType().getKeyGenerator(r).generateKey();
		Agreement exchanger1;
		Agreement exchanger2;
		if (asType!=null)
		{
			exchanger1=asType.getAgreementAlgorithmForASymmetricSignatureRequester(r, keyPair);
			exchanger2=asType.getAgreementAlgorithmForASymmetricSignatureReceiver(r, keyPair.getASymmetricPublicKey());

		}
		else {
			exchanger1 = type.getAgreementAlgorithm(r, "participant id 1".getBytes(), m, 0,
					m.length, messageIsKey, salt, 0, salt == null ? 0 : salt.length, (expectedVerify ? secretKey : falseSecretKey), keyPair==null?null:keyPair.getASymmetricPrivateKey(), distantKeyPair==null?null:distantKeyPair.getASymmetricPublicKey());
			exchanger2 = type.getAgreementAlgorithm(r, "participant id 2".getBytes(),
					expectedVerify ? m : falseMessage, 0, (expectedVerify ? m : falseMessage).length, messageIsKey, salt, 0,
					salt == null ? 0 : salt.length, (expectedVerify ? secretKey : falseSecretKey), distantKeyPair==null?null:distantKeyPair.getASymmetricPrivateKey(), keyPair==null?null:keyPair.getASymmetricPublicKey());
		}
		try {
			int send1=0, received1=0;
			int send2=0, received2=0;
			while (!exchanger1.hasFinishedSend())
			{
				byte[] step1 = exchanger1.hasFinishedSend()?null:exchanger1.getDataToSend();
				byte[] step2 = exchanger2.hasFinishedSend()?null:exchanger2.getDataToSend();
				if (step1!=null)
					send1++;
				if (step2!=null)
					send2++;
				if (!expectedVerify)
				{
					if (step1!=null) {
						for (int i = 0; i < step1.length; i++)
							step1[i] = (byte) ~step1[i];
					}
					if (step2!=null) {
						for (int i = 0; i < step2.length; i++)
							step2[i] = (byte) ~step2[i];
					}
				}
				Assert.assertEquals(exchanger1.isAgreementProcessValid(), exchanger1.hasFinishedReception() && exchanger1.hasFinishedSend());
				Assert.assertEquals(exchanger2.isAgreementProcessValid(), exchanger2.hasFinishedReception() && exchanger2.hasFinishedSend());
				Assert.assertEquals(exchanger1.hasFinishedReception(), received1==exchanger1.getStepsNumberForReception());
				Assert.assertEquals(exchanger2.hasFinishedReception(), received2==exchanger2.getStepsNumberForReception());
				Assert.assertEquals(exchanger1.hasFinishedSend(), send1==exchanger1.getStepsNumberForSend(), ""+send1+";"+exchanger1.getStepsNumberForSend()+";"+exchanger1.getActualStepForSendIndex());
				Assert.assertEquals(exchanger2.hasFinishedSend(), send2==exchanger2.getStepsNumberForSend(), ""+send2+";"+exchanger2.getStepsNumberForSend()+";"+exchanger2.getActualStepForSendIndex());
				if (step2!=null) {
					received1++;
					exchanger1.receiveData(step2);
				}
				if (step1!=null) {
					received2++;
					exchanger2.receiveData(step1);
				}

				if (exchanger1.hasFinishedReception() && exchanger1.hasFinishedSend())
				{
					Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify || asType!=null, ""+exchanger1.getClass());
					Assert.assertEquals(exchanger2.isAgreementProcessValid(), expectedVerify, ""+exchanger2.getClass());
				}
				else
				{
					Assert.assertEquals(exchanger1.hasFinishedReception(), received1==exchanger1.getStepsNumberForReception(), ""+received1+" ; "+exchanger1.getStepsNumberForReception());
					Assert.assertEquals(exchanger2.hasFinishedReception(), received2==exchanger2.getStepsNumberForReception());
					Assert.assertEquals(exchanger1.hasFinishedSend(), send1==exchanger1.getStepsNumberForSend());
					Assert.assertEquals(exchanger2.hasFinishedSend(), send2==exchanger2.getStepsNumberForSend());
				}
			}
			Assert.assertEquals(send1, received2);
			Assert.assertEquals(send2, received1);
			Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify || asType!=null);
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
}
