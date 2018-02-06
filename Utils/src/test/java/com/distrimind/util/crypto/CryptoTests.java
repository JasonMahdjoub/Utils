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
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Random;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnu.security.spec.InvalidParameterSpecException;
import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import gnu.vm.jgnux.crypto.ShortBufferException;

import org.bouncycastle.crypto.InvalidWrappingException;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.distrimind.util.Bits;
import com.distrimind.util.crypto.P2PASymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.ASymmetricEncryptionType;
import com.distrimind.util.crypto.ASymmetricKeyPair;
import com.distrimind.util.crypto.ASymmetricPrivateKey;
import com.distrimind.util.crypto.ASymmetricPublicKey;
import com.distrimind.util.crypto.ClientASymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.P2PASymmetricSecretMessageExchanger;
import com.distrimind.util.crypto.PasswordHash;
import com.distrimind.util.crypto.PasswordHashType;
import com.distrimind.util.crypto.ServerASymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.MessageDigestType;
import com.distrimind.util.crypto.ASymmetricAuthentifiedSignatureType;
import com.distrimind.util.crypto.SymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.SymmetricEncryptionType;
import com.distrimind.util.crypto.SymmetricSecretKey;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.6
 * @since Utils 1.4
 */
public class CryptoTests {
	private static final byte[] messagesToEncrypt[];

	private static final byte salt[];
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

	private static int[] keySizes = { 1024, 2048, 3072, 4096 };

	@DataProvider(name = "provideDataForASymetricEncryptions", parallel = true)
	public Object[][] provideDataForASymetricEncryptions() {
		Object[][] res = new Object[ASymmetricEncryptionType.values().length][];
		int i = 0;
		for (ASymmetricEncryptionType v : ASymmetricEncryptionType.values()) {
			Object o[] = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}
	
	@DataProvider(name = "provideDataForASymetricSignatures", parallel = true)
	public Object[][] provideDataForASymetricSignatures() {
		Object[][] res = new Object[ASymmetricAuthentifiedSignatureType.values().length][];
		int i = 0;
		for (ASymmetricAuthentifiedSignatureType v : ASymmetricAuthentifiedSignatureType.values()) {
			Object o[] = new Object[1];
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
					Object o[] = new Object[2];
					o[0] = vAS;
					o[1] = vS;
					res[index++] = o;
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
		return res2;
	}

	@SuppressWarnings("deprecation")
	@DataProvider(name = "provideDataForASymmetricSignatureTest", parallel = true)
	public Object[][] provideDataForASymmetricSignatureTest() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		Object[][] res = new Object[ASymmetricAuthentifiedSignatureType.values().length
				* keySizes.length][];
		int index = 0;
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (ASymmetricAuthentifiedSignatureType st : ASymmetricAuthentifiedSignatureType.values()) {
			if (st.getSignatureAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withECDSA.getSignatureAlgorithmName()))
			{
				Object o[] = new Object[3];
				o[0]=st;
				o[1] = st.getKeyPairGenerator(rand, (short) 384).generateKeyPair();
				o[2] = new Integer(384);
				res[index++] = o;
			}
			else if (st.getSignatureAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA256withECDSA.getSignatureAlgorithmName()))
			{
				Object o[] = new Object[3];
				o[0]=st;
				o[1] = st.getKeyPairGenerator(rand, (short) 256).generateKeyPair();
				o[2] = new Integer(256);
				res[index++] = o;
			}
			else if (st.getSignatureAlgorithmName().equals(ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withECDSA.getSignatureAlgorithmName()))
			{
				Object o[] = new Object[3];
				o[0]=st;
				o[1] = st.getKeyPairGenerator(rand, (short) 512).generateKeyPair();
				o[2] = new Integer(512);
				res[index++] = o;
			}
			else
			{
				for (int keySize : keySizes) {
					Object o[] = new Object[3];
					o[0]=st;					
					o[1] = st.getKeyPairGenerator(rand, (short) keySize).generateKeyPair();
					o[2] = new Integer(keySize);
					res[index++] = o;
				}
			}
		}
		Object[][] res2=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
		return res2;
	}

	@DataProvider(name = "provideDataForSymmetricSignatureTest", parallel = true)
	public Object[][] provideDataForSymmetricSignatureTest() throws NoSuchAlgorithmException, NoSuchProviderException {
		Object[][] res = new Object[SymmetricAuthentifiedSignatureType.values().length][];
		int i = 0;
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (SymmetricAuthentifiedSignatureType ast : SymmetricAuthentifiedSignatureType.values()) {
			Object o[] = new Object[2];
			o[0] = ast;
			
			o[1] = ast.getKeyGenerator(rand, (short)256).generateKey();
			res[i++] = o;
		}
		return res;
	}

	@DataProvider(name = "provideDataForSymetricEncryptions", parallel = true)
	public Object[][] provideDataForSymetricEncryptions() {
		Object[][] res = new Object[SymmetricEncryptionType.values().length][];
		int i = 0;
		for (SymmetricEncryptionType v : SymmetricEncryptionType.values()) {
			Object o[] = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}

	@DataProvider(name = "provideMessageDigestType", parallel = true)
	public Object[][] provideMessageDigestType() {
		Object[][] res = new Object[MessageDigestType.values().length][];
		int i = 0;
		for (MessageDigestType v : MessageDigestType.values()) {
			Object o[] = new Object[1];
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
			Object o[] = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}

	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricKeyPairEncoding(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, (short)1024).generateKeyPair();

		Assert.assertEquals(ASymmetricPublicKey.decode(kpd.getASymmetricPublicKey().encode()),
				kpd.getASymmetricPublicKey());
		Assert.assertEquals(ASymmetricPrivateKey.decode(kpd.getASymmetricPrivateKey().encode()),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()), kpd);
		Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPrivateKey(),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPublicKey(),
				kpd.getASymmetricPublicKey());
	}
	@Test(dataProvider = "provideDataForASymetricSignatures")
	public void testASymmetricKeyPairEncoding(ASymmetricAuthentifiedSignatureType type)
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		
		@SuppressWarnings("deprecation")
		boolean isECDSA=type==ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withECDSA 
				|| 	type==ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA256withECDSA
				|| type==ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withECDSA; 
		
		ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, isECDSA?type.getDefaultKeySize():(short)1024).generateKeyPair();

		Assert.assertEquals(ASymmetricPublicKey.decode(kpd.getASymmetricPublicKey().encode()),
				kpd.getASymmetricPublicKey());
		Assert.assertEquals(ASymmetricPrivateKey.decode(kpd.getASymmetricPrivateKey().encode()),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()), kpd);
		Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPrivateKey(),
				kpd.getASymmetricPrivateKey());
		Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPublicKey(),
				kpd.getASymmetricPublicKey());
	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncoding",
			"testReadWriteDataPackaged" })
	public void testASymmetricSecretMessageExchanger(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalAccessException, InvalidKeySpecException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException {
		System.out.println("Testing ASymmetricSecretMessageExchanger " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (short keySize = 1024; keySize <= 4096; keySize += 1024) {
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

		res[0] = new Object[] { new Boolean(true), salt, new Boolean(true) };
		res[1] = new Object[] { new Boolean(true), salt, new Boolean(false) };
		res[2] = new Object[] { new Boolean(false), salt, new Boolean(false) };
		res[3] = new Object[] { new Boolean(false), salt, new Boolean(true) };
		res[4] = new Object[] { new Boolean(true), null, new Boolean(true) };
		res[5] = new Object[] { new Boolean(true), null, new Boolean(false) };
		res[6] = new Object[] { new Boolean(false), null, new Boolean(false) };
		res[7] = new Object[] { new Boolean(false), null, new Boolean(true) };

		return res;
	}

	@Test(dataProvider = "provideDataForP2PJPAKEPasswordExchanger", dependsOnMethods = { "testMessageDigest",
			"testPasswordHash" })
	public void testP2PJPAKEPasswordExchanger(boolean expectedVerify, byte[] salt, boolean messageIsKey)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException,
			ClassNotFoundException {
		char[] password = "password".toCharArray();
		char[] falsePassword = "falsePassword".toCharArray();
		AbstractSecureRandom random=SecureRandomType.DEFAULT.getSingleton(null);
		P2PJPAKESecretMessageExchanger exchanger1 = new P2PJPAKESecretMessageExchanger(random, "participant id 1", password,
				salt, 0, salt == null ? 0 : salt.length);
		P2PJPAKESecretMessageExchanger exchanger2 = new P2PJPAKESecretMessageExchanger(random, "participant id 2",
				expectedVerify ? password : falsePassword, salt, 0, salt == null ? 0 : salt.length);
		try {

			byte[] step11 = exchanger1.getDataToSend();
			byte[] step21 = exchanger2.getDataToSend();

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			exchanger1.receiveData(step21);
			exchanger2.receiveData(step11);

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());
			
			byte[] step12 = exchanger1.getDataToSend();
			byte[] step22 = exchanger2.getDataToSend();
			
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			exchanger1.receiveData(step22);
			exchanger2.receiveData(step12);

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			byte[] step13 = exchanger1.getDataToSend();
			byte[] step23 = exchanger2.getDataToSend();

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
			
			exchanger1.receiveData(step23);
			exchanger2.receiveData(step13);
			
			Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify);
			Assert.assertEquals(exchanger2.isAgreementProcessValid(), expectedVerify);
			Assert.assertTrue(exchanger1.hasFinishedReceiption());
			Assert.assertTrue(exchanger2.hasFinishedReceiption());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
		} catch (Exception e) {
			if (expectedVerify)
				Assert.fail("Unexpected exception", e);
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
		}
	}

	@DataProvider(name = "provideDataForP2PJPAKESecretMessageExchanger", parallel = true)
	public Object[][] provideDataForP2PJPAKESecretMessageExchanger() {
		byte[] salt = new byte[] { (byte) 21, (byte) 5645, (byte) 512, (byte) 42310, (byte) 24, (byte) 0, (byte) 1,
				(byte) 1231, (byte) 34 };

		ArrayList<Object[]> res = new ArrayList<>();

		for (byte[] m : messagesToEncrypt) {
			for (boolean expectedVerify : new boolean[] { true, false }) {
				for (byte[] s : new byte[][] { null, salt }) {
					for (boolean messageIsKey : new boolean[] { true, false }) {
						res.add(new Object[] { new Boolean(expectedVerify), new Boolean(messageIsKey), s, m });
					}
				}
			}
		}
		Object[][] res2 = new Object[res.size()][];
		for (int i = 0; i < res.size(); i++)
			res2[i] = res.get(i);
		return res2;
	}

	@Test(dataProvider = "provideDataForP2PJPAKESecretMessageExchanger", dependsOnMethods = { "testMessageDigest" })
	public void testP2PJPAKESecretMessageExchanger(boolean expectedVerify, boolean messageIsKey, byte[] salt, byte[] m)
			throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException,
			ClassNotFoundException {
		AbstractSecureRandom r = SecureRandomType.DEFAULT.getSingleton(null);
		byte[] falseMessage = new byte[10];
		r.nextBytes(falseMessage);

		P2PJPAKESecretMessageExchanger exchanger1 = new P2PJPAKESecretMessageExchanger(r, "participant id 1", m, 0,
				m.length, salt, 0, salt == null ? 0 : salt.length, messageIsKey);
		P2PJPAKESecretMessageExchanger exchanger2 = new P2PJPAKESecretMessageExchanger(r, "participant id 2",
				expectedVerify ? m : falseMessage, 0, (expectedVerify ? m : falseMessage).length, salt, 0,
				salt == null ? 0 : salt.length, messageIsKey);
		try {

			byte[] step11 = exchanger1.getDataToSend();
			byte[] step21 = exchanger2.getDataToSend();

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			exchanger1.receiveData(step21);
			exchanger2.receiveData(step11);

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());
			
			byte[] step12 = exchanger1.getDataToSend();
			byte[] step22 = exchanger2.getDataToSend();
			
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			exchanger1.receiveData(step22);
			exchanger2.receiveData(step12);

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertFalse(exchanger1.hasFinishedSend());
			Assert.assertFalse(exchanger2.hasFinishedSend());

			byte[] step13 = exchanger1.getDataToSend();
			byte[] step23 = exchanger2.getDataToSend();

			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
			Assert.assertFalse(exchanger1.hasFinishedReceiption());
			Assert.assertFalse(exchanger2.hasFinishedReceiption());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
			
			exchanger1.receiveData(step23);
			exchanger2.receiveData(step13);
			
			Assert.assertEquals(exchanger1.isAgreementProcessValid(), expectedVerify);
			Assert.assertEquals(exchanger2.isAgreementProcessValid(), expectedVerify);
			Assert.assertTrue(exchanger1.hasFinishedReceiption());
			Assert.assertTrue(exchanger2.hasFinishedReceiption());
			Assert.assertTrue(exchanger1.hasFinishedSend());
			Assert.assertTrue(exchanger2.hasFinishedSend());
		} catch (Exception e) {
			if (expectedVerify)
				Assert.fail("Unexpected exception", e);
			Assert.assertFalse(exchanger1.isAgreementProcessValid());
			Assert.assertFalse(exchanger2.isAgreementProcessValid());
		}
	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncoding" })
	public void testClientServerASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, SignatureException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, ShortBufferException, IllegalStateException, InvalidParameterSpecException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp = type.getKeyPairGenerator(rand, (short) 1024).generateKeyPair();
		
		ClientASymmetricEncryptionAlgorithm algoClient = new ClientASymmetricEncryptionAlgorithm(rand,
				kp.getASymmetricPublicKey());
		ServerASymmetricEncryptionAlgorithm algoServer = new ServerASymmetricEncryptionAlgorithm(kp);

		for (byte m[] : messagesToEncrypt) {
			byte[] encodedBytes = algoClient.encode(m);
			Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeForEncryption(m.length));
			byte[] decodedBytes = algoServer.decode(encodedBytes);
			Assert.assertEquals(m, decodedBytes);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encodedBytes = algoClient.encode(m, off, size);
			Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeForEncryption(size));
			decodedBytes = algoServer.decode(encodedBytes);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(decodedBytes[i], m[i + off]);

		}

	}

	@Test(invocationCount = 20)
	public void testEncodeAndSeparateEncoding() {
		Random rand = new Random(System.currentTimeMillis());
		byte[] t1 = new byte[rand.nextInt(100) + 20];
		byte[] t2 = new byte[rand.nextInt(100) + 20];
		byte[] encoded = Bits.concateEncodingWithShortSizedTabs(t1, t2);
		byte[][] decoded = Bits.separateEncodingsWithShortSizedTabs(encoded);
		Assert.assertEquals(t1, decoded[0]);
		Assert.assertEquals(t2, decoded[1]);
		encoded = Bits.concateEncodingWithIntSizedTabs(t1, t2);
		decoded = Bits.separateEncodingsWithIntSizedTabs(encoded);
		Assert.assertEquals(t1, decoded[0]);
		Assert.assertEquals(t2, decoded[1]);
	}

	@Test(dataProvider = "provideDataForHybridEncryptions", dependsOnMethods = { "testSymetricEncryptions","testP2PASymetricEncryptions" })
	public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException,
			NoSuchProviderException, InvalidKeySpecException, IllegalStateException, IllegalArgumentException, InvalidWrappingException {
		System.out.println("Testing " + astype + "/" + stype);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = astype.getKeyPairGenerator(rand, (short)1024).generateKeyPair();

		SymmetricSecretKey localKey = stype.getKeyGenerator(rand).generateKey();
		SymmetricEncryptionAlgorithm algoLocalS = new SymmetricEncryptionAlgorithm(rand, localKey);
		ASymmetricKeyWrapperType kw=null;
		if (astype.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)
			kw=ASymmetricKeyWrapperType.GNU_RSA_OAEP;
		else
			kw=ASymmetricKeyWrapperType.BC_FIPS_RSA_OAEP;
		
			
		byte[] localEncryptedKey = kw.wrapKey(rand, kpd.getASymmetricPublicKey(), localKey);
		SymmetricSecretKey decryptedKey=kw.unwrapKey(kpd.getASymmetricPrivateKey(), localEncryptedKey);
		Assert.assertEquals(localKey.getAuthentifiedSignatureAlgorithmType(), decryptedKey.getAuthentifiedSignatureAlgorithmType());
		Assert.assertEquals(localKey.getEncryptionAlgorithmType(), decryptedKey.getEncryptionAlgorithmType());
		Assert.assertEquals(localKey.getKeySize(), decryptedKey.getKeySize());
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
			byte b1[] = md.digest(m);
			md.reset();
			byte b2[] = md.digest(m);

			Assert.assertEquals(b1, b2);

		}

	}

	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncoding" })
	public void testP2PASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, SignatureException, IllegalBlockSizeException,
			BadPaddingException, NoSuchProviderException, InvalidKeySpecException, ShortBufferException, IllegalStateException, InvalidParameterSpecException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, (short)1024).generateKeyPair();
		ASymmetricKeyPair kpl = type.getKeyPairGenerator(rand, (short)1024).generateKeyPair();
		P2PASymmetricEncryptionAlgorithm algoDistant = new P2PASymmetricEncryptionAlgorithm(kpd,
				kpl.getASymmetricPublicKey());
		P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(kpl,
				kpd.getASymmetricPublicKey());

		for (byte m[] : messagesToEncrypt) {
			byte[] encoded = algoLocal.encode(m);
			Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(m.length));
			byte md[] = algoDistant.decode(encoded);
			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);

			encoded = algoDistant.encode(m);
			Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(m.length));
			md = algoLocal.decode(encoded);

			Assert.assertEquals(md.length, m.length, "Testing size " + type);
			Assert.assertEquals(md, m, "Testing " + type);


			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			encoded = algoLocal.encode(m, off, size);
			Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(size));
			md = algoDistant.decode(encoded);
			Assert.assertEquals(md.length, size, "Testing size " + type);
			for (int i = 0; i < size; i++)
				Assert.assertEquals(md[i], m[i + off]);

			encoded = algoDistant.encode(m, off, size);
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
		Assert.assertTrue(ph.checkValidHashedPassword(password, hashedValue));
		Assert.assertFalse(ph.checkValidHashedPassword(invalidPassword, hashedValue));
		byte[] staticSalt = new byte[20];
		random.nextBytes(staticSalt);
		hashedValue = ph.hash(password, staticSalt);
		Assert.assertTrue(ph.checkValidHashedPassword(password, hashedValue, staticSalt));
		Assert.assertFalse(ph.checkValidHashedPassword(password, hashedValue));
		Assert.assertFalse(ph.checkValidHashedPassword(invalidPassword, hashedValue, staticSalt));
	}
	@Test(dataProvider = "providePasswordKeyDerivationTypesForSymmetricEncryptions", dependsOnMethods="testPasswordHash")
	public void testPasswordKeyDerivation(PasswordBasedKeyGenerationType derivationType, SymmetricEncryptionType encryptionType) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		String password = "password";
		String invalidPassword = "invalid password";
		Random r=new Random(System.currentTimeMillis());
		byte[] salt=new byte[32];
		r.nextBytes(salt);
		SymmetricSecretKey key1=derivationType.derivateKey(password.toCharArray(), salt, (byte)7, encryptionType);
		Assert.assertEquals(key1.getKeySize(), encryptionType.getDefaultKeySizeBits());
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
		Assert.assertEquals(key1.getKeySize(), signatureType.getDefaultKeySizeBits());
		Assert.assertEquals(key1.getAuthentifiedSignatureAlgorithmType(), signatureType);
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
					Object params[]=new Object[2];
					params[0]=p;
					params[1]=s;
					res[index++]=params;
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
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
					Object params[]=new Object[2];
					params[0]=p;
					params[1]=s;
					res[index++]=params;
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
		return res2;
	}
	
	@Test(dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods = "testEncodeAndSeparateEncoding")
	public void testSecretKeyEncoding(SymmetricEncryptionType type) throws NoSuchAlgorithmException,
			InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException,
			IllegalArgumentException, InvalidKeySpecException {
		System.out.println("Testing " + type);
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey key = type.getKeyGenerator(random).generateKey();
		Assert.assertEquals(SymmetricSecretKey.decode(key.encode()), key);
		new SymmetricEncryptionAlgorithm(random, key);
		Assert.assertEquals(SymmetricSecretKey.decode(key.encode()), key);

	}

	@Test(dataProvider = "provideSecureRandomType")
	public void testSecureRandom(SecureRandomType type) throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom random = type.getInstance(null, "parameter".getBytes());
		System.out.println("Test "+type);
		random = type.getSingleton("nonce".getBytes(), "parameter".getBytes());
		System.out.println(type+" instantiated");
		random.nextBytes(new byte[10]);
		if (type!=SecureRandomType.NativePRNG && type!=SecureRandomType.GNU_DEFAULT && type!=SecureRandomType.SHA1PRNG && type.getProvider()!=CodeProvider.BCFIPS)
		{
			
			int nb= type.getProvider()!=CodeProvider.BCFIPS?110000:260000/8;
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
	public void testAsymmetricSignatures(ASymmetricAuthentifiedSignatureType type, ASymmetricKeyPair kpd, int keySize)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException,
			NoSuchProviderException, ShortBufferException, IllegalStateException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException {
		System.out.println("Testing asymmetric signature : " + keySize);
		byte b[]=kpd.encode();
		ASymmetricKeyPair kpd2=ASymmetricKeyPair.decode(b);
		Assert.assertEquals(kpd2, kpd);
		ASymmetricAuthentifiedSignerAlgorithm signer = new ASymmetricAuthentifiedSignerAlgorithm(kpd.getASymmetricPrivateKey());
		ASymmetricAuthentifiedSignatureCheckerAlgorithm checker = new ASymmetricAuthentifiedSignatureCheckerAlgorithm(kpd.getASymmetricPublicKey());
		byte[] signature=testSignature(signer, checker);
		if (kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withECDSA
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA256withECDSA
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withECDSA
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_25519
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_25519
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_25519
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_SHA256withECDSA_CURVE_M_511
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_SHA384withECDSA_CURVE_M_511
				&& kpd.getAuthentifiedSignatureAlgorithmType()!=ASymmetricAuthentifiedSignatureType.BC_SHA512withECDSA_CURVE_M_511			
				)
			Assert.assertEquals(kpd.getAuthentifiedSignatureAlgorithmType().getSignatureSizeBits(kpd.getKeySize()), signature.length*8);
	}
	
	@Test(dataProvider="provideDataSymmetricKeyWrapperForEncryption")
	public void testSymmetricKeyWrapperForEncryption(SymmetricKeyWrapperType typeWrapper, SymmetricEncryptionType asetype, SymmetricEncryptionType setype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey kp=asetype.getKeyGenerator(rand, asetype.getDefaultKeySizeBits()).generateKey();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, setype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(kp, sk);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp, wrappedKey);
		Assert.assertEquals(sk.getKeySize(), sk2.getKeySize());
		Assert.assertEquals(sk.getAuthentifiedSignatureAlgorithmType(), sk2.getAuthentifiedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
	}
	@Test(dataProvider="provideDataSymmetricKeyWrapperForSignature")
	public void testSymmetricKeyWrapperForSignature(SymmetricKeyWrapperType typeWrapper, SymmetricEncryptionType asetype, SymmetricAuthentifiedSignatureType setype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey kp=asetype.getKeyGenerator(rand, (short)128).generateKey();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, (short)128).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(kp, sk);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp, wrappedKey);
		Assert.assertEquals(sk.getKeySize(), sk2.getKeySize());
		Assert.assertEquals(sk.getAuthentifiedSignatureAlgorithmType(), sk2.getAuthentifiedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
	}
	@DataProvider(name="provideDataSymmetricKeyWrapperForEncryption", parallel=false)
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
						Object params[]=new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
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
						Object params[]=new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
		return res2;
	}

	
	@Test(dataProvider="provideDataASymmetricKeyWrapperForEncryption")
	public void testASymmetricKeyWrapper(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricEncryptionType setype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp=asetype.getKeyPairGenerator(rand, (short)1024).generateKeyPair();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, setype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(rand, kp.getASymmetricPublicKey(), sk);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp.getASymmetricPrivateKey(), wrappedKey);
		Assert.assertEquals(sk.getKeySize(), sk2.getKeySize());
		Assert.assertEquals(sk.getAuthentifiedSignatureAlgorithmType(), sk2.getAuthentifiedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());

	}
	@Test(dataProvider="provideDataASymmetricKeyWrapperForSignature")
	public void testASymmetricKeyWrapper(ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricAuthentifiedSignatureType ssigtype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, IllegalArgumentException, InvalidWrappingException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp=asetype.getKeyPairGenerator(rand, (short)1024).generateKeyPair();
		SymmetricSecretKey sk= ssigtype.getKeyGenerator(rand, ssigtype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(rand, kp.getASymmetricPublicKey(), sk);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp.getASymmetricPrivateKey(), wrappedKey);
		Assert.assertEquals(sk.getKeySize(), sk2.getKeySize());
		Assert.assertEquals(sk.getAuthentifiedSignatureAlgorithmType(), sk2.getAuthentifiedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());

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
						Object params[]=new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
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
						Object params[]=new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object res2[][]=new Object[index][];
		for (int i=0;i<index;i++)
			res2[i]=res[i];
		return res2;
	}
	
	private byte[] testSignature(AbstractAuthentifiedSignerAlgorithm signer, AbstractAuthentifiedCheckerAlgorithm checker) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, InvalidKeySpecException, ShortBufferException, IllegalStateException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException
	{
		byte[] m = new byte[100000];
		Random r=new Random(System.currentTimeMillis());
		r.nextBytes(m);

		byte[] signature = signer.sign(m);

		Assert.assertTrue(checker.verify(m, signature));
		Assert.assertTrue(checker.verify(m, signature));
		

		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) ~m[i];
		}

		Assert.assertFalse(checker.verify(m, signature));
		return signature;
		
	}

	@Test(dataProvider = "provideDataForSymmetricSignatureTest", dependsOnMethods = { "testSymetricEncryptions" })
	public void testSymmetricSignatures(SymmetricAuthentifiedSignatureType type, SymmetricSecretKey secretKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException,
			NoSuchProviderException, ShortBufferException, IllegalStateException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException {
		System.out.println("Testing symmetric signature : " + secretKey.getAuthentifiedSignatureAlgorithmType());
		SymmetricAuthentifiedSignerAlgorithm signer = new SymmetricAuthentifiedSignerAlgorithm(secretKey);
		SymmetricAuthentifiedSignatureCheckerAlgorithm checker = new SymmetricAuthentifiedSignatureCheckerAlgorithm(secretKey);
		byte[] signature=testSignature(signer, checker);
		Assert.assertEquals(signature.length*8, secretKey.getAuthentifiedSignatureAlgorithmType().getSignatureSizeInBits());
	}

	@Test(invocationCount = 1, dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods = "testSecretKeyEncoding")
	public void testSymetricEncryptions(SymmetricEncryptionType type) throws NoSuchAlgorithmException,
			NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException,
			IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException {
		System.out.println("Testing " + type);
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);

		SymmetricSecretKey key = type.getKeyGenerator(random).generateKey();

		SymmetricEncryptionAlgorithm algoDistant = new SymmetricEncryptionAlgorithm(random, key);
		SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(random, key);

		Random rand = new Random(System.currentTimeMillis());

		for (byte[] m : messagesToEncrypt) {
			byte encrypted[] = algoLocal.encode(m);
			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(m.length), "length=" + m.length);

			Assert.assertTrue(encrypted.length >= m.length);
			byte decrypted[] = algoDistant.decode(encrypted);
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

	@Test(invocationCount = 4000)
	public void testReadWriteDataPackaged() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		Random rand = new Random(System.currentTimeMillis());
		byte originalBytes[] = new byte[50 + rand.nextInt(10000)];
		rand.nextBytes(originalBytes);
		int randNb = rand.nextInt(10000);
		byte encodedBytes[] = OutputDataPackagerWithRandomValues.encode(originalBytes, randNb);
		// Assert.assertTrue(encodedBytes.length>originalBytes.length);
		Assert.assertTrue(encodedBytes.length >= originalBytes.length, "invalid size : " + encodedBytes.length
				+ " (originalBytes size=" + originalBytes.length + ", randNb=" + randNb + ") ");
		byte decodedBytes[] = InputDataPackagedWithRandomValues.decode(encodedBytes);
		Assert.assertEquals(decodedBytes.length, originalBytes.length);
		for (int i = 0; i < decodedBytes.length; i++)
			Assert.assertEquals(decodedBytes[i], originalBytes[i]);
	}

	@Test(invocationCount = 100, dataProvider = "provideDataForEllipticCurveDiffieHellmanKeyExchanger", dependsOnMethods = "testMessageDigest")
	public void testEllipticCurveDiffieHellmanKeyExchanger(EllipticCurveDiffieHellmanType type)
			throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException,
			java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			BadPaddingException, IllegalStateException, IllegalBlockSizeException, IOException {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		EllipticCurveDiffieHellmanAlgorithm peer1 = type.getInstance(random);
		EllipticCurveDiffieHellmanAlgorithm peer2 = type.getInstance(random);
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);
		peer1.generateAndSetKeyPair();
		peer2.generateAndSetKeyPair();
		
		byte[] publicKey1 = peer1.getEncodedPublicKey();
		byte[] publicKey2 = peer2.getEncodedPublicKey();
		{
			try
			{
				EllipticCurveDiffieHellmanAlgorithm falsePeer = type.getInstance(random);
				falsePeer.setKeyPair(peer1.getKeyPair());
				falsePeer.setDistantPublicKey(publicKey1, SymmetricEncryptionType.DEFAULT, (short)128, keyingMaterial);
				
				Assert.fail();
			}
			catch(Exception e)
			{
				
			}
		}
		
		peer1.setDistantPublicKey(publicKey2, SymmetricEncryptionType.DEFAULT, (short)128, keyingMaterial);
		peer2.setDistantPublicKey(publicKey1, SymmetricEncryptionType.DEFAULT, (short)128, keyingMaterial);
		Assert.assertEquals(peer1.getDerivedKey(),peer2.getDerivedKey());

		SymmetricSecretKey key = peer1.getDerivedKey();

		SymmetricEncryptionAlgorithm algoDistant = new SymmetricEncryptionAlgorithm(random, key);
		SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(random, key);

		Random rand = new Random(System.currentTimeMillis());

		for (byte[] m : messagesToEncrypt) {
			byte encrypted[] = algoLocal.encode(m);
			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(m.length), "length=" + m.length);

			Assert.assertTrue(encrypted.length >= m.length);
			byte decrypted[] = algoDistant.decode(encrypted);
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
	@Test(invocationCount = 100, dataProvider = "provideDataForEllipticCurveDiffieHellmanKeyExchanger", dependsOnMethods = "testMessageDigest")
	public void testEllipticCurveDiffieHellmanKeyExchangerForSignature(EllipticCurveDiffieHellmanType type)
			throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException,
			java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException,
			InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeySpecException,
			BadPaddingException, IllegalStateException, IllegalBlockSizeException, IOException, SignatureException, ShortBufferException, InvalidParameterSpecException {
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		EllipticCurveDiffieHellmanAlgorithm peer1 = type.getInstance(random);
		EllipticCurveDiffieHellmanAlgorithm peer2 = type.getInstance(random);
		peer1.generateAndSetKeyPair();
		peer2.generateAndSetKeyPair();
		
		byte[] publicKey1 = peer1.getEncodedPublicKey();
		byte[] publicKey2 = peer2.getEncodedPublicKey();
		byte[] keyingMaterial=new byte[100];
		random.nextBytes(keyingMaterial);
		
		peer1.setDistantPublicKey(publicKey2, SymmetricAuthentifiedSignatureType.DEFAULT, (short)128, keyingMaterial);
		peer2.setDistantPublicKey(publicKey1, SymmetricAuthentifiedSignatureType.DEFAULT, (short)128, keyingMaterial);
		Assert.assertEquals(peer1.getDerivedKey(),peer2.getDerivedKey());

		SymmetricSecretKey key = peer1.getDerivedKey();

		SymmetricAuthentifiedSignatureCheckerAlgorithm checker=new SymmetricAuthentifiedSignatureCheckerAlgorithm(key);
		SymmetricAuthentifiedSignerAlgorithm signer=new SymmetricAuthentifiedSignerAlgorithm(key);

		for (byte[] m : messagesToEncrypt) {
			byte[] signature=signer.sign(m);
			Assert.assertTrue(checker.verify(m, signature));
			for (int i=0;i<signature.length;i++)
				signature[i]=(byte)~signature[i];
			Assert.assertFalse(checker.verify(m, signature));
		}

	}

	@DataProvider(name = "provideDataForEllipticCurveDiffieHellmanKeyExchanger", parallel = true)
	public Object[][] provideDataForEllipticCurveDiffieHellmanKeyExchanger() {
		Object[][] res = new Object[EllipticCurveDiffieHellmanType.values().length][];
		int index = 0;
		for (EllipticCurveDiffieHellmanType type : EllipticCurveDiffieHellmanType.values()) {
			res[index] = new Object[1];
			res[index++][0] = type;
		}
		return res;
	}

}
