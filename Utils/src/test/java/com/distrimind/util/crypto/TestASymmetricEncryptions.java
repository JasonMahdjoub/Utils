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
public class TestASymmetricEncryptions {
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
	public void testASymmetricKeyWrapperForEncryption(AbstractSecureRandom rand, AbstractKeyPair<?,?> kp,  ASymmetricKeyWrapperType typeWrapper, ASymmetricEncryptionType asetype, SymmetricEncryptionType setype)
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
	@Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = { "testASymmetricKeyPairEncodingForEncryption" })
	public void testP2PASymetricEncryptions(ASymmetricEncryptionType type)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, IOException,
			NoSuchProviderException, IllegalStateException {
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
	@Test(dataProvider = "provideDataForHybridASymetricEncryptions")
	public void testHybridP2PASymetricEncryptions(HybridASymmetricEncryptionType type)
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, IOException,
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
				kpl.getASymmetricPublicKey());
		P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(kpl,
				kpd.getASymmetricPublicKey());

		testP2PASymetricEncryptionsImpl(rand, type, algoDistant, algoLocal);

	}
	public void testP2PASymetricEncryptionsImpl(AbstractSecureRandom rand, Object type, P2PASymmetricEncryptionAlgorithm algoDistant, P2PASymmetricEncryptionAlgorithm algoLocal)
			throws
			IOException,
			IllegalStateException {


		for (byte[] m : VariousTests.messagesToEncrypt) {
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

	@Test(dataProvider = "provideDataForHybridEncryptions")
	public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException,
			NoSuchProviderException, InvalidKeySpecException, IllegalStateException, IllegalArgumentException, InvalidWrappingException {
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
			InvalidAlgorithmParameterException, IOException,
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
				kp.getASymmetricPublicKey());
		ServerASymmetricEncryptionAlgorithm algoServer = new ServerASymmetricEncryptionAlgorithm(kp);

		for (byte[] m : VariousTests.messagesToEncrypt) {
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
			throws NoSuchAlgorithmException,
			InvalidAlgorithmParameterException, IOException,
			NoSuchProviderException, IllegalStateException {
		System.out.println("Testing " + type);
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		ASymmetricKeyPair kp = type.getKeyPairGenerator(rand, type.name().startsWith("BCPQC_MCELIECE_")?type.getDefaultKeySizeBits():2048).generateKeyPair();

		testClientServerASymetricEncryptions(kp);

	}
	@Test(dataProvider = "provideDataForASymetricEncryptions")
	public void testASymmetricKeyExpirationTimeChange(ASymmetricEncryptionType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
		TestASymmetricSignatures.testASymmetricKeyExpirationTimeChange(generateKeyPair(type));
	}
	private ASymmetricKeyPair generateKeyPair(ASymmetricEncryptionType type) throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
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
			throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeySpecException, IOException {
		System.out.println("Testing ASymmetricKeyPairEncoding " + type);

		ASymmetricKeyPair kpd=generateKeyPair(type);

		byte[] b = kpd.encode(false);
		ASymmetricKeyPair kpd2=(ASymmetricKeyPair)DecentralizedValue.decode(b);
		testASymmetricKeyPairEqualityForEncryption(kpd, kpd2);
		testASymmetricKeyPairEqualityForEncryption(kpd, (ASymmetricKeyPair)DecentralizedValue.valueOf(kpd.encodeString()));
		Assert.assertEquals(kpd2.getASymmetricPublicKey().getTimeExpirationUTC(), Long.MAX_VALUE);

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

		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPublicKey().encodeString()), kpd.getASymmetricPublicKey());
		Assert.assertEquals(DecentralizedValue.valueOf(kpd.getASymmetricPrivateKey().encodeString()), kpd.getASymmetricPrivateKey());

		System.out.println(type+" :");
		System.out.println("\tKey pair encoding : "+kpd.toString());
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
