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
import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;

import org.bouncycastle.crypto.CryptoException;
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
import com.distrimind.util.crypto.SignatureType;
import com.distrimind.util.crypto.SymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.SymmetricEncryptionType;
import com.distrimind.util.crypto.SymmetricSecretKey;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.5
 * @since Utils 1.4
 */
public class CryptoTests
{
    private static final byte[] messagesToEncrypt[];

    private static final byte salt[];
    static
    {
	System.out.println("Generatring messages");
	Random rand = new Random(System.currentTimeMillis());
	messagesToEncrypt = new byte[30][];
	for (int i = 0; i < messagesToEncrypt.length; i++)
	{
	    byte[] b = new byte[rand.nextInt(50) + 10000];
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
    public Object[][] provideDataForASymetricEncryptions()
    {
	Object[][] res = new Object[ASymmetricEncryptionType.values().length][];
	int i = 0;
	for (ASymmetricEncryptionType v : ASymmetricEncryptionType.values())
	{
	    Object o[] = new Object[1];
	    o[0] = v;
	    res[i++] = o;
	}
	return res;
    }

    @DataProvider(name = "provideDataForHybridEncryptions", parallel = true)
    public Object[][] provideDataForHybridEncryptions()
    {
	Object[][] res = new Object[SymmetricEncryptionType.values().length
		* ASymmetricEncryptionType.values().length][];
	int i = 0;
	for (SymmetricEncryptionType vS : SymmetricEncryptionType.values())
	{
	    for (ASymmetricEncryptionType vAS : ASymmetricEncryptionType
		    .values())
	    {
		Object o[] = new Object[2];
		o[0] = vAS;
		o[1] = vS;
		res[i++] = o;
	    }
	}
	return res;
    }

    @DataProvider(name = "provideDataForSignatureTest", parallel = true)
    public Object[][] provideDataForSignatureTest()
    {
	Object[][] res = new Object[ASymmetricEncryptionType.values().length
		* SignatureType.values().length * keySizes.length][];
	int i = 0;
	for (ASymmetricEncryptionType ast : ASymmetricEncryptionType.values())
	{
	    for (SignatureType st : SignatureType.values())
	    {
		for (int keySize : keySizes)
		{
		    Object o[] = new Object[3];
		    o[0] = ast;
		    o[1] = st;
		    o[2] = new Integer(keySize);
		    res[i++] = o;
		}
	    }
	}
	return res;
    }

    @DataProvider(name = "provideDataForSymetricEncryptions", parallel = true)
    public Object[][] provideDataForSymetricEncryptions()
    {
	Object[][] res = new Object[SymmetricEncryptionType.values().length][];
	int i = 0;
	for (SymmetricEncryptionType v : SymmetricEncryptionType.values())
	{
	    Object o[] = new Object[1];
	    o[0] = v;
	    res[i++] = o;
	}
	return res;
    }

    @DataProvider(name = "provideMessageDigestType", parallel = true)
    public Object[][] provideMessageDigestType()
    {
	Object[][] res = new Object[MessageDigestType.values().length][];
	int i = 0;
	for (MessageDigestType v : MessageDigestType.values())
	{
	    Object o[] = new Object[1];
	    o[0] = v;
	    res[i++] = o;
	}
	return res;
    }

    @DataProvider(name = "providePasswordHashTypes", parallel = true)
    public Object[][] providePasswordHashTypes()
    {
	Object[][] res = new Object[PasswordHashType.values().length][1];
	int index = 0;
	for (PasswordHashType type : PasswordHashType.values())
	{
	    res[index++][0] = type;
	}
	return res;
    }

    @DataProvider(name = "provideSecureRandomType", parallel = true)
    public Object[][] provideSecureRandomType()
    {
	Object[][] res = new Object[SecureRandomType.values().length][];
	int i = 0;
	for (SecureRandomType v : SecureRandomType.values())
	{
	    Object o[] = new Object[1];
	    o[0] = v;
	    res[i++] = o;
	}
	return res;
    }

    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = "testSecureRandom")
    public void testASymmetricKeyPairEncoding(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchProviderException
    {
	System.out.println("Testing ASymmetricKeyPairEncoding " + type);
	AbstractSecureRandom rand = SecureRandomType.DEFAULT.getInstance();
	ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand).generateKeyPair();

	Assert.assertEquals(
		ASymmetricPublicKey
			.decode(kpd.getASymmetricPublicKey().encode()),
		kpd.getASymmetricPublicKey());
	Assert.assertEquals(
		ASymmetricPrivateKey
			.decode(kpd.getASymmetricPrivateKey().encode()),
		kpd.getASymmetricPrivateKey());
	Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()), kpd);
	Assert.assertEquals(
		ASymmetricKeyPair.decode(kpd.encode())
			.getASymmetricPrivateKey(),
		kpd.getASymmetricPrivateKey());
	Assert.assertEquals(
		ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPublicKey(),
		kpd.getASymmetricPublicKey());
    }
    
    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = {
	    "testASymmetricKeyPairEncoding", "testReadWriteDataPackaged" })
    public void testASymmetricSecretMessageExchanger(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalAccessException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException
    {
	System.out.println("Testing ASymmetricSecretMessageExchanger " + type);
	AbstractSecureRandom rand = SecureRandomType.DEFAULT.getInstance();
	for (short keySize = 1024; keySize <= 4096; keySize += 1024)
	{
	    ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, keySize)
		    .generateKeyPair();
	    ASymmetricKeyPair kpl = type.getKeyPairGenerator(rand, keySize)
		    .generateKeyPair();

	    P2PASymmetricSecretMessageExchanger algoLocal = new P2PASymmetricSecretMessageExchanger(
		    kpl.getASymmetricPublicKey());
	    P2PASymmetricSecretMessageExchanger algoDistant = new P2PASymmetricSecretMessageExchanger(
		    kpd.getASymmetricPublicKey());
	    algoLocal.setDistantPublicKey(algoDistant.encodeMyPublicKey());
	    algoDistant.setDistantPublicKey(algoLocal.encodeMyPublicKey());
	    algoLocal.setHashIterationsNumber(1024);
	    algoDistant.setHashIterationsNumber(1024);

	    byte[] falseMessage = new byte[10];
	    rand.nextBytes(falseMessage);

	    for (byte[] m : messagesToEncrypt)
	    {
		byte[] localCrypt = algoLocal.encode(m, salt, true);
		Assert.assertTrue(localCrypt.length != 0);
		Assert.assertTrue(algoDistant.verifyDistantMessage(m, salt, localCrypt, true));
		Assert.assertFalse(algoDistant.verifyDistantMessage(m, salt, falseMessage, true));
		Assert.assertFalse(algoDistant.verifyDistantMessage(
			falseMessage, salt, localCrypt, true));

		byte[] distantCrypt = algoDistant.encode(m, salt, true);
		Assert.assertTrue(distantCrypt.length != 0);
		Assert.assertTrue(algoLocal.verifyDistantMessage(m, salt,
			distantCrypt, true));
		Assert.assertFalse(algoLocal.verifyDistantMessage(m, salt,
			falseMessage, true));
		Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage,
			salt, distantCrypt, true));
	    }

	    for (byte[] m : messagesToEncrypt)
	    {
		byte[] localCrypt = algoLocal.encode(m, salt, false);
		Assert.assertTrue(localCrypt.length != 0);
		Assert.assertTrue(algoDistant.verifyDistantMessage(m, salt,
			localCrypt, false));
		Assert.assertFalse(algoDistant.verifyDistantMessage(m, salt,
			falseMessage, false));
		Assert.assertFalse(algoDistant.verifyDistantMessage(
			falseMessage, salt, localCrypt, false));

		byte[] distantCrypt = algoDistant.encode(m, salt, false);
		Assert.assertTrue(distantCrypt.length != 0);
		Assert.assertTrue(algoLocal.verifyDistantMessage(m, salt,
			distantCrypt, false));
		Assert.assertFalse(algoLocal.verifyDistantMessage(m, salt,
			falseMessage, false));
		Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage,
			salt, distantCrypt, false));
	    }
	    for (byte[] m : messagesToEncrypt)
	    {
		byte[] localCrypt = algoLocal.encode(m, null, true);
		Assert.assertTrue(localCrypt.length != 0);
		Assert.assertTrue(algoDistant.verifyDistantMessage(m, null,
			localCrypt, true));
		Assert.assertFalse(algoDistant.verifyDistantMessage(m, null,
			falseMessage, true));
		Assert.assertFalse(algoDistant.verifyDistantMessage(
			falseMessage, null, localCrypt, true));

		byte[] distantCrypt = algoDistant.encode(m, null, true);
		Assert.assertTrue(distantCrypt.length != 0);
		Assert.assertTrue(algoLocal.verifyDistantMessage(m, null,
			distantCrypt, true));
		Assert.assertFalse(algoLocal.verifyDistantMessage(m, null,
			falseMessage, true));
		Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage,
			null, distantCrypt, true));
	    }
	    for (byte[] m : messagesToEncrypt)
	    {
		byte[] localCrypt = algoLocal.encode(m, null, false);
		Assert.assertTrue(localCrypt.length != 0);
		Assert.assertTrue(algoDistant.verifyDistantMessage(m, null,
			localCrypt, false));
		Assert.assertFalse(algoDistant.verifyDistantMessage(m, null,
			falseMessage, false));
		Assert.assertFalse(algoDistant.verifyDistantMessage(
			falseMessage, null, localCrypt, false));

		byte[] distantCrypt = algoDistant.encode(m, null, false);
		Assert.assertTrue(distantCrypt.length != 0);
		Assert.assertTrue(algoLocal.verifyDistantMessage(m, null,
			distantCrypt, false));
		Assert.assertFalse(algoLocal.verifyDistantMessage(m, null,
			falseMessage, false));
		Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage,
			null, distantCrypt, false));
	    }
	    String password = "password";
	    String falsePassword = "falsePassword";
	    byte[] localCrypt = algoLocal.encode(password, salt);
	    Assert.assertTrue(localCrypt.length != 0);
	    Assert.assertTrue(algoDistant.verifyDistantMessage(password, salt,
		    localCrypt));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(password, salt,
		    falseMessage));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(falsePassword,
		    salt, localCrypt));

	    byte[] distantCrypt = algoDistant.encode(password, salt);
	    Assert.assertTrue(distantCrypt.length != 0);
	    Assert.assertTrue(algoLocal.verifyDistantMessage(password, salt,
		    distantCrypt));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(password, salt,
		    falseMessage));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(falsePassword,
		    salt, distantCrypt));

	}
    }
    
    @DataProvider(name = "provideDataForP2PJPAKEPasswordExchanger", parallel = true)
    public Object[][] provideDataForP2PJPAKEPasswordExchanger()
    {
	byte[] salt=new byte[]{(byte)21,(byte)5645,(byte)512,(byte)42310,(byte)24,(byte)0,(byte)1,(byte)1231,(byte)34};
	
	
	Object[][] res=new Object[8][];
	
	res[0]=new Object[]{new Boolean(true), salt, new Boolean(true)};
	res[1]=new Object[]{new Boolean(true), salt, new Boolean(false)};
	res[2]=new Object[]{new Boolean(false), salt, new Boolean(false)};
	res[3]=new Object[]{new Boolean(false), salt, new Boolean(true)};
	res[4]=new Object[]{new Boolean(true), null, new Boolean(true)};
	res[5]=new Object[]{new Boolean(true), null, new Boolean(false)};
	res[6]=new Object[]{new Boolean(false), null, new Boolean(false)};
	res[7]=new Object[]{new Boolean(false), null, new Boolean(true)};
	
	return res;
    }
    @Test(dataProvider = "provideDataForP2PJPAKEPasswordExchanger", dependsOnMethods = {"testMessageDigest", "testPasswordHash"})
    public void testP2PJPAKEPasswordExchanger(boolean expectedVerify, byte[] salt, boolean messageIsKey) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException, ClassNotFoundException
    {
	    char[] password= "password".toCharArray();
	    char[] falsePassword = "falsePassword".toCharArray();
	    
	    
	    
	    P2PJPAKESecretMessageExchanger exchanger1=new P2PJPAKESecretMessageExchanger("participant id 1", password, salt, 0, salt==null?0:salt.length);
	    P2PJPAKESecretMessageExchanger exchanger2=new P2PJPAKESecretMessageExchanger("participant id 2", expectedVerify?password:falsePassword, salt, 0, salt==null?0:salt.length);
	    try
	    {
	
		byte[] step11=exchanger1.getStep1Message();
		byte[] step21=exchanger2.getStep1Message();
		
		byte[] step12=exchanger1.receiveStep1AndGetStep2Message(step21);
		byte[] step22=exchanger2.receiveStep1AndGetStep2Message(step11);
		
		byte[] step13=exchanger1.receiveStep2AndGetStep3Message(step22);
		byte[] step23=exchanger2.receiveStep2AndGetStep3Message(step12);
		
		exchanger1.receiveStep3(step23);
		exchanger2.receiveStep3(step13);
		
		Assert.assertEquals(exchanger1.isPassworkOrKeyValid(), expectedVerify);
		Assert.assertEquals(exchanger2.isPassworkOrKeyValid(), expectedVerify);
	    }
	    catch(CryptoException e)
	    {
		if (expectedVerify)
		    Assert.fail("Unexpected exception", e);
		Assert.assertFalse(exchanger1.isPassworkOrKeyValid());
		Assert.assertFalse(exchanger2.isPassworkOrKeyValid());
	    }
    }
    
    @DataProvider(name = "provideDataForP2PJPAKESecretMessageExchanger", parallel = true)
    public Object[][] provideDataForP2PJPAKESecretMessageExchanger()
    {
	byte[] salt=new byte[]{(byte)21,(byte)5645,(byte)512,(byte)42310,(byte)24,(byte)0,(byte)1,(byte)1231,(byte)34};
	
	
	ArrayList<Object[]> res=new ArrayList<>();
	
	for (byte[] m : messagesToEncrypt)
	{
	    for (boolean expectedVerify : new boolean[]{true, false})
	    {
		for (byte[] s : new byte[][]{null, salt})
		{
		    for (boolean messageIsKey : new boolean[]{true, false})
		    {
			res.add(new Object[]{new Boolean(expectedVerify), new Boolean(messageIsKey), s, m});
		    }
		}
	    }
	}
	Object[][] res2=new Object[res.size()][];
	for (int i=0;i<res.size();i++)
	    res2[i]=res.get(i);
	return res2;
    }
    

    
    @Test(dataProvider = "provideDataForP2PJPAKESecretMessageExchanger", dependsOnMethods = {"testMessageDigest"})
    public void testP2PJPAKESecretMessageExchanger(boolean expectedVerify, boolean messageIsKey, byte[] salt, byte []m) throws NoSuchAlgorithmException, IOException, InvalidKeySpecException, NoSuchProviderException, ClassNotFoundException
    {
	Random r = new Random(System.currentTimeMillis());
	byte[] falseMessage = new byte[10];
	r.nextBytes(falseMessage);

	P2PJPAKESecretMessageExchanger exchanger1=new P2PJPAKESecretMessageExchanger("participant id 1", m, 0, m.length, salt, 0, salt==null?0:salt.length, messageIsKey);
	P2PJPAKESecretMessageExchanger exchanger2=new P2PJPAKESecretMessageExchanger("participant id 2", expectedVerify?m:falseMessage, 0, (expectedVerify?m:falseMessage).length, salt, 0, salt==null?0:salt.length, messageIsKey);
	try
	{
	
	    byte[] step11=exchanger1.getStep1Message();
	    byte[] step21=exchanger2.getStep1Message();
	    byte[] step12=exchanger1.receiveStep1AndGetStep2Message(step21);
	    byte[] step22=exchanger2.receiveStep1AndGetStep2Message(step11);
		
	    byte[] step13=exchanger1.receiveStep2AndGetStep3Message(step22);
	    byte[] step23=exchanger2.receiveStep2AndGetStep3Message(step12);
		
	    exchanger1.receiveStep3(step23);
	    exchanger2.receiveStep3(step13);
		
	    Assert.assertEquals(exchanger1.isPassworkOrKeyValid(), expectedVerify);
	    Assert.assertEquals(exchanger2.isPassworkOrKeyValid(), expectedVerify);
	}
	catch(CryptoException e)
	{
	    if (expectedVerify)
		Assert.fail("Unexpected exception", e);
	    Assert.assertFalse(exchanger1.isPassworkOrKeyValid());
	    Assert.assertFalse(exchanger2.isPassworkOrKeyValid());
	}
    }

    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = {
	    "testASymmetricKeyPairEncoding" })
    public void testClientServerASymetricEncryptions(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, SignatureException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException
    {
	System.out.println("Testing " + type);
	AbstractSecureRandom rand = SecureRandomType.DEFAULT.getInstance();
	ASymmetricKeyPair kp = type.getKeyPairGenerator(rand, (short) 1024)
		.generateKeyPair();
	ClientASymmetricEncryptionAlgorithm algoClient = new ClientASymmetricEncryptionAlgorithm(
		kp.getASymmetricPublicKey());
	ServerASymmetricEncryptionAlgorithm algoServer = new ServerASymmetricEncryptionAlgorithm(
		kp);

	for (byte m[] : messagesToEncrypt)
	{
	    byte[] encodedBytes = algoClient.encode(m);
	    Assert.assertEquals(encodedBytes.length,
		    algoClient.getOutputSizeForEncryption(m.length));
	    byte[] decodedBytes = algoServer.decode(encodedBytes);
	    Assert.assertEquals(m, decodedBytes);
	    byte[] signature = algoServer.getSignerAlgorithm().sign(m);
	    Assert.assertTrue(algoClient.getSignatureCheckerAlgorithm()
		    .verify(m, signature));

	    int off = rand.nextInt(15);
	    int size = m.length;
	    size -= rand.nextInt(15) + off;

	    encodedBytes = algoClient.encode(m, off, size);
	    Assert.assertEquals(encodedBytes.length,
		    algoClient.getOutputSizeForEncryption(size));
	    decodedBytes = algoServer.decode(encodedBytes);
	    for (int i = 0; i < size; i++)
		Assert.assertEquals(decodedBytes[i], m[i + off]);

	    signature = algoServer.getSignerAlgorithm().sign(m, off, size);
	    Assert.assertTrue(algoClient.getSignatureCheckerAlgorithm()
		    .verify(m, off, size, signature, 0, signature.length));

	}

    }

    @Test(invocationCount = 20)
    public void testEncodeAndSeparateEncoding()
    {
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

    @Test(dataProvider = "provideDataForHybridEncryptions", dependsOnMethods = {
	    "testSymetricEncryptions", "testP2PASymetricEncryptions" })
    public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException
    {
	System.out.println("Testing " + astype + "/" + stype);
	AbstractSecureRandom rand = SecureRandomType.DEFAULT.getInstance();
	ASymmetricKeyPair kpd = astype.getKeyPairGenerator(rand)
		.generateKeyPair();
	ASymmetricKeyPair kpl = astype.getKeyPairGenerator(rand)
		.generateKeyPair();

	P2PASymmetricEncryptionAlgorithm algoDistantAS = new P2PASymmetricEncryptionAlgorithm(
		kpd, kpl.getASymmetricPublicKey());
	P2PASymmetricEncryptionAlgorithm algoLocalAS = new P2PASymmetricEncryptionAlgorithm(
		kpl, kpd.getASymmetricPublicKey());

	SymmetricSecretKey localKey = stype.getKeyGenerator(rand).generateKey();

	SymmetricEncryptionAlgorithm algoLocalS = new SymmetricEncryptionAlgorithm(
		localKey, SecureRandomType.DEFAULT, null);
	byte[] localEncryptedKey = algoLocalS.encodeKey(algoLocalAS);
	SymmetricEncryptionAlgorithm algoDistantS = SymmetricEncryptionAlgorithm
		.getInstance(SecureRandomType.DEFAULT, null, localEncryptedKey,
			algoDistantAS);

	for (byte[] m : messagesToEncrypt)
	{
	    byte[] md = algoDistantS.decode(algoLocalS.encode(m));
	    Assert.assertEquals(md.length, m.length,
		    "Testing size " + astype + "/" + stype);
	    Assert.assertEquals(md, m, "Testing " + astype + "/" + stype);

	    md = algoLocalS.decode(algoDistantS.encode(m));
	    Assert.assertEquals(md.length, m.length,
		    "Testing size " + astype + "/" + stype);
	    Assert.assertEquals(md, m, "Testing " + astype + "/" + stype);
	}

    }

    @Test(dataProvider = "provideMessageDigestType")
    public void testMessageDigest(MessageDigestType type) throws NoSuchAlgorithmException
    {
	System.out.println("Testing message digest " + type);

	AbstractMessageDigest md = type.getMessageDigestInstance();
	for (byte[] m : messagesToEncrypt)
	{
	    byte b1[] = md.digest(m);
	    md.reset();
	    byte b2[] = md.digest(m);
	    
	    Assert.assertEquals(b1, b2);
	    
	}

    }

    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods = {
	    "testASymmetricKeyPairEncoding" })
    public void testP2PASymetricEncryptions(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, SignatureException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException
    {
	System.out.println("Testing " + type);
	AbstractSecureRandom rand = SecureRandomType.DEFAULT.getInstance();
	ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand)
		.generateKeyPair();
	ASymmetricKeyPair kpl = type.getKeyPairGenerator(rand)
		.generateKeyPair();
	P2PASymmetricEncryptionAlgorithm algoDistant = new P2PASymmetricEncryptionAlgorithm(
		kpd, kpl.getASymmetricPublicKey());
	P2PASymmetricEncryptionAlgorithm algoLocal = new P2PASymmetricEncryptionAlgorithm(
		kpl, kpd.getASymmetricPublicKey());

	for (byte m[] : messagesToEncrypt)
	{
	    byte[] encoded = algoLocal.encode(m);
	    Assert.assertEquals(encoded.length,
		    algoLocal.getOutputSizeForEncryption(m.length));
	    byte md[] = algoDistant.decode(encoded);
	    Assert.assertEquals(md.length, m.length, "Testing size " + type);
	    Assert.assertEquals(md, m, "Testing " + type);

	    encoded = algoDistant.encode(m);
	    Assert.assertEquals(encoded.length,
		    algoLocal.getOutputSizeForEncryption(m.length));
	    md = algoLocal.decode(encoded);

	    Assert.assertEquals(md.length, m.length, "Testing size " + type);
	    Assert.assertEquals(md, m, "Testing " + type);

	    byte[] sign = algoLocal.getSignerAlgorithm().sign(m);
	    Assert.assertTrue(
		    algoDistant.getSignatureCheckerAlgorithm().verify(m, sign));

	    int off = rand.nextInt(15);
	    int size = m.length;
	    size -= rand.nextInt(15) + off;

	    encoded = algoLocal.encode(m, off, size);
	    Assert.assertEquals(encoded.length,
		    algoLocal.getOutputSizeForEncryption(size));
	    md = algoDistant.decode(encoded);
	    Assert.assertEquals(md.length, size, "Testing size " + type);
	    for (int i = 0; i < size; i++)
		Assert.assertEquals(md[i], m[i + off]);

	    encoded = algoDistant.encode(m, off, size);
	    Assert.assertEquals(encoded.length,
		    algoLocal.getOutputSizeForEncryption(size));
	    md = algoLocal.decode(encoded);

	    Assert.assertEquals(md.length, size, "Testing size " + type);
	    for (int i = 0; i < size; i++)
		Assert.assertEquals(md[i], m[i + off]);

	    sign = algoLocal.getSignerAlgorithm().sign(m, off, size);
	    Assert.assertTrue(algoDistant.getSignatureCheckerAlgorithm()
		    .verify(m, off, size, sign, 0, sign.length));

	}

    }

    @Test(dataProvider = "providePasswordHashTypes")
    public void testPasswordHash(PasswordHashType type) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	SecureRandom random = new SecureRandom();
	PasswordHash ph = new PasswordHash(type, random);
	String password = "password";
	String invalidPassword = "invalid password";
	byte[] hashedValue = ph.hash(password);
	Assert.assertTrue(ph.checkValidHashedPassword(password, hashedValue));
	Assert.assertFalse(
		ph.checkValidHashedPassword(invalidPassword, hashedValue));
	byte[] staticSalt = new byte[20];
	random.nextBytes(staticSalt);
	hashedValue = ph.hash(password, staticSalt);
	Assert.assertTrue(
		ph.checkValidHashedPassword(password, hashedValue, staticSalt));
	Assert.assertFalse(ph.checkValidHashedPassword(password, hashedValue));
	Assert.assertFalse(ph.checkValidHashedPassword(invalidPassword,
		hashedValue, staticSalt));
    }

    @Test(dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods = "testEncodeAndSeparateEncoding")
    public void testSecretKeyEncoding(SymmetricEncryptionType type) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, IllegalArgumentException, InvalidKeySpecException
    {
	System.out.println("Testing " + type);
	AbstractSecureRandom random = SecureRandomType.DEFAULT.getInstance();
	SymmetricSecretKey key = type.getKeyGenerator(random).generateKey();
	Assert.assertEquals(SymmetricSecretKey.decode(key.encode()), key);
	new SymmetricEncryptionAlgorithm(key, SecureRandomType.DEFAULT, null);
	Assert.assertEquals(SymmetricSecretKey.decode(key.encode()), key);

    }

    @Test(dataProvider = "provideSecureRandomType")
    public void testSecureRandom(SecureRandomType type) throws NoSuchAlgorithmException, NoSuchProviderException
    {
	AbstractSecureRandom random = type.getInstance();
	random.nextBytes(new byte[100]);
    }

    @Test(dataProvider = "provideDataForSignatureTest")
    public void testSignatures(ASymmetricEncryptionType type, SignatureType sigType, int keySize) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException, NoSuchProviderException
    {
	if (sigType.getCodeProvider() != type.getCodeProvider())
	    return;
	System.out.println(
		"Testing signature : " + type + "/" + sigType + "/" + keySize);
	AbstractSecureRandom rand = SecureRandomType.DEFAULT.getInstance();
	ASymmetricKeyPair kpd = type.getKeyPairGenerator(rand, (short) keySize)
		.generateKeyPair();
	byte[] m = new byte[10];
	rand.nextBytes(m);

	AbstractSignature s = sigType.getSignatureInstance();
	s.initSign(kpd.getASymmetricPrivateKey());
	s.update(m);
	byte[] sign = s.sign();
	Assert.assertEquals(sign.length, type.getDefaultSignatureAlgorithm()
		.getSignatureSizeBytes(keySize));
	s.initVerify(kpd.getASymmetricPublicKey());
	s.update(m);
	Assert.assertTrue(s.verify(sign));
    }

    @Test(invocationCount = 1, dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods = "testSecretKeyEncoding")
    public void testSymetricEncryptions(SymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException, NoSuchProviderException, InvalidKeySpecException
    {
	System.out.println("Testing " + type);
	AbstractSecureRandom random = SecureRandomType.DEFAULT.getInstance();
	
	SymmetricSecretKey key = type.getKeyGenerator(random).generateKey();
	
	SymmetricEncryptionAlgorithm algoDistant = new SymmetricEncryptionAlgorithm(
		key, SecureRandomType.DEFAULT, null);
	SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(
		key, SecureRandomType.DEFAULT, null);
		
	Random rand = new Random(System.currentTimeMillis());
	
	for (byte[] m : messagesToEncrypt)
	{
	    byte encrypted[] = algoLocal.encode(m);
	    Assert.assertEquals(encrypted.length,
		    algoLocal.getOutputSizeForEncryption(m.length),
		    "length=" + m.length);
	    
	    Assert.assertTrue(encrypted.length >= m.length);
	    byte decrypted[] = algoDistant.decode(encrypted);
	    Assert.assertEquals(decrypted.length, m.length,
		    "Testing size " + type);
	    Assert.assertEquals(decrypted, m, "Testing " + type);
	    byte[] md = decrypted;
	    Assert.assertEquals(md.length, m.length, "Testing size " + type);
	    Assert.assertEquals(md, m, "Testing " + type);
	    encrypted = algoDistant.encode(m);
	    Assert.assertEquals(encrypted.length,
		    algoDistant.getOutputSizeForEncryption(m.length));
	    Assert.assertTrue(encrypted.length >= m.length);
	    md = algoLocal.decode(encrypted);
	    Assert.assertEquals(md.length, m.length, "Testing size " + type);
	    Assert.assertEquals(md, m, "Testing " + type);

	    int off = rand.nextInt(15);
	    int size = m.length;
	    size -= rand.nextInt(15) + off;

	    encrypted = algoLocal.encode(m, off, size);

	    Assert.assertEquals(encrypted.length,
		    algoLocal.getOutputSizeForEncryption(size));
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
	    Assert.assertEquals(encrypted.length,
		    algoDistant.getOutputSizeForEncryption(size));
	    Assert.assertTrue(encrypted.length >= size);

	    md = algoLocal.decode(encrypted);
	    Assert.assertEquals(md.length, size, "Testing size " + type);
	    for (int i = 0; i < md.length; i++)
		Assert.assertEquals(md[i], m[i + off]);

	}

    }
    
    
    @Test(invocationCount=4000)
    public void testReadWriteDataPackaged() throws NoSuchAlgorithmException, NoSuchProviderException, IOException
    {
	Random rand=new Random(System.currentTimeMillis());
	byte originalBytes[]=new byte[50+rand.nextInt(10000)];
	rand.nextBytes(originalBytes);
	int randNb=rand.nextInt(10000);
	byte encodedBytes[]=OutputDataPackagerWithRandomValues.encode(originalBytes, randNb);
	//Assert.assertTrue(encodedBytes.length>originalBytes.length);
	Assert.assertTrue(encodedBytes.length>=originalBytes.length, "invalid size : "+encodedBytes.length+" (originalBytes size="+originalBytes.length+", randNb="+randNb+") ");
	byte decodedBytes[]=InputDataPackagedWithRandomValues.decode(encodedBytes);
	Assert.assertEquals(decodedBytes.length, originalBytes.length);
	for (int i=0;i<decodedBytes.length;i++)
	    Assert.assertEquals(decodedBytes[i], originalBytes[i]);
    }
    
    
    @Test(invocationCount=100, dataProvider = "provideDataForEllipticCurveDiffieHellmanKeyExchanger", dependsOnMethods = "testMessageDigest")
    public void testEllipticCurveDiffieHellmanKeyExchanger(EllipticCurveDiffieHellmanType type) throws java.security.NoSuchAlgorithmException, java.security.InvalidKeyException, java.security.spec.InvalidKeySpecException, NoSuchAlgorithmException
    {
	EllipticCurveDiffieHellmanAlgorithm peer1=type.getInstance();
	EllipticCurveDiffieHellmanAlgorithm peer2=type.getInstance();
	
	byte[] publicKey1=peer1.generateAndGetPublicKey();
	byte[] publicKey2=peer2.generateAndGetPublicKey();
	peer1.setDistantPublicKey(publicKey2);
	peer2.setDistantPublicKey(publicKey1);
	Assert.assertEquals(peer1.getDerivedKey(), peer2.getDerivedKey());
	
    }

    @DataProvider(name = "provideDataForEllipticCurveDiffieHellmanKeyExchanger", parallel = true)
    public Object[][] provideDataForEllipticCurveDiffieHellmanKeyExchanger()
    {
	Object[][] res=new Object[EllipticCurveDiffieHellmanType.values().length][];
	int index=0;
	for (EllipticCurveDiffieHellmanType type : EllipticCurveDiffieHellmanType.values())
	{
	    res[index]=new Object[1];
	    res[index++][0]=type;
	}
	return res;
    }
    
    
}
