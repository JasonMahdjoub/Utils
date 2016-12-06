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
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

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
 * @version 1.4
 * @since Utils 1.4
 */
public class CryptoTests
{
    private static final byte[] messagesToEncrypt[];
    private static final byte salt[];
    static 
    {
	Random rand=new Random(System.currentTimeMillis());
	messagesToEncrypt=new byte[30][];
	for (int i=0;i<messagesToEncrypt.length;i++)
	{
	    byte[] b=new byte[rand.nextInt(50)+10000];
	    for (int j=0;j<b.length;j++)
		b[j]=(byte)rand.nextInt();
		
	    messagesToEncrypt[i]=b;
	}
	salt=new byte[rand.nextInt(10)+30];
	for (int j=0;j<salt.length;j++)
	    salt[j]=(byte)rand.nextInt();
	
    }
    
    @Test(dataProvider = "providePasswordHashTypes")
    public void testPasswordHash(PasswordHashType type) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	SecureRandom random=new SecureRandom();
	PasswordHash ph=new PasswordHash(type, random);
	String password="password";
	String invalidPassword="invalid password";
	byte[] hashedValue=ph.hash(password);
	Assert.assertTrue(ph.checkValidHashedPassword(password, hashedValue));
	Assert.assertFalse(ph.checkValidHashedPassword(invalidPassword, hashedValue));
	byte[] staticSalt=new byte[20];
	random.nextBytes(staticSalt);
	hashedValue=ph.hash(password, staticSalt);
	Assert.assertTrue(ph.checkValidHashedPassword(password, hashedValue, staticSalt));
	Assert.assertFalse(ph.checkValidHashedPassword(password, hashedValue));
	Assert.assertFalse(ph.checkValidHashedPassword(invalidPassword, hashedValue, staticSalt));
    }
    @DataProvider(name = "providePasswordHashTypes", parallel = true)
    public Object[][] providePasswordHashTypes()
    {
	Object[][] res=new Object[PasswordHashType.values().length][1];
	int index=0;
	for (PasswordHashType type : PasswordHashType.values())
	{
	    res[index++][0]=type;
	}
	return res;
    }
    
    
    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods={"testASymmetricKeyPairEncoding"})
    public void testClientServerASymetricEncryptions(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, SignatureException, IllegalBlockSizeException, BadPaddingException
    {
	System.out.println("Testing "+type);
	SecureRandom rand=new SecureRandom();
	ASymmetricKeyPair kp=ASymmetricKeyPair.generate(rand, type);
	ClientASymmetricEncryptionAlgorithm algoClient=new ClientASymmetricEncryptionAlgorithm(kp.getASymmetricPublicKey());
	ServerASymmetricEncryptionAlgorithm algoServer=new ServerASymmetricEncryptionAlgorithm(kp);
	
	for (byte m []: messagesToEncrypt)
	{
	    byte[] encodedBytes=algoClient.encode(m);
	    Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeForEncryption(m.length));
	    byte[] decodedBytes=algoServer.decode(encodedBytes);
	    Assert.assertEquals(m, decodedBytes);
	    byte[] signature=algoServer.getSignerAlgorithm().sign(m);
	    Assert.assertTrue(algoClient.getSignatureCheckerAlgorithm().verify(m, signature));

	    int off=rand.nextInt(15);
	    int size=m.length;
	    size-=rand.nextInt(15)+off;
	    
	    
	    encodedBytes=algoClient.encode(m, off, size);
	    Assert.assertEquals(encodedBytes.length, algoClient.getOutputSizeForEncryption(size));
	    decodedBytes=algoServer.decode(encodedBytes);
	    for (int i=0;i<size;i++)
		Assert.assertEquals(decodedBytes[i], m[i+off]);

	    signature=algoServer.getSignerAlgorithm().sign(m, off, size);
	    Assert.assertTrue(algoClient.getSignatureCheckerAlgorithm().verify(m, off, size, signature, 0, signature.length));
	
	}
	
    }

    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods={"testASymmetricKeyPairEncoding"})
    public void testP2PASymetricEncryptions(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, SignatureException, IllegalBlockSizeException, BadPaddingException
    {
	System.out.println("Testing "+type);
	SecureRandom rand=new SecureRandom();
	ASymmetricKeyPair kpd=ASymmetricKeyPair.generate(rand, type);
	ASymmetricKeyPair kpl=ASymmetricKeyPair.generate(rand, type);
	P2PASymmetricEncryptionAlgorithm algoDistant=new P2PASymmetricEncryptionAlgorithm(kpd, kpl.getASymmetricPublicKey());
	P2PASymmetricEncryptionAlgorithm algoLocal=new P2PASymmetricEncryptionAlgorithm(kpl, kpd.getASymmetricPublicKey());
	
	for (byte m [] : messagesToEncrypt)
	{
	    byte[] encoded=algoLocal.encode(m);
	    Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(m.length));
	    byte md[]=algoDistant.decode(encoded);
	    Assert.assertEquals(md.length, m.length, "Testing size "+type);
	    Assert.assertEquals(md, m, "Testing "+type);
	    
	    encoded=algoDistant.encode(m);
	    Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(m.length));
	    md=algoLocal.decode(encoded);
	    
	    Assert.assertEquals(md.length, m.length, "Testing size "+type);
	    Assert.assertEquals(md, m, "Testing "+type);
	    
	    byte[] sign=algoLocal.getSignerAlgorithm().sign(m);
	    Assert.assertTrue(algoDistant.getSignatureCheckerAlgorithm().verify(m, sign));

	    int off=rand.nextInt(15);
	    int size=m.length;
	    size-=rand.nextInt(15)+off;
	    
	    
	    encoded=algoLocal.encode(m, off, size);
	    Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(size));
	    md=algoDistant.decode(encoded);
	    Assert.assertEquals(md.length, size, "Testing size "+type);
	    for (int i=0;i<size;i++)
		Assert.assertEquals(md[i], m[i+off]);
	    
	    encoded=algoDistant.encode(m, off, size);
	    Assert.assertEquals(encoded.length, algoLocal.getOutputSizeForEncryption(size));
	    md=algoLocal.decode(encoded);
	    
	    Assert.assertEquals(md.length, size, "Testing size "+type);
	    for (int i=0;i<size;i++)
		Assert.assertEquals(md[i], m[i+off]);
	    
	    sign=algoLocal.getSignerAlgorithm().sign(m, off, size);
	    Assert.assertTrue(algoDistant.getSignatureCheckerAlgorithm().verify(m, off, size, sign, 0, sign.length));
	
	}
	
    }

    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods={"testASymmetricKeyPairEncoding"})
    public void testASymmetricSecretMessageExchanger(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalAccessException, InvalidKeySpecException, IllegalBlockSizeException, BadPaddingException
    {
	System.out.println("Testing ASymmetricSecretMessageExchanger "+type);
	SecureRandom rand=new SecureRandom();
	for (short keySize=1024;keySize<=4096;keySize+=1024)
	{
	ASymmetricKeyPair kpd=ASymmetricKeyPair.generate(rand, type, keySize);
	ASymmetricKeyPair kpl=ASymmetricKeyPair.generate(rand, type, keySize);
	
	P2PASymmetricSecretMessageExchanger algoLocal=new P2PASymmetricSecretMessageExchanger(kpl.getASymmetricPublicKey());
	P2PASymmetricSecretMessageExchanger algoDistant=new P2PASymmetricSecretMessageExchanger(kpd.getASymmetricPublicKey());
	algoLocal.setDistantPublicKey(algoDistant.encodeMyPublicKey());
	algoDistant.setDistantPublicKey(algoLocal.encodeMyPublicKey());
	algoLocal.setHashIterationsNumber(1024);
	algoDistant.setHashIterationsNumber(1024);	
	
	byte[] falseMessage=new byte[10];
	rand.nextBytes(falseMessage);
	
	for (byte[] m : messagesToEncrypt)
	{
	    byte[] localCrypt=algoLocal.encode(m, salt, true);
	    Assert.assertTrue(localCrypt.length!=0);
	    Assert.assertTrue(algoDistant.verifyDistantMessage(m, salt, localCrypt, true));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(m, salt, falseMessage, true));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, salt, localCrypt, true));
	    
	    byte[] distantCrypt=algoDistant.encode(m, salt, true);
	    Assert.assertTrue(distantCrypt.length!=0);
	    Assert.assertTrue(algoLocal.verifyDistantMessage(m, salt, distantCrypt, true));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(m, salt, falseMessage, true));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, salt, distantCrypt, true));
	}
	
	for (byte[] m : messagesToEncrypt)
	{
	    byte[] localCrypt=algoLocal.encode(m, salt, false);
	    Assert.assertTrue(localCrypt.length!=0);
	    Assert.assertTrue(algoDistant.verifyDistantMessage(m, salt, localCrypt, false));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(m, salt, falseMessage, false));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, salt, localCrypt, false));
	    
	    byte[] distantCrypt=algoDistant.encode(m, salt, false);
	    Assert.assertTrue(distantCrypt.length!=0);
	    Assert.assertTrue(algoLocal.verifyDistantMessage(m, salt, distantCrypt, false));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(m, salt, falseMessage, false));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, salt, distantCrypt, false));
	}
	for (byte [] m : messagesToEncrypt)
	{
	    byte[] localCrypt=algoLocal.encode(m, null, true);
	    Assert.assertTrue(localCrypt.length!=0);	    
	    Assert.assertTrue(algoDistant.verifyDistantMessage(m, null, localCrypt, true));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(m, null, falseMessage, true));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, null, localCrypt, true));
	    
	    byte[] distantCrypt=algoDistant.encode(m, null, true);
	    Assert.assertTrue(distantCrypt.length!=0);
	    Assert.assertTrue(algoLocal.verifyDistantMessage(m, null, distantCrypt, true));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(m, null, falseMessage, true));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, null, distantCrypt, true));
	}
	for (byte [] m : messagesToEncrypt)
	{
	    byte[] localCrypt=algoLocal.encode(m, null, false);
	    Assert.assertTrue(localCrypt.length!=0);	    
	    Assert.assertTrue(algoDistant.verifyDistantMessage(m, null, localCrypt, false));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(m, null, falseMessage, false));
	    Assert.assertFalse(algoDistant.verifyDistantMessage(falseMessage, null, localCrypt, false));
	    
	    byte[] distantCrypt=algoDistant.encode(m, null, false);
	    Assert.assertTrue(distantCrypt.length!=0);
	    Assert.assertTrue(algoLocal.verifyDistantMessage(m, null, distantCrypt, false));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(m, null, falseMessage, false));
	    Assert.assertFalse(algoLocal.verifyDistantMessage(falseMessage, null, distantCrypt, false));
	}
	String password="password";
	String falsePassword="falsePassword";
	byte[] localCrypt=algoLocal.encode(password, salt);
	Assert.assertTrue(localCrypt.length!=0);
	Assert.assertTrue(algoDistant.verifyDistantMessage(password, salt, localCrypt));
	Assert.assertFalse(algoDistant.verifyDistantMessage(password, salt, falseMessage));
	Assert.assertFalse(algoDistant.verifyDistantMessage(falsePassword, salt, localCrypt));
	    
	byte[] distantCrypt=algoDistant.encode(password, salt);
	Assert.assertTrue(distantCrypt.length!=0);
	Assert.assertTrue(algoLocal.verifyDistantMessage(password, salt, distantCrypt));
	Assert.assertFalse(algoLocal.verifyDistantMessage(password, salt, falseMessage));
	Assert.assertFalse(algoLocal.verifyDistantMessage(falsePassword, salt, distantCrypt));
	
	
	}
    }

    @Test(invocationCount = 20)
    public void testEncodeAndSeparateEncoding()
    {
	Random rand=new Random(System.currentTimeMillis());
	byte[] t1=new byte[rand.nextInt(100)+20];
	byte[] t2=new byte[rand.nextInt(100)+20];
	byte[] encoded=Bits.concateEncodingWithShortSizedTabs(t1, t2);
	byte[][] decoded=Bits.separateEncodingsWithShortSizedTabs(encoded);
	Assert.assertEquals(t1, decoded[0]);
	Assert.assertEquals(t2, decoded[1]);
	encoded=Bits.concateEncodingWithIntSizedTabs(t1, t2);
	decoded=Bits.separateEncodingsWithIntSizedTabs(encoded);
	Assert.assertEquals(t1, decoded[0]);
	Assert.assertEquals(t2, decoded[1]);
    }
    
    @Test(dataProvider = "provideDataForASymetricEncryptions",dependsOnMethods="testEncodeAndSeparateEncoding")
    public void testASymmetricKeyPairEncoding(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	System.out.println("Testing ASymmetricKeyPairEncoding "+type);
	SecureRandom rand=new SecureRandom();
	ASymmetricKeyPair kpd=ASymmetricKeyPair.generate(rand, type);

	
	Assert.assertEquals(ASymmetricPublicKey.decode(kpd.getASymmetricPublicKey().encode()), kpd.getASymmetricPublicKey());
	Assert.assertEquals(ASymmetricPrivateKey.decode(kpd.getASymmetricPrivateKey().encode()), kpd.getASymmetricPrivateKey());
	Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()), kpd);
	Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPrivateKey(), kpd.getASymmetricPrivateKey());
	Assert.assertEquals(ASymmetricKeyPair.decode(kpd.encode()).getASymmetricPublicKey(), kpd.getASymmetricPublicKey());
    }
    
    

    @DataProvider(name = "provideDataForASymetricEncryptions", parallel = true)
    public Object[][] provideDataForASymetricEncryptions()
    {
	Object[][] res=new Object[ASymmetricEncryptionType.values().length][];
	int i=0;
	for (ASymmetricEncryptionType v : ASymmetricEncryptionType.values())
	{
	    Object o[]=new Object[1];
	    o[0]=v;
	    res[i++]=o;
	}
	return res;
    }

    @Test(dataProvider = "provideDataForSignatureTest")
    public void testSignatures(ASymmetricEncryptionType type, SignatureType sigType, int keySize) throws NoSuchAlgorithmException, InvalidKeyException, SignatureException
    {
	System.out.println("Testing signature : "+type+"/"+sigType+"/"+keySize);
	SecureRandom rand=new SecureRandom();
	KeyPair kpd=type.getKeyPairGenerator(rand, (short)keySize).generateKeyPair();
	byte[] m=new byte[10];
	rand.nextBytes(m);
	
	Signature s=sigType.getSignatureInstance();
	s.initSign(kpd.getPrivate());
	s.update(m);
	byte[] sign=s.sign();
	Assert.assertEquals(sign.length, type.getDefaultSignatureAlgorithm().getSignatureSizeBytes(keySize));
	s.initVerify(kpd.getPublic());
	s.update(m);
	Assert.assertTrue(s.verify(sign));
    }
    
    private static int[] keySizes={1024, 2048, 3072, 4096};
    
    @DataProvider(name = "provideDataForSignatureTest", parallel = true)
    public Object[][] provideDataForSignatureTest()
    {
	Object[][] res=new Object[ASymmetricEncryptionType.values().length*SignatureType.values().length*keySizes.length][];
	int i=0;
	for (ASymmetricEncryptionType ast : ASymmetricEncryptionType.values())
	{
	    for (SignatureType st : SignatureType.values())
	    {
		for (int keySize : keySizes)
		{
		    Object o[]=new Object[3];
		    o[0]=ast;
		    o[1]=st;
		    o[2]=new Integer(keySize);
		    res[i++]=o;
		}
	    }
	}
	return res;
    }
    
    
    @Test(invocationCount=10, dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods="testSecretKeyEncoding")
    public void testSymetricEncryptions(SymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	System.out.println("Testing "+type);
	SecureRandom random=new SecureRandom();
	SymmetricSecretKey key=SymmetricSecretKey.generate(random, type);
	
	SymmetricEncryptionAlgorithm algoDistant=new SymmetricEncryptionAlgorithm(key, SecureRandomType.DEFAULT, null);
	SymmetricEncryptionAlgorithm algoLocal=new SymmetricEncryptionAlgorithm(key, SecureRandomType.DEFAULT, null);
	Random rand=new Random(System.currentTimeMillis());
	for (byte[] m : messagesToEncrypt)
	{
	    byte encrypted[]=algoLocal.encode(m);
	    Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(m.length));
	    Assert.assertTrue(encrypted.length>=m.length);
	    byte decrypted[]=algoDistant.decode(encrypted);
	    Assert.assertEquals(decrypted.length, m.length, "Testing size "+type);
	    Assert.assertEquals(decrypted, m, "Testing "+type);
	    byte []md=decrypted;
	    Assert.assertEquals(md.length, m.length, "Testing size "+type);
	    Assert.assertEquals(md, m,"Testing "+type);
	    
	    encrypted=algoDistant.encode(m);
	    Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeForEncryption(m.length));
	    Assert.assertTrue(encrypted.length>=m.length);
	    md=algoLocal.decode(encrypted);
	    Assert.assertEquals(md.length, m.length, "Testing size "+type);
	    Assert.assertEquals(md, m,"Testing "+type);

	    int off=rand.nextInt(15);
	    int size=m.length;
	    size-=rand.nextInt(15)+off;
	    
	    encrypted=algoLocal.encode(m, off, size);
	    Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeForEncryption(size));
	    Assert.assertTrue(encrypted.length>=size);
	    decrypted=algoDistant.decode(encrypted);
	    Assert.assertEquals(decrypted.length, size, "Testing size "+type);
	    for (int i=0;i<decrypted.length;i++)
		Assert.assertEquals(decrypted[i], m[i+off]);
	    
	    md=algoDistant.decode(encrypted);
	    
	    Assert.assertEquals(md.length, size, "Testing size "+type);
	    for (int i=0;i<md.length;i++)
		Assert.assertEquals(md[i], m[i+off]);
	    
	    encrypted=algoDistant.encode(m, off, size);
	    Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeForEncryption(size));
	    Assert.assertTrue(encrypted.length>=size);
	    md=algoLocal.decode(encrypted);
	    Assert.assertEquals(md.length, size, "Testing size "+type);
	    for (int i=0;i<md.length;i++)
		Assert.assertEquals(md[i], m[i+off]);

	
	}
	
    }
    @Test(dataProvider = "provideDataForSymetricEncryptions",dependsOnMethods="testEncodeAndSeparateEncoding")
    public void testSecretKeyEncoding(SymmetricEncryptionType type) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
	System.out.println("Testing "+type);
	SecureRandom random=new SecureRandom();
	SymmetricSecretKey key=SymmetricSecretKey.generate(random, type);
	Assert.assertEquals(SymmetricSecretKey.decode(key.encode()), key);
	new SymmetricEncryptionAlgorithm(key, SecureRandomType.DEFAULT, null);
	Assert.assertEquals(SymmetricSecretKey.decode(key.encode()), key);
	
    }
    
    @DataProvider(name = "provideDataForSymetricEncryptions", parallel = true)
    public Object[][] provideDataForSymetricEncryptions()
    {
	Object[][] res=new Object[SymmetricEncryptionType.values().length][];
	int i=0;
	for (SymmetricEncryptionType v : SymmetricEncryptionType.values())
	{
	    Object o[]=new Object[1];
	    o[0]=v;
	    res[i++]=o;
	}
	return res;
    }

    @Test(dataProvider = "provideDataForHybridEncryptions", dependsOnMethods={"testSymetricEncryptions", "testP2PASymetricEncryptions"})
    public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	System.out.println("Testing "+astype+"/"+stype);
	SecureRandom rand=new SecureRandom();
	ASymmetricKeyPair kpd=ASymmetricKeyPair.generate(rand, astype);
	ASymmetricKeyPair kpl=ASymmetricKeyPair.generate(rand, astype);
	
	P2PASymmetricEncryptionAlgorithm algoDistantAS=new P2PASymmetricEncryptionAlgorithm(kpd, kpl.getASymmetricPublicKey());
	P2PASymmetricEncryptionAlgorithm algoLocalAS=new P2PASymmetricEncryptionAlgorithm(kpl, kpd.getASymmetricPublicKey());
	
	
	SymmetricSecretKey localKey=SymmetricSecretKey.generate(rand, stype);

	SymmetricEncryptionAlgorithm algoLocalS=new SymmetricEncryptionAlgorithm(localKey, SecureRandomType.DEFAULT, null);
	byte[] localEncryptedKey=algoLocalS.encodeKey(algoLocalAS);
	SymmetricEncryptionAlgorithm algoDistantS=SymmetricEncryptionAlgorithm.getInstance(SecureRandomType.DEFAULT, null, localEncryptedKey, algoDistantAS);
	
	
	for (byte[] m : messagesToEncrypt)
	{
	    byte[] md=algoDistantS.decode(algoLocalS.encode(m));
	    Assert.assertEquals(md.length, m.length, "Testing size "+astype+"/"+stype);
	    Assert.assertEquals(md, m,"Testing "+astype+"/"+stype);
	    
	    md=algoLocalS.decode(algoDistantS.encode(m));
	    Assert.assertEquals(md.length, m.length, "Testing size "+astype+"/"+stype);
	    Assert.assertEquals(md, m,"Testing "+astype+"/"+stype);
	}
	
    }
    
    @DataProvider(name = "provideDataForHybridEncryptions", parallel = true)
    public Object[][] provideDataForHybridEncryptions()
    {
	Object[][] res=new Object[SymmetricEncryptionType.values().length*ASymmetricEncryptionType.values().length][];
	int i=0;
	for (SymmetricEncryptionType vS : SymmetricEncryptionType.values())
	{
	    for (ASymmetricEncryptionType vAS : ASymmetricEncryptionType.values())
	    {
		Object o[]=new Object[2];
		o[0]=vAS;
		o[1]=vS;
		res[i++]=o;
	    }
	}
	return res;
    }
    
    @Test(dataProvider = "provideMessageDigestType")
    public void testMessageDigest(MessageDigestType type) throws NoSuchAlgorithmException
    {
	System.out.println("Testing message digest "+type);
	
	MessageDigest md=type.getMessageDigestInstance();
	for (byte[] m : messagesToEncrypt)
	{
	    byte b1[]=md.digest(m);
	    md.reset();
	    byte b2[]=md.digest(m);
	    Assert.assertEquals(b1, b2);
	}
	
    }
    
    @DataProvider(name = "provideMessageDigestType", parallel = true)
    public Object[][] provideMessageDigestType()
    {
	Object[][] res=new Object[MessageDigestType.values().length][];
	int i=0;
	for (MessageDigestType v : MessageDigestType.values())
	{
	    Object o[]=new Object[1];
	    o[0]=v;
	    res[i++]=o;
	}
	return res;
    }
    
    
}
