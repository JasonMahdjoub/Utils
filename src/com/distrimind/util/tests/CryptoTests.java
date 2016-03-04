/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package com.distrimind.util.tests;

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

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.distrimind.util.Bits;
import com.distrimind.util.crypto.ASymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.ASymmetricEncryptionType;
import com.distrimind.util.crypto.PeerToPeerASymmetricSecretMessageExchanger;
import com.distrimind.util.crypto.MessageDigestType;
import com.distrimind.util.crypto.SignatureType;
import com.distrimind.util.crypto.SymmetricEncryptionAlgorithm;
import com.distrimind.util.crypto.SymmetricEncryptionType;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 1.4
 */
public class CryptoTests
{
    private static final String messagesToEncrypt[]={"sdfknhdfikdng dlkg nfsdkijng ", "edfknz gfjét  ", "dfkjndeifhzreufghbergerjognbvolserdbgnv"};
    
    
    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods={"testASymmetricKeyPairEncoding"})
    public void testASymetricEncryptions(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, SignatureException
    {
	System.out.println("Testing "+type);
	SecureRandom rand=new SecureRandom();
	KeyPair kpd=type.getKeyPairGenerator(rand).generateKeyPair();
	KeyPair kpl=type.getKeyPairGenerator(rand).generateKeyPair();
	ASymmetricEncryptionAlgorithm algoDistant=new ASymmetricEncryptionAlgorithm(type, kpd, kpl.getPublic());
	ASymmetricEncryptionAlgorithm algoLocal=new ASymmetricEncryptionAlgorithm(type, kpl, kpd.getPublic());
	
	for (String m : messagesToEncrypt)
	{
	    String md=new String(algoDistant.decode(algoLocal.encode(m.getBytes())));
	    Assert.assertEquals(md.length(), m.length(), "Testing size "+type);
	    Assert.assertEquals(md, m, "Testing "+type);
	    
	    md=new String(algoLocal.decode(algoDistant.encode(m.getBytes())));
	    Assert.assertEquals(md.length(), m.length(), "Testing size "+type);
	    Assert.assertEquals(md, m, "Testing "+type);
	    
	    byte[] sign=algoLocal.sign(m.getBytes());
	    Assert.assertTrue(algoDistant.verify(m.getBytes(), sign));
	}
	
    }

    @Test(dataProvider = "provideDataForASymetricEncryptions", dependsOnMethods={"testASymmetricKeyPairEncoding"})
    public void testASymmetricSecretMessageExchanger(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalAccessException, InvalidKeySpecException
    {
	System.out.println("Testing ASymmetricSecretMessageExchanger "+type);
	SecureRandom rand=new SecureRandom();
	KeyPair kpd=type.getKeyPairGenerator(rand).generateKeyPair();
	KeyPair kpl=type.getKeyPairGenerator(rand).generateKeyPair();
	
	PeerToPeerASymmetricSecretMessageExchanger algoLocal=new PeerToPeerASymmetricSecretMessageExchanger(type, kpl.getPublic());
	PeerToPeerASymmetricSecretMessageExchanger algoDistant=new PeerToPeerASymmetricSecretMessageExchanger(type, kpd.getPublic());
	algoLocal.setDistantPublicKey(algoDistant.encodeMyPublicKey());
	algoDistant.setDistantPublicKey(algoLocal.encodeMyPublicKey());
	
	
	
	for (String m : messagesToEncrypt)
	{
	    byte[] localCrypt=algoLocal.encode(m.getBytes());
	    Assert.assertTrue(algoDistant.verifyDistantMessage(m.getBytes(), localCrypt));
	    
	    byte[] distantCrypt=algoDistant.encode(m.getBytes());
	    Assert.assertTrue(algoLocal.verifyDistantMessage(m.getBytes(), distantCrypt));
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
	KeyPair kpd=type.getKeyPairGenerator(rand).generateKeyPair();
	
	Assert.assertEquals(ASymmetricEncryptionType.decodePublicKey(ASymmetricEncryptionType.encodePublicKey(kpd.getPublic())), kpd.getPublic());
	Assert.assertEquals(ASymmetricEncryptionType.decodePrivateKey(ASymmetricEncryptionType.encodePrivateKey(kpd.getPrivate())), kpd.getPrivate());
	KeyPair decodedkp=ASymmetricEncryptionType.decodeKeyPair(ASymmetricEncryptionType.encodeKeyPair(kpd));
	Assert.assertEquals(decodedkp.getPrivate(), kpd.getPrivate());
	Assert.assertEquals(decodedkp.getPublic(), kpd.getPublic());
    }
    
    

    @DataProvider(name = "provideDataForASymetricEncryptions")
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
	KeyPair kpd=type.getKeyPairGenerator(rand, keySize).generateKeyPair();
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
    
    @DataProvider(name = "provideDataForSignatureTest")
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
    
    
    @Test(dataProvider = "provideDataForSymetricEncryptions", dependsOnMethods="testSecretKeyEncoding")
    public void testSymetricEncryptions(SymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	System.out.println("Testing "+type);
	SecretKey key=type.getKeyGenerator(new SecureRandom()).generateKey();
	
	SymmetricEncryptionAlgorithm algoDistant=new SymmetricEncryptionAlgorithm(type,  key, new SecureRandom());
	SymmetricEncryptionAlgorithm algoLocal=new SymmetricEncryptionAlgorithm(type,key, new SecureRandom(), algoDistant.getIV());
	
	for (String m : messagesToEncrypt)
	{
	    byte encrypted[]=algoLocal.encode(m.getBytes());
	    Assert.assertEquals(encrypted.length, algoLocal.getOutputSize(m.getBytes().length));
	    Assert.assertTrue(encrypted.length>=m.getBytes().length);
	    byte decrypted[]=algoDistant.decode(encrypted);
	    Assert.assertEquals(decrypted.length, m.getBytes().length, "Testing size "+type);
	    Assert.assertEquals(decrypted, m.getBytes(), "Testing "+type);
	    String md=new String(algoDistant.decode(encrypted));
	    Assert.assertEquals(md.length(), m.length(), "Testing size "+type);
	    Assert.assertEquals(md, m,"Testing "+type);
	    
	    encrypted=algoDistant.encode(m.getBytes());
	    Assert.assertEquals(encrypted.length, algoDistant.getOutputSize(m.getBytes().length));
	    Assert.assertTrue(encrypted.length>=m.getBytes().length);
	    md=new String(algoLocal.decode(encrypted));
	    Assert.assertEquals(md.length(), m.length(), "Testing size "+type);
	    Assert.assertEquals(md, m,"Testing "+type);
	}
	
    }
    @Test(dataProvider = "provideDataForSymetricEncryptions",dependsOnMethods="testEncodeAndSeparateEncoding")
    public void testSecretKeyEncoding(SymmetricEncryptionType type) throws NoSuchAlgorithmException
    {
	System.out.println("Testing "+type);
	SecretKey key=type.getKeyGenerator(new SecureRandom()).generateKey();
	
	Assert.assertEquals(SymmetricEncryptionType.decodeSecretKey(SymmetricEncryptionType.encodeSecretKey(key)), key);
	
    }
    
    @DataProvider(name = "provideDataForSymetricEncryptions")
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

    @Test(dataProvider = "provideDataForHybridEncryptions", dependsOnMethods={"testSymetricEncryptions", "testASymetricEncryptions"})
    public void testHybridEncryptions(ASymmetricEncryptionType astype, SymmetricEncryptionType stype) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	System.out.println("Testing "+astype+"/"+stype);
	SecureRandom rand=new SecureRandom();
	KeyPair kpd=astype.getKeyPairGenerator(rand).generateKeyPair();
	KeyPair kpl=astype.getKeyPairGenerator(rand).generateKeyPair();
	
	ASymmetricEncryptionAlgorithm algoDistantAS=new ASymmetricEncryptionAlgorithm(astype, kpd, kpl.getPublic());
	ASymmetricEncryptionAlgorithm algoLocalAS=new ASymmetricEncryptionAlgorithm(astype, kpl, kpd.getPublic());
	
	
	SecretKey localKey=stype.getKeyGenerator(new SecureRandom()).generateKey();

	SymmetricEncryptionAlgorithm algoLocalS=new SymmetricEncryptionAlgorithm(stype, localKey, rand);
	byte[] localEncryptedKey=algoLocalS.encodeKeyAndIvParameter(algoLocalAS);
	SymmetricEncryptionAlgorithm algoDistantS=SymmetricEncryptionAlgorithm.getInstance(stype, rand, localEncryptedKey, algoDistantAS);
	
	
	for (String m : messagesToEncrypt)
	{
	    String md=new String(algoDistantS.decode(algoLocalS.encode(m.getBytes())));
	    Assert.assertEquals(md.length(), m.length(), "Testing size "+astype+"/"+stype);
	    Assert.assertEquals(md, m,"Testing "+astype+"/"+stype);
	    
	    md=new String(algoLocalS.decode(algoDistantS.encode(m.getBytes())));
	    Assert.assertEquals(md.length(), m.length(), "Testing size "+astype+"/"+stype);
	    Assert.assertEquals(md, m,"Testing "+astype+"/"+stype);
	}
	
    }
    
    @DataProvider(name = "provideDataForHybridEncryptions")
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
	for (String m : messagesToEncrypt)
	{
	    byte b1[]=md.digest(m.getBytes());
	    md.reset();
	    byte b2[]=md.digest(m.getBytes());
	    Assert.assertEquals(b1, b2);
	}
	
    }
    
    @DataProvider(name = "provideMessageDigestType")
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
