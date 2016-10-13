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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 1.3
 * @since Utils 1.4.1
 */
public class P2PASymmetricSecretMessageExchanger
{
    private final ASymmetricPublicKey myPublicKey;
    private final ASymmetricEncryptionType type;
    private P2PASymmetricSecretMessageExchanger distantMessageEncoder;
    private final FakeSecureRandom random;
    private final Cipher cipher;
    private final MessageDigest messageDigest;
    private final MessageDigestType messageDigestType;
    private final PasswordHashType passwordHashType;
    private int hashIterationsNumber=PasswordHash.DEFAULT_NB_ITERATIONS;
    public int getHashIterationsNumber()
    {
        return hashIterationsNumber;
    }

    public void setHashIterationsNumber(int _hashIterationsNumber)
    {
        hashIterationsNumber = _hashIterationsNumber;
        if (distantMessageEncoder!=null)
            distantMessageEncoder.setHashIterationsNumber(_hashIterationsNumber);
    }

    public P2PASymmetricSecretMessageExchanger(MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey, byte[] distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException
    {
	if (messageDigestType==null)
	    throw new NullPointerException("messageDigestType");
	if (myPublicKey==null)
	    throw new NullPointerException("myPublicKey");
	if (passwordHashType==null)
	    throw new NullPointerException("passwordHashType");
	this.type=myPublicKey.getAlgorithmType();
	this.myPublicKey=myPublicKey;

	if (distantPublicKey!=null)
	    setDistantPublicKey(distantPublicKey);
	random=new FakeSecureRandom();
	cipher=getCipherInstancePriv(type);
	this.messageDigestType=messageDigestType;
	this.messageDigest=messageDigestType.getMessageDigestInstance();
	this.messageDigest.reset();
	this.passwordHashType=passwordHashType;
    }

    public P2PASymmetricSecretMessageExchanger(MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
	this(messageDigestType, passwordHashType, myPublicKey, null);
    }

    public P2PASymmetricSecretMessageExchanger(ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
	this(MessageDigestType.SHA_512, PasswordHashType.DEFAULT, myPublicKey);
    }
    
    public void setDistantPublicKey(byte[] distantPublicKeyAndIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	distantMessageEncoder=new P2PASymmetricSecretMessageExchanger(messageDigestType, passwordHashType, ASymmetricPublicKey.decode(distantPublicKeyAndIV));
	if (myPublicKey.equals(distantMessageEncoder.myPublicKey))
	    throw new IllegalArgumentException("Local public key equals distant public key");
	distantMessageEncoder.setHashIterationsNumber(getHashIterationsNumber());
    }
    
    private byte[] hashMessage(byte data[], int off, int len, byte[] salt, int offset_salt, int len_salt, boolean messageIsKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (!messageIsKey && salt!=null && len_salt>0)
	{
	    byte s[]=new byte[len_salt];
	    System.arraycopy(salt, offset_salt, s, 0, len_salt);
	    data=passwordHashType.hash(data, off, len, s, hashIterationsNumber);
	    off=0;
	    len=data.length;
	}
	messageDigest.update(data, off, len);
	if (messageIsKey && salt!=null && len_salt>0)
	    messageDigest.update(salt, offset_salt, len_salt);
	return messageDigest.digest();
    }
    
    private byte[] hashMessage(char password[], byte[] salt, int offset_salt, int len_salt) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (salt==null)
	    throw new NullPointerException("salt can't be null when the message is a password (and not a secret key) !");
	if (salt.length==0)
	    throw new NullPointerException("salt can't be empty when the message is a password (and not a secret key) !");
	
	if (salt!=null && len_salt>0)
	{
	    byte s[]=new byte[len_salt];
	    System.arraycopy(salt, offset_salt, s, 0, len_salt);
	    byte[] res=passwordHashType.hash(password, s, hashIterationsNumber);
	    return hashMessage(res, 0, res.length, null, -1, -1, true);
	}
	else
	{
	    byte[] res=new byte[password.length*2];
	    for (int i=0;i<password.length;i++)
	    {
		res[i*2]=(byte)(password[i] & 0xFF);
		res[i*2+1]=(byte)((password[i]>>8) & 0xFF);
	    }
	    return res;
	}
	    
    }
    
    private void initCipherForEncrypt(byte hashedMessage[]) throws InvalidKeyException
    {
	random.setSeed(hashedMessage);
	cipher.init(Cipher.ENCRYPT_MODE, myPublicKey.getPublicKey(), random);
	messageDigest.reset();
    }
    
    public byte[] encodeMyPublicKey()
    {
	return myPublicKey.encode();
    }

    private static Cipher getCipherInstancePriv(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return type.getCipherInstance();
    }

    
    public byte[] encode(byte[] message, byte[] salt, boolean messageIsKey) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (salt==null)
	    salt=new byte[0];
	return encode(message, 0, message.length, salt, 0, salt.length, messageIsKey);
    }
    public byte[] encode(byte[] message, int offset, int len, byte[] salt, int offset_salt, int len_salt, boolean messageIsKey) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (message==null)
	    throw new NullPointerException("message");
	if (message.length-offset<len)
	    throw new IllegalArgumentException("message");
	if (salt!=null && salt.length-offset_salt<len_salt)
	    throw new IllegalArgumentException("salt");
	
	message=hashMessage(message, offset, len, salt, offset_salt, len_salt, messageIsKey);
	initCipherForEncrypt(message);
	
	int maxBlockSize=myPublicKey.getMaxBlockSize();
	
	boolean finish=false;
	offset=0;
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream())
	{
	    while (!finish)
	    {
	    
		int size=Math.min(maxBlockSize, message.length-offset);
		if (size>0)
		{
		    baos.write(cipher.doFinal(message, offset, size));
		    offset+=size;
		}
		if (size<=0)
		    finish=true;
	    }
	    baos.flush();
	    return baos.toByteArray();
	}
	
    }
    public byte[] encode(String message, byte[] salt) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	return encode(message.toCharArray(), salt);
    }
    public byte[] encode(char[] message, byte[] salt) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (salt==null)
	    salt=new byte[0];
	return encode(message, salt, 0, salt.length);
    }
    public byte[] encode(String message, byte[] salt, int offset_salt, int len_salt) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	return encode(message.toCharArray(), salt, offset_salt, len_salt);
    }
    public byte[] encode(char[] message, byte[] salt, int offset_salt, int len_salt) throws IOException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (message==null)
	    throw new NullPointerException("message");
	if (salt==null)
	{
	    salt=new byte[0];
	    offset_salt=0;
	    len_salt=0;
	}
	if (salt.length-offset_salt<len_salt)
	    throw new IllegalArgumentException("salt");
	
	byte hashedMessage[]=hashMessage(message, salt, offset_salt, len_salt);
	initCipherForEncrypt(hashedMessage);
	
	int maxBlockSize=myPublicKey.getMaxBlockSize();
	
	boolean finish=false;
	int offset=0;
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream())
	{
	    while (!finish)
	    {
	    
		int size=Math.min(maxBlockSize, hashedMessage.length-offset);
		if (size>0)
		{
		    baos.write(cipher.doFinal(hashedMessage, offset, size));
		    offset+=size;
		}
		if (size<=0)
		    finish=true;
	    }
	    baos.flush();
	    return baos.toByteArray();
	}
	
    }
    
    public boolean verifyDistantMessage(byte[] originalMessage, byte[] salt,byte[] distantMessage, boolean messageIsKey) throws InvalidKeyException, IOException, IllegalAccessException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (salt==null)
	    salt=new byte[0];
	return this.verifyDistantMessage(originalMessage, 0, originalMessage.length, salt, 0, salt.length, distantMessage, 0, distantMessage.length, messageIsKey);
    }
    public boolean verifyDistantMessage(char[] originalMessage, byte[] salt,byte[] distantMessage) throws InvalidKeyException, IOException, IllegalAccessException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (salt==null)
	    salt=new byte[0];
	return this.verifyDistantMessage(originalMessage, salt, 0, salt.length, distantMessage, 0, distantMessage.length);
    }
    public boolean verifyDistantMessage(String originalMessage, byte[] salt,byte[] distantMessage) throws InvalidKeyException, IOException, IllegalAccessException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	return this.verifyDistantMessage(originalMessage.toCharArray(), salt, distantMessage);
    }
    
    public boolean verifyDistantMessage(char[] originalMessage, byte[] salt, int offset_salt, int len_salt,byte[] distantMessage, int offd, int lend) throws InvalidKeyException, IOException, IllegalAccessException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (originalMessage==null)
	    throw new NullPointerException("message");
	if (distantMessage==null)
	    throw new NullPointerException("distantMessage");
	if (distantMessage.length-offd<lend)
	    throw new IllegalArgumentException("distantMessage");
	if (salt==null)
	{
	    salt=new byte[0];
	    offset_salt=0;
	    len_salt=0;
	}
	if (salt.length-offset_salt<len_salt)
	    throw new IllegalArgumentException("salt");

	if (distantMessageEncoder==null)
	    throw new IllegalAccessException("You must set the distant public key before calling this function ! ");
	byte[] oc=distantMessageEncoder.encode(originalMessage, salt, offset_salt, len_salt);
	if (oc.length!=lend)
	    return false;
	for (int i=0;i<lend;i++)
	{
	    if (oc[i]!=distantMessage[i+offd])
		return false;
	}
	return true;
    }
    
    public boolean verifyDistantMessage(byte[] originalMessage, int offo, int leno, byte[] salt, int offset_salt, int len_salt,byte[] distantMessage, int offd, int lend, boolean messageIsKey) throws InvalidKeyException, IOException, IllegalAccessException, IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	if (originalMessage==null)
	    throw new NullPointerException("message");
	if (originalMessage.length-offo<leno)
	    throw new IllegalArgumentException("message");
	if (distantMessage==null)
	    throw new NullPointerException("distantMessage");
	if (distantMessage.length-offd<lend)
	    throw new IllegalArgumentException("distantMessage");
	if (salt==null)
	{
	    salt=new byte[0];
	    offset_salt=0;
	    len_salt=0;
	}
	if (salt.length-offset_salt<len_salt)
	    throw new IllegalArgumentException("salt");

	if (distantMessageEncoder==null)
	    throw new IllegalAccessException("You must set the distant public key before calling this function ! ");
	byte[] oc=distantMessageEncoder.encode(originalMessage, offo, leno, salt, offset_salt, len_salt, messageIsKey);
	
	if (oc.length!=lend)
	    return false;
	for (int i=0;i<lend;i++)
	{
	    if (oc[i]!=distantMessage[i+offd])
		return false;
	}
	return true;
    }
    
    public ASymmetricPublicKey getMyPublicKey()
    {
	return myPublicKey;
    }
    public ASymmetricPublicKey getDistantPublicKey()
    {
	if (distantMessageEncoder==null)
	    return null;
	return this.distantMessageEncoder.getMyPublicKey();
    }
    
    protected static class FakeSecureRandom extends SecureRandom
    {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3862260428441022619L;
	
	private Random random=null;
	
	protected FakeSecureRandom()
	{
	    random=new Random();
	}
	
	@Override
	public String getAlgorithm() {
	    return "Fake Secure Random";
	}
	
	@Override
	public void setSeed(byte[] seed) 
	{
	    BigInteger num=new BigInteger(seed);
	    random.setSeed(num.mod(maxLongValue).longValue());
	}
	
	@Override
	public void setSeed(long seed) {
	    if (random!=null)
		random.setSeed(seed);
	}
	
	@Override
	synchronized public void nextBytes(byte[] bytes) {
	    random.nextBytes(bytes);
	}
	
	@Override
	public byte[] generateSeed(int numBytes) {
	    return null;
	}
	
	@Override
	public int nextInt() {
	    return random.nextInt();
	}
	
	@Override
	public int nextInt(int bound) {
	    return random.nextInt(bound);
	}
	
	@Override
	public long nextLong() {
	    return random.nextLong();
	}
	
	@Override
	public boolean nextBoolean() {
	    return random.nextBoolean();
	}
	@Override
	public float nextFloat() {
	    return random.nextFloat();
	}
	@Override
	public double nextDouble() {
	    return random.nextDouble();
	}
	@Override
	public double nextGaussian() {
	    return random.nextGaussian();
	}
    }
    
    protected static BigInteger maxLongValue=BigInteger.valueOf(1).shiftLeft(63);
    
}
