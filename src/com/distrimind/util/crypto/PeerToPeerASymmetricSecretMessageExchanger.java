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
package com.distrimind.util.crypto;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Random;
import java.util.stream.DoubleStream;
import java.util.stream.IntStream;
import java.util.stream.LongStream;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.4.1
 */
public class PeerToPeerASymmetricSecretMessageExchanger
{
    private final PublicKey myPublicKey;
    private final ASymmetricEncryptionType type;
    private PeerToPeerASymmetricSecretMessageExchanger distantMessageEncoder;
    private final FakeSecureRandom random;
    private final Cipher cipher;
    private final MessageDigest messageDigest;
    private final MessageDigestType messageDigestType;
    
    public PeerToPeerASymmetricSecretMessageExchanger(MessageDigestType messageDigestType, ASymmetricEncryptionType aSymmetricEncryptionType, PublicKey myPublicKey, byte[] distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidKeySpecException, InvalidAlgorithmParameterException
    {
	if (aSymmetricEncryptionType==null)
	    throw new NullPointerException("type");
	if (messageDigestType==null)
	    throw new NullPointerException("messageDigestType");
	if (myPublicKey==null)
	    throw new NullPointerException("myPublicKey");
	
	this.type=aSymmetricEncryptionType;
	this.myPublicKey=myPublicKey;

	if (distantPublicKey!=null)
	    setDistantPublicKey(distantPublicKey);
	random=new FakeSecureRandom();
	cipher=getCipherInstancePriv(aSymmetricEncryptionType);
	this.messageDigestType=messageDigestType;
	this.messageDigest=messageDigestType.getMessageDigestInstance();
	this.messageDigest.reset();
    }

    public PeerToPeerASymmetricSecretMessageExchanger(MessageDigestType messageDigestType, ASymmetricEncryptionType aSymmetricEncryptionType, PublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
	this(messageDigestType, aSymmetricEncryptionType, myPublicKey, null);
    }

    public PeerToPeerASymmetricSecretMessageExchanger(ASymmetricEncryptionType aSymmetricEncryptionType, PublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
	this(MessageDigestType.DEFAULT, aSymmetricEncryptionType, myPublicKey);
    }
    public PeerToPeerASymmetricSecretMessageExchanger(PublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, InvalidKeySpecException
    {
	this(ASymmetricEncryptionType.DEFAULT, myPublicKey);
    }
    
    public void setDistantPublicKey(byte[] distantPublicKeyAndIV) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	distantMessageEncoder=new PeerToPeerASymmetricSecretMessageExchanger(messageDigestType, type, ASymmetricEncryptionType.decodePublicKey(distantPublicKeyAndIV));
	if (myPublicKey.equals(distantMessageEncoder.myPublicKey))
	    throw new IllegalArgumentException("Local public key equals distant public key");
    }
    
    public void initCipherForEncrypt(byte data[], int off, int len) throws InvalidKeyException
    {
	messageDigest.update(data, off, len);
	random.setSeed(messageDigest.digest());
	cipher.init(Cipher.ENCRYPT_MODE, myPublicKey, random);
	messageDigest.reset();
    }
    
    public byte[] encodeMyPublicKey()
    {
	return ASymmetricEncryptionType.encodePublicKey(myPublicKey);
    }

    private static Cipher getCipherInstancePriv(ASymmetricEncryptionType type) throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return type.getCipherInstance();
    }

    
    public byte[] encode(byte[] message) throws IOException, InvalidKeyException
    {
	return encode(message, 0, message.length);
    }
    public byte[] encode(byte[] message, int offset, int len) throws IOException, InvalidKeyException
    {
	initCipherForEncrypt(message, offset, len);
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream())
	{
	    try (CipherOutputStream cos=new CipherOutputStream(baos, cipher))
	    {
		cos.write(message, offset, len);
	    }
	    return baos.toByteArray();
	}
    }
    
    public boolean verifyDistantMessage(byte[] originalMessage,byte[] distantMessage) throws InvalidKeyException, IOException, IllegalAccessException
    {
	return this.verifyDistantMessage(originalMessage, 0, originalMessage.length, distantMessage, 0, distantMessage.length);
    }
    
    
    public boolean verifyDistantMessage(byte[] originalMessage, int offo, int leno,byte[] distantMessage, int offd, int lend) throws InvalidKeyException, IOException, IllegalAccessException
    {
	if (distantMessageEncoder==null)
	    throw new IllegalAccessException("You must set the distant public key before calling this function ! ");
	byte[] oc=distantMessageEncoder.encode(originalMessage, offo, leno);
	if (oc.length!=lend)
	    return false;
	for (int i=0;i<lend;i++)
	{
	    if (oc[i]!=distantMessage[i+offd])
		return false;
	}
	return true;
    }
    
    public PublicKey getMyPublicKey()
    {
	return myPublicKey;
    }
    public PublicKey getDistantPublicKey()
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
	@Override
	public IntStream ints(long streamSize) {
	    return random.ints(streamSize);
	}
	@Override
	public IntStream ints() {
	    return random.ints();
	}
	@Override
	public IntStream ints(long streamSize, int randomNumberOrigin, int randomNumberBound)
	{
	    return random.ints(streamSize, randomNumberOrigin, randomNumberBound);
	}
	@Override
	public IntStream ints(int randomNumberOrigin, int randomNumberBound) {
	    return random.ints(randomNumberOrigin, randomNumberBound);
	}
	@Override
	public LongStream longs(long streamSize) {
	    return random.longs(streamSize);
	}
	@Override
	public LongStream longs() {
	    return random.longs();
	}
	@Override
	public LongStream longs(long streamSize, long randomNumberOrigin, long randomNumberBound) {
	    return random.longs(streamSize, randomNumberOrigin, randomNumberBound);
	}
	@Override
	public LongStream longs(long randomNumberOrigin, long randomNumberBound) {
	    return random.longs(randomNumberOrigin, randomNumberBound);
	}
	@Override
	public DoubleStream doubles(long streamSize) {
	    return random.doubles();
	}
	@Override
	public DoubleStream doubles() {
	    return random.doubles();
	}
	@Override
	public DoubleStream doubles(long streamSize, double randomNumberOrigin, double randomNumberBound) {
	    return random.doubles(streamSize, randomNumberOrigin, randomNumberBound);
	}
	@Override
	public DoubleStream doubles(double randomNumberOrigin, double randomNumberBound) {
	    return random.doubles(randomNumberOrigin, randomNumberBound);
	}
    }
    
    protected static BigInteger maxLongValue=BigInteger.valueOf(1).shiftLeft(63);
    
}
