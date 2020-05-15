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

import com.distrimind.util.Bits;
import com.distrimind.util.io.*;

import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;
import java.util.Random;

import javax.crypto.*;


/**
 * 
 * @author Jason Mahdjoub
 * @version 3.1
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {



	private final SymmetricSecretKey key;

	private final SymmetricEncryptionType type;

	private final AbstractSecureRandom random;
	private final byte[] iv;
	
	private final byte blockModeCounterBytes;
	private final boolean internalCounter;
	
	private byte[] externalCounter;

	@Override
	public boolean isPostQuantumEncryption() {
		return key.isPostQuantumKey();
	}
	public SubStreamHashResult getIVAndPartialHashedSubStreamFromEncryptedStream(RandomInputStream encryptedInputStream, SubStreamParameters subStreamParameters) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
		return getIVAndPartialHashedSubStreamFromEncryptedStream(encryptedInputStream, subStreamParameters, null);
	}
	public SubStreamHashResult getIVAndPartialHashedSubStreamFromEncryptedStream(RandomInputStream encryptedInputStream, SubStreamParameters subStreamParameters, byte[] externalCounter) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
		if (!getType().supportRandomReadWrite())
			throw new IllegalStateException("Encryption type must support random read and write");
		if (getMaxBlockSizeForDecoding()!=Integer.MAX_VALUE)
			throw new IllegalAccessError();


		byte[] iv=initIVAndCounter(readIV(encryptedInputStream, externalCounter), externalCounter);
		//initCipherForDecrypt(cipher, iv, externalCounter);
		byte[] hash=subStreamParameters.generateHash(encryptedInputStream);
		return new SubStreamHashResult(hash, iv);
	}
	public boolean checkPartialHashWithNonEncryptedStream(SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters, RandomInputStream nonEncryptedInputStream, byte[] associatedData, int offAD, int lenAD) throws InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, IOException, InvalidKeyException {
		AbstractMessageDigest md=subStreamParameters.getMessageDigestType().getMessageDigestInstance();
		md.reset();
		return checkPartialHashWithNonEncryptedStream(hashResultFromEncryptedStream, subStreamParameters, nonEncryptedInputStream, associatedData, offAD, lenAD, md);
	}
	public static void main(String args[]) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException {
		byte[] iv=new byte[16];
		AbstractSecureRandom random=SecureRandomType.DEFAULT.getInstance(null);
		random.nextBytes(iv);
		SymmetricSecretKey key=SymmetricEncryptionType.AES_CTR.getKeyGenerator(random).generateKey();
		SymmetricEncryptionAlgorithm enc=new SymmetricEncryptionAlgorithm(random, key);
		enc.cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		byte[] message=new byte[10000];
		byte[] encMessage=enc.cipher.doFinal(message);
		int blockSizeBytes=key.getEncryptionAlgorithmType().getBlockSizeBits()/8;
		ByteBuffer biv= ByteBuffer.allocate(blockSizeBytes);
		int indexPos= blockSizeBytes - 4;
		biv.put(iv);
		biv.putInt(indexPos, 12+biv.getInt(indexPos));
		enc.cipher.init(Cipher.ENCRYPT_MODE, key, biv.array());
		byte[] encM2=enc.cipher.doFinal(message, 12*blockSizeBytes, 64);
		for (int i=0;i<encM2.length;i++)
		{
			if (encM2[i]!=encMessage[i+12*blockSizeBytes])
			{
				System.out.println("Failed");
				break;
			}
		}
		System.out.println("Finished");

	}

	public boolean checkPartialHashWithNonEncryptedStream(SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters, RandomInputStream nonEncryptedInputStream, byte[] associatedData, int offAD, int lenAD, AbstractMessageDigest md) throws InvalidKeySpecException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeyException, IOException {
		if (getPlanTextSizeForEncoding()!=Integer.MAX_VALUE)
			throw new IllegalAccessError();

		List<SubStreamParameter> parameters=subStreamParameters.getParameters() ;
		byte[] iv=hashResultFromEncryptedStream.getIv().clone();
		int blockSizeBytes=iv.length;
		if (blockSizeBytes!=key.getEncryptionAlgorithmType().getBlockSizeBits())
			throw new IOException();
		int keySizeBytes=key.getKeySizeBits()/8;
		byte[] buffer=new byte[keySizeBytes*32];
		int indexPos= blockSizeBytes - 4;
		final int counter= Bits.getInt(iv, indexPos);

		for (SubStreamParameter p : parameters)
		{
			long start=p.getStreamStartIncluded();

			if (start<iv.length)
			{
				md.update(hashResultFromEncryptedStream.getIv(), (int)start, (int)(Math.min(hashResultFromEncryptedStream.getIv().length, p.getStreamEndExcluded())-start));
				start=hashResultFromEncryptedStream.getIv().length;
			}
			long l = p.getStreamEndExcluded() - start;
			if (l<=0)
				continue;
			start-=hashResultFromEncryptedStream.getIv().length;

			long startAligned=start/keySizeBytes*keySizeBytes;
			int ivInc=(int)(startAligned/blockSizeBytes);
			nonEncryptedInputStream.seek(startAligned);

			Bits.putInt(iv, indexPos, ivInc +counter);
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			InputStream cis=cipher.getCipherInputStream(nonEncryptedInputStream);
			long toSkip=start-startAligned;
			while(toSkip>0) {
				toSkip-=cis.read(buffer, 0, (int)toSkip);
			}

			do {
				int s = (int) Math.min(buffer.length, l);
				s=cis.read(buffer, 0, s);
				if (s>0)
					md.update(buffer, 0, s);
				if (s<0)
					throw new EOFException();
				l -= s;
			} while(l>0);
		}
		return Arrays.equals(md.digest(), hashResultFromEncryptedStream.getHash());
	}

	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {
		this(random, key, (byte)0, true);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key, byte blockModeCounterBytes)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {
		this(random, key, blockModeCounterBytes, false);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException {
		super(key.getEncryptionAlgorithmType().getCipherInstance(), key.getEncryptionAlgorithmType().getIVSizeBytes());

		this.type = key.getEncryptionAlgorithmType();
		if (internalCounter && type.getMaxCounterSizeInBytesUsedWithBlockMode()<blockModeCounterBytes)
			throw new IllegalArgumentException(type+" cannot manage a internal counter size greater than "+type.getMaxCounterSizeInBytesUsedWithBlockMode());
		if (!internalCounter && blockModeCounterBytes>8)
			throw new IllegalArgumentException("The external counter size can't be greater than 8");
		if (blockModeCounterBytes<0)
			throw new IllegalArgumentException("The external counter size can't be lower than 0");
		this.blockModeCounterBytes = blockModeCounterBytes;
		this.internalCounter = internalCounter || blockModeCounterBytes==0;
		this.key = key;
		this.random = random;
		iv = new byte[getIVSizeBytesWithExternalCounter()];
		externalCounter=this.internalCounter?null:new byte[blockModeCounterBytes];
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key, generateIV());
		
		initBufferAllocatorArgs();
		
	}
	@Override
	public byte getBlockModeCounterBytes() {
		return blockModeCounterBytes;
	}
	@Override
	public boolean useExternalCounter()
	{
		return !internalCounter;
	}

	@Override
	public int getIVSizeBytesWithExternalCounter()
	{
		return type.getIVSizeBytes()-(internalCounter?blockModeCounterBytes:0);
	}	
	
	private byte[] generateIV() {
		random.nextBytes(iv);
		if (!internalCounter)
		{
			int j=0;
			for (int i=iv.length-externalCounter.length;i<iv.length;i++)
			{
				iv[i]=externalCounter[j++];
			}
		}
		return iv;
	}
	
	

	public int getBlockSizeBytes() {
		return cipher.getBlockSize();
	}

	@Override
	public AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		return type.getCipherInstance();
	}

	@Override
	public int getMaxBlockSizeForDecoding() {
		return key.getMaxBlockSize();
	}

	@Override
	public int getPlanTextSizeForEncoding() {
		return key.getMaxBlockSize();
	}
	
	

	
	
	public SymmetricSecretKey getSecretKey() {
		return key;
	}

	public SymmetricEncryptionType getType() {
		return type;
	}

	@Override
	protected boolean includeIV() {
		return true;
	}

	private byte[] initIVAndCounter(byte[] iv, byte[] externalCounter)
	{
		if (!internalCounter && (externalCounter==null || externalCounter.length!=blockModeCounterBytes) && (externalCounter==null?0:externalCounter.length)+iv.length<getIVSizeBytesWithExternalCounter())
			throw new IllegalArgumentException("Please use external counters at every initialization with the defined size "+blockModeCounterBytes);
		if (iv!=null && iv.length<getIVSizeBytesWithoutExternalCounter() && (externalCounter==null || externalCounter.length+iv.length<getIVSizeBytesWithExternalCounter()))
			throw new IllegalArgumentException("Illegal iv size");
		this.externalCounter=externalCounter;

		if (iv != null)
		{
			if (!internalCounter && externalCounter!=null && externalCounter.length!=0 && iv!=this.iv)
			{
				System.arraycopy(iv, 0, this.iv, 0, iv.length);
				int j=0;
				for (int i=iv.length;i<this.iv.length;i++)
				{
					this.iv[i]=externalCounter[j];
				}
				iv=this.iv;
			}
		}
		return iv;
	}

	@Override
	public void initCipherForDecrypt(AbstractCipher cipher, byte[] iv, byte[] externalCounter)
			throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException,
			InvalidKeySpecException, NoSuchProviderException {
		iv=initIVAndCounter(iv, externalCounter);

		if (iv != null)
		{
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		}
		else
			cipher.init(Cipher.DECRYPT_MODE, key);
	}

	@Override
	public byte[] initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) throws InvalidKeyException,
			InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException {
		if (!internalCounter && (externalCounter==null || externalCounter.length!=blockModeCounterBytes))
			throw new IllegalArgumentException("Please use external counters at every initialization with the defined size "+blockModeCounterBytes);
		this.externalCounter=externalCounter;
		byte[] iv=generateIV();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return iv;
	}
	private final Random nonSecureRandom=new Random(System.currentTimeMillis());
	@Override
	public void initCipherForEncryptWithNullIV(AbstractCipher cipher) throws InvalidKeyException,
			NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		nonSecureRandom.nextBytes(nullIV);
		cipher.init(Cipher.ENCRYPT_MODE, key, nullIV);
	}


	@Override
	public void initCipherForDecrypt(AbstractCipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		initCipherForDecrypt(cipher, null, null);
	}

	@Override
	public int getOutputSizeForEncryption(int inputLen) {
		if (includeIV()) {
			return cipher.getOutputSize(inputLen) + getIVSizeBytesWithoutExternalCounter();
		} else {
			return cipher.getOutputSize(inputLen);
		}
	}
}
