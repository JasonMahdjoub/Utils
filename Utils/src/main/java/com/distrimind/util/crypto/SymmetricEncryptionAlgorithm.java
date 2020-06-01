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

import com.distrimind.util.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.List;


/**
 * 
 * @author Jason Mahdjoub
 * @version 4.0
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {

	private final SymmetricSecretKey key;

	private final SymmetricEncryptionType type;

	private final AbstractSecureRandom random;
	//private byte[] iv;
	
	private final byte blockModeCounterBytes;
	private final boolean internalCounter;
	
	private byte[] externalCounter;
	private final int counterStepInBytes;
	private final boolean supportRandomReadWrite;
	private final boolean chacha;
	private final boolean gcm;

	@Override
	public boolean isPostQuantumEncryption() {
		return key.isPostQuantumKey();
	}
	public SubStreamHashResult getIVAndPartialHashedSubStreamFromEncryptedStream(RandomInputStream encryptedInputStream, SubStreamParameters subStreamParameters) throws IOException {
		return getIVAndPartialHashedSubStreamFromEncryptedStream(encryptedInputStream, subStreamParameters, null);
	}
	public SubStreamHashResult getIVAndPartialHashedSubStreamFromEncryptedStream(RandomInputStream encryptedInputStream, SubStreamParameters subStreamParameters, byte[] externalCounter) throws IOException {
		if (!getType().supportRandomReadWrite())
			throw new IllegalStateException("Encryption type must support random read and write");
		try {
			byte[] hash = subStreamParameters.generateHash(encryptedInputStream);
			return new SubStreamHashResult(hash, readIvsFromEncryptedStream(encryptedInputStream));
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}

	}
	public boolean checkPartialHashWithNonEncryptedStream(SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters, RandomInputStream nonEncryptedInputStream, byte[] associatedData, int offAD, int lenAD) throws IOException{
		try {
			AbstractMessageDigest md = subStreamParameters.getMessageDigestType().getMessageDigestInstance();
			md.reset();
			return checkPartialHashWithNonEncryptedStream(hashResultFromEncryptedStream, subStreamParameters, nonEncryptedInputStream, associatedData, offAD, lenAD, md);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}

	}
	public static void main(String[] args) throws NoSuchProviderException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException {
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

	private void partialHash(RandomInputStream nonEncryptedInputStream, NullRandomOutputStream nullStream, AbstractMessageDigest nullMD, AbstractMessageDigest md, HashRandomOutputStream hashOut, RandomOutputStream os, long pos, long len) throws IOException {
		long mod=pos%maxEncryptedPartLength;
		if (mod>0)
			mod-=getIVSizeBytesWithoutExternalCounter();
		assert mod>=0;
		pos=(pos/maxEncryptedPartLength)*maxPlainTextSizeForEncoding+mod;
		long p=(pos/getCounterStepInBytes())*getCounterStepInBytes();
		long off=pos-p;
		nonEncryptedInputStream.seek(p);
		os.seek(p);
		if (off>0)
		{
			hashOut.set(nullStream, nullMD);
			nonEncryptedInputStream.transferTo(os, off);
		}
		hashOut.set(nullStream, md);
		nonEncryptedInputStream.transferTo(os, len);
	}

	public boolean checkPartialHashWithNonEncryptedStream(SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters,
														  RandomInputStream nonEncryptedInputStream, byte[] associatedData, int offAD, int lenAD,
														  AbstractMessageDigest md) throws IOException, NoSuchProviderException {

		List<SubStreamParameter> parameters = subStreamParameters.getParameters();
		byte[][] ivs = hashResultFromEncryptedStream.getIvs();
		for (byte[] iv : ivs)
			if (iv.length != key.getEncryptionAlgorithmType().getIVSizeBytes())
				throw new IOException();

		final int ivSizeWithoutExternalCounter=getIVSizeBytesWithoutExternalCounter();
		NullRandomOutputStream nullStream=new NullRandomOutputStream();
		nullStream.setLength(getOutputSizeAfterEncryption(nonEncryptedInputStream.length()));
		AbstractMessageDigest nullMD;
		HashRandomOutputStream hashOut;
		try {
			nullMD=MessageDigestType.DEFAULT.getMessageDigestInstance();
			hashOut=new HashRandomOutputStream(nullStream, nullMD);
		} catch (NoSuchAlgorithmException e) {
			throw new IOException(e);
		}


		try(RandomOutputStream os= getCipherOutputStreamForEncryption(hashOut, false, associatedData, offAD, lenAD, null, ivs)) {

			for (SubStreamParameter p : parameters) {
				long start = p.getStreamStartIncluded();
				long end = p.getStreamEndExcluded();
				int round = (int) (end / maxEncryptedPartLength);
				long startIV = round * maxEncryptedPartLength;
				long endIV = startIV + ivSizeWithoutExternalCounter;
				if (start < startIV) {
					partialHash(nonEncryptedInputStream, nullStream, nullMD, md, hashOut, os, start, startIV - start);
					if (end > startIV) {
						md.update(ivs[round], 0, (int) Math.min(end - startIV, ivSizeWithoutExternalCounter));
					}
				} else if (start < endIV) {
					int off = (int) (startIV - start);
					md.update(ivs[round], off, (int) Math.min(end - startIV, ivSizeWithoutExternalCounter - off));
				}
				if (end > endIV) {
					start = Math.max(endIV, start);
					partialHash(nonEncryptedInputStream, nullStream, nullMD, md, hashOut, os, start, end - start);
				}
			}
			return Arrays.equals(md.digest(), hashResultFromEncryptedStream.getHash());
		}
	}

	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key)
			throws IOException {
		this(random, key, (byte)0, true);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key, byte blockModeCounterBytes)
			throws IOException {
		this(random, key, blockModeCounterBytes, false);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom random, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter)
			throws IOException {
		super(key.getEncryptionAlgorithmType().getCipherInstance(), key.getEncryptionAlgorithmType().getIVSizeBytes());

		this.type = key.getEncryptionAlgorithmType();
		/*if (internalCounter && type.getMaxCounterSizeInBytesUsedWithBlockMode()<blockModeCounterBytes)
			throw new IllegalArgumentException(type+" cannot manage a internal counter size greater than "+type.getMaxCounterSizeInBytesUsedWithBlockMode());*/
		if (!internalCounter && blockModeCounterBytes>type.getMaxCounterSizeInBytesUsedWithBlockMode())
			throw new IllegalArgumentException("The external counter size can't be greater than "+type.getMaxCounterSizeInBytesUsedWithBlockMode());
		if (blockModeCounterBytes<0)
			throw new IllegalArgumentException("The external counter size can't be lower than 0");
		this.blockModeCounterBytes = blockModeCounterBytes;
		this.internalCounter = internalCounter || blockModeCounterBytes==0;
		this.key = key;
		this.random = random;
		this.counterStepInBytes=type.getBlockSizeBits()/8;
		this.supportRandomReadWrite=type.supportRandomReadWrite();
		//iv = new byte[getIVSizeBytesWithExternalCounter()];
		externalCounter=this.internalCounter?null:new byte[blockModeCounterBytes];
		this.chacha =type.getAlgorithmName().toUpperCase().startsWith(SymmetricEncryptionType.CHACHA20.getAlgorithmName().toUpperCase());
		this.gcm =type.getBlockMode().toUpperCase().equals("GCM");
		try {
			this.cipher.init(Cipher.ENCRYPT_MODE, this.key, generateIV());
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		}

		setMaxPlainTextSizeForEncoding(key.getMaxPlainTextSizeForEncoding());
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
		return type.getIVSizeBytes();
	}	
	
	private byte[] generateIV() {
		/*if (supportRandomEncryptionAndRandomDecryption())
			iv=new byte[iv.length];*/
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
	public AbstractCipher getCipherInstance() throws IOException {
		return type.getCipherInstance();
	}

	@Override
	protected int getCounterStepInBytes() {
		return counterStepInBytes;
	}

	@Override
	public boolean supportRandomEncryptionAndRandomDecryption() {
		return type.supportRandomReadWrite();
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
	public void initCipherForDecryption(AbstractCipher cipher, byte[] iv, byte[] externalCounter)
			throws IOException {
		iv=initIVAndCounter(iv, externalCounter);

		try {
			if (iv != null) {
				cipher.init(Cipher.DECRYPT_MODE, key, iv);
			} else
				cipher.init(Cipher.DECRYPT_MODE, key);
		}
		catch (NoSuchAlgorithmException | InvalidKeyException | InvalidAlgorithmParameterException | NoSuchProviderException | InvalidKeySpecException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		try {
			if (!supportRandomReadWrite)
				throw new IllegalAccessError();
			cipher.init(Cipher.DECRYPT_MODE, key, iv, counter);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		}
	}

	@Override
	public void initCipherForDecryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {

		try {

			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		}
	}

	@Override
	protected boolean allOutputGeneratedIntoDoFinalFunction() {
		return gcm;
	}


	@Override
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		try {
			if (!supportRandomReadWrite)
				throw new IllegalAccessError();
			cipher.init(Cipher.ENCRYPT_MODE, key, iv, counter);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		}
	}
	@Override
	protected void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		}
	}

	@Override
	public byte[] initCipherForEncryption(AbstractCipher cipher, byte[] externalCounter) throws IOException {
		if (!internalCounter && (externalCounter==null || externalCounter.length!=blockModeCounterBytes))
			throw new IllegalArgumentException("Please use external counters at every initialization with the defined size "+blockModeCounterBytes);
		this.externalCounter=externalCounter;
		byte[] iv=generateIV();
		try {
			cipher.init(Cipher.ENCRYPT_MODE, key, iv);
			return iv;
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | InvalidAlgorithmParameterException e) {
			throw new IOException(e);
		}

	}
	//private final Random nonSecureRandom=new Random(System.currentTimeMillis());
	protected boolean mustAlterIVForOutputSizeComputation()
	{
		return chacha;
	}
	@Override
	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher) throws IOException {
		byte[] iv=this.iv;
		if (mustAlterIVForOutputSizeComputation() || gcm)
		{
			/*iv = cipher.getIV();
			if (iv == null)
				iv = this.iv;*/

			iv[0] = (byte) ~iv[0];
		}

		initCipherForEncryptionWithIv(cipher, iv);
	}


	@Override
	public void initCipherForDecryption(AbstractCipher cipher) throws IOException{
		initCipherForDecryption(cipher, null, null);
	}


}
