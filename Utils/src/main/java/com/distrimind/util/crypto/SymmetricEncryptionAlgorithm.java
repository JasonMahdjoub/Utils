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

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;


/**
 * 
 * @author Jason Mahdjoub
 * @version 4.1
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
	public void zeroize() {
		super.zeroize();
		if (externalCounter!=null) {
			Arrays.fill(externalCounter, (byte) 0);
			externalCounter=null;
		}
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return key.isPostQuantumKey();
	}
	public SubStreamHashResult getIVAndPartialHashedSubStreamFromEncryptedStream(RandomInputStream encryptedInputStream, SubStreamParameters subStreamParameters, int headLengthBytes) throws IOException {
		return getIVAndPartialHashedSubStreamFromEncryptedStream(encryptedInputStream, subStreamParameters,headLengthBytes, null);
	}
	public SubStreamHashResult getIVAndPartialHashedSubStreamFromEncryptedStream(RandomInputStream encryptedInputStream, SubStreamParameters subStreamParameters, int headLengthBytes, byte[] externalCounter) throws IOException {
		if (!getType().supportRandomReadWrite())
			throw new IllegalStateException("Encryption type must support random read and write");
		try {
			byte[] hash = subStreamParameters.generateHash(encryptedInputStream);
			return new SubStreamHashResult(hash, readIvsFromEncryptedStream(encryptedInputStream, headLengthBytes));
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}

	}
	public boolean checkPartialHashWithNonEncryptedStream(byte[] head, SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters, RandomInputStream nonEncryptedInputStream) throws IOException{
		try {
			AbstractMessageDigest md = subStreamParameters.getMessageDigestType().getMessageDigestInstance();
			md.reset();
			return checkPartialHashWithNonEncryptedStream(head, hashResultFromEncryptedStream, subStreamParameters, nonEncryptedInputStream, md);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}

	}


	private void partialHash(RandomInputStream nonEncryptedInputStream, NullRandomOutputStream nullStream, AbstractMessageDigest md, CommonCipherOutputStream os, long pos, long len) throws IOException {
		long mod=pos%maxEncryptedPartLength;
		mod-=getIVSizeBytesWithoutExternalCounter();
		assert mod>=0;
		pos=(pos/maxEncryptedPartLength)*maxPlainTextSizeForEncoding+mod;
		long p=(pos/getCounterStepInBytes())*getCounterStepInBytes();
		long off=pos-p;
		nonEncryptedInputStream.seek(p);
		os.seek(p);
		long l=pos+len;
		if (l%getCounterStepInBytes()!=0)
			l=(((l/getCounterStepInBytes())+1)*getCounterStepInBytes());
		assert l%getCounterStepInBytes()==0;
		assert p%getCounterStepInBytes()==0;
		boolean doFinal=false;
		if (l>nonEncryptedInputStream.length()) {
			doFinal=true;
			l = nonEncryptedInputStream.length();
		}
		l-=p;
		RandomByteArrayOutputStream out=new RandomByteArrayOutputStream((int)l);
		os.os=out;
		nonEncryptedInputStream.transferTo(os, l);
		out.flush();
		byte[] b=out.getBytes();
		md.update(b, (int)off,(int)len);
		if (doFinal) {
			byte[] f = cipher.doFinal();
			md.update(f, 0, f.length);
		}
		os.os=nullStream;
	}

	public boolean checkPartialHashWithNonEncryptedStream(byte[] head, SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters,
														  RandomInputStream nonEncryptedInputStream,
														  AbstractMessageDigest md) throws IOException {

		if (nonEncryptedInputStream.currentPosition()!=0)
			nonEncryptedInputStream.seek(0);
		List<SubStreamParameter> parameters = subStreamParameters.getParameters();
		byte[][] ivs = hashResultFromEncryptedStream.getIvs();
		for (byte[] iv : ivs)
			if (iv==null)
				throw new IOException();
			if (iv.length != key.getEncryptionAlgorithmType().getIVSizeBytes())
				throw new IOException();

		final int ivSizeWithoutExternalCounter=getIVSizeBytesWithoutExternalCounter();
		NullRandomOutputStream nullStream=new NullRandomOutputStream();
		nullStream.setLength(getOutputSizeAfterEncryption(nonEncryptedInputStream.length()));


		try(CommonCipherOutputStream os= getCipherOutputStreamForEncryption(nullStream, false, null, 0, 0, null, ivs)) {

			List<SubStreamParameter> ssp;
			if (head!=null) {
				ssp=new ArrayList<>(parameters.size());
				for (SubStreamParameter p : subStreamParameters.getParameters()) {
					if (p.getStreamStartIncluded() < head.length) {
						md.update(head, (int) p.getStreamStartIncluded(), (int) Math.min(p.getStreamEndExcluded()-p.getStreamStartIncluded(), head.length-p.getStreamStartIncluded()));
						if (p.getStreamEndExcluded() > head.length)
							ssp.add(new SubStreamParameter(0, p.getStreamEndExcluded()-head.length));
					} else
						ssp.add(new SubStreamParameter(p.getStreamStartIncluded()-head.length, p.getStreamEndExcluded()-head.length));
				}
			}
			else
				ssp=parameters;
			ArrayList<SubStreamParameter> ssp2=new ArrayList<>(ssp.size());
			for (SubStreamParameter p : ssp) {
				int round1 = (int) (p.getStreamStartIncluded() / maxEncryptedPartLength);
				int round2 = (int) (p.getStreamEndExcluded() / maxEncryptedPartLength);
				if (round1==round2 || (p.getStreamEndExcluded() % maxEncryptedPartLength)==0)
					ssp2.add(p);
				else
				{
					long siv=(long)round2 * (long)maxEncryptedPartLength;
					ssp2.add(new SubStreamParameter(p.getStreamStartIncluded(), siv));
					ssp2.add(new SubStreamParameter(siv, p.getStreamEndExcluded()));
				}
			}

			for (SubStreamParameter p : ssp2) {
				long start = p.getStreamStartIncluded();
				long end = p.getStreamEndExcluded();
				int round = (int) (start / maxEncryptedPartLength);
				long startIV = (long)round * (long)maxEncryptedPartLength;
				long endIV = startIV + ivSizeWithoutExternalCounter;
				if (start<endIV) {
					md.update(ivs[round], (int)(start-startIV), (int) Math.min(end - start, endIV-start));
				}
				if (end>endIV)
				{
					start = Math.max(endIV, start);
					partialHash(nonEncryptedInputStream, nullStream, md, os, start, end - start);
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
		this.chacha =type.getAlgorithmName().toUpperCase().startsWith(SymmetricEncryptionType.CHACHA20_NO_RANDOM_ACCESS.getAlgorithmName().toUpperCase());
		this.gcm = type.getBlockMode().equalsIgnoreCase("GCM");
		this.cipher.init(Cipher.ENCRYPT_MODE, this.key, generateIV());

		setMaxPlainTextSizeForEncoding(type.getMaxPlainTextSizeForEncoding());
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

	AbstractSecureRandom getSecureRandom()
	{
		return random;
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

		if (iv != null) {
			cipher.init(Cipher.DECRYPT_MODE, key, iv);
		} else
			cipher.init(Cipher.DECRYPT_MODE, key);
	}

	@Override
	protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		if (!supportRandomReadWrite)
			throw new IllegalAccessError();
		cipher.init(Cipher.DECRYPT_MODE, key, iv, counter);

	}

	@Override
	public void initCipherForDecryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {

		cipher.init(Cipher.DECRYPT_MODE, key, iv);
	}

	@Override
	protected boolean allOutputGeneratedIntoDoFinalFunction() {
		return gcm || (chacha && type.getAlgorithmName().toUpperCase().contains("POLY1305"));
	}


	@Override
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		if (!supportRandomReadWrite)
			throw new IllegalAccessError();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv, counter);
	}
	@Override
	protected void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
	}

	@Override
	public byte[] initCipherForEncryption(AbstractCipher cipher, byte[] externalCounter) throws IOException {
		if (!internalCounter && (externalCounter==null || externalCounter.length!=blockModeCounterBytes))
			throw new IllegalArgumentException("Please use external counters at every initialization with the defined size "+blockModeCounterBytes);
		this.externalCounter=externalCounter;
		byte[] iv=generateIV();
		cipher.init(Cipher.ENCRYPT_MODE, key, iv);
		return iv;

	}
	protected boolean mustAlterIVForOutputSizeComputation()
	{
		return chacha;
	}
	@Override
	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher) throws IOException {
		byte[] iv=this.iv;
		if (mustAlterIVForOutputSizeComputation() || gcm)
		{

			iv[0] = (byte) ~iv[0];
		}

		initCipherForEncryptionWithIv(cipher, iv);
	}


	@Override
	public void initCipherForDecryption(AbstractCipher cipher) throws IOException{
		initCipherForDecryption(cipher, null, null);
	}


}
