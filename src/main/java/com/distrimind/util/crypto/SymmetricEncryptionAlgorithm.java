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
import java.util.List;
import java.util.Random;


/**
 * 
 * @author Jason Mahdjoub
 * @version 4.1
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {

	static final SymmetricKeyWrapperType DEFAULT_SYMMETRIC_KEY_WRAPPER_TYPE=SymmetricKeyWrapperType.BC_FIPS_AES_WITH_PADDING;
	private final SymmetricSecretKey key;

	private final SymmetricEncryptionType type;

	private final AbstractSecureRandom randomForIV;
	//private byte[] iv;
	
	private final byte blockModeCounterBytes;
	private final boolean internalCounter;


	private final int counterStepInBytes;
	private final boolean supportRandomReadWrite;
	private final boolean chacha;
	private final boolean gcm;
	private final boolean useDerivedKeys;
	protected final byte[] fakeIV;
	private final AbstractSecureRandom secureRandomForKeyGeneration;

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
			AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys=useDerivedKeys?new WrappedIVsAndSecretKeys():new WrappedIVs();
			readIvsFromEncryptedStream(encryptedInputStream, headLengthBytes, manualIvsAndSecretKeys);
			return new SubStreamHashResult(hash, manualIvsAndSecretKeys);
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


	@SuppressWarnings("unchecked")
	private void partialHash(RandomInputStream nonEncryptedInputStream, NullRandomOutputStream nullStream, AbstractMessageDigest md, RandomOutputStream os, long pos, long len) throws IOException {
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

		try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream((int)l)) {
			CommonCipherOutputStream cos;
			if (os instanceof CPUUsageAsDecoyOutputStream)
				cos=((CPUUsageAsDecoyOutputStream<CommonCipherOutputStream>)os).getDestinationRandomOutputStream();
			else
				cos=(CommonCipherOutputStream)os;
			cos.os = out;
			nonEncryptedInputStream.transferTo(os, l);
			out.flush();
			byte[] b = out.getBytes();
			md.update(b, (int) off, (int) len);
			if (doFinal) {
				byte[] f = cipher.doFinal();
				md.update(f, 0, f.length);
			}
			cos.os = nullStream;
		}
	}

	public boolean checkPartialHashWithNonEncryptedStream(byte[] head, SubStreamHashResult hashResultFromEncryptedStream, SubStreamParameters subStreamParameters,
														  RandomInputStream nonEncryptedInputStream,
														  AbstractMessageDigest md) throws IOException {

		if (nonEncryptedInputStream.currentPosition()!=0)
			nonEncryptedInputStream.seek(0);
		List<SubStreamParameter> parameters = subStreamParameters.getParameters();
		AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys = hashResultFromEncryptedStream.getManualIvsAndSecretKeys(this);

		final int ivSizeWithoutExternalCounter=getIVSizeBytesWithoutExternalCounter();
		NullRandomOutputStream nullStream=new NullRandomOutputStream();
		nullStream.setLength(getOutputSizeAfterEncryption(nonEncryptedInputStream.length()));


		try(RandomOutputStream os= getCipherOutputStreamForEncryption(nullStream, false, null, 0, 0, null, manualIvsAndSecretKeys)) {

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
				long round = start / maxEncryptedPartLength;
				long startIV = round * (long)maxEncryptedPartLength;
				long endIV = startIV + ivSizeWithoutExternalCounter;
				if (start<endIV) {
					byte[] e;
					try(RandomByteArrayOutputStream o=new RandomByteArrayOutputStream())
					{
						manualIvsAndSecretKeys.getElement(round).write(o);
						e=o.getBytes();
					}
					md.update(e, (int)(start-startIV), (int) Math.min(end - start, endIV-start));
				}
				if (end>endIV)
				{
					start = Math.max(endIV, start);
					partialHash(nonEncryptedInputStream, nullStream, md, os, start, end - start);
				}
			}
			return com.distrimind.bouncycastle.util.Arrays.constantTimeAreEqual(md.digest(), hashResultFromEncryptedStream.getHash());
		}

	}
	SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, SymmetricSecretKey key, boolean useDerivedKeys)
			throws IOException {
		this(randomForIV, key, (byte)0, false, useDerivedKeys);
	}
	SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, AbstractSecureRandom secureRandomForKeyGeneration,SymmetricSecretKey key, boolean useDerivedKeys)
			throws IOException {
		this(randomForIV, secureRandomForKeyGeneration, key, (byte)0, false, useDerivedKeys);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, SymmetricSecretKey key)
			throws IOException {
		this(randomForIV, key, true);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, AbstractSecureRandom secureRandomForKeyGeneration, SymmetricSecretKey key)
			throws IOException {
		this(randomForIV, secureRandomForKeyGeneration, key, true);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, SymmetricSecretKey key, byte blockModeCounterBytes)
			throws IOException {
		this(randomForIV, key, blockModeCounterBytes, false);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, AbstractSecureRandom secureRandomForKeyGeneration, SymmetricSecretKey key, byte blockModeCounterBytes)
			throws IOException {
		this(randomForIV, secureRandomForKeyGeneration, key, blockModeCounterBytes, false);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter) throws IOException {
		this(randomForIV, key, blockModeCounterBytes, internalCounter, true);
	}
	public SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, AbstractSecureRandom secureRandomForKeyGeneration, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter) throws IOException {
		this(randomForIV, secureRandomForKeyGeneration, key, blockModeCounterBytes, internalCounter, true);
	}
	SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter, boolean useDerivedKeys) throws IOException {
		this(randomForIV,AbstractWrappedIVs.getDefaultSecureRandom(), key, blockModeCounterBytes, internalCounter, useDerivedKeys);
	}
	SymmetricEncryptionAlgorithm(AbstractSecureRandom randomForIV, AbstractSecureRandom secureRandomForKeyGeneration, SymmetricSecretKey key, byte blockModeCounterBytes, boolean internalCounter, boolean useDerivedKeys)
			throws IOException {
		super(key.getEncryptionAlgorithmType().getCipherInstance(), key.getEncryptionAlgorithmType().getIVSizeBytes());
		if (secureRandomForKeyGeneration==null)
			throw new NullPointerException();

		this.secureRandomForKeyGeneration=secureRandomForKeyGeneration;
		this.fakeIV=new byte[key.getEncryptionAlgorithmType().getIVSizeBytes()];
		Random r=new Random(System.nanoTime());
		r.nextBytes(fakeIV);
		this.useDerivedKeys=useDerivedKeys;
		if (key.isCleaned())
			throw new IllegalArgumentException();

		if (randomForIV ==null)
			throw new NullPointerException();
		this.type = key.getEncryptionAlgorithmType();
		if (!internalCounter && blockModeCounterBytes>type.getMaxCounterSizeInBytesUsedWithBlockMode())
			throw new IllegalArgumentException("The external counter size can't be greater than "+type.getMaxCounterSizeInBytesUsedWithBlockMode());
		if (blockModeCounterBytes<0)
			throw new IllegalArgumentException("The external counter size can't be lower than 0");
		this.blockModeCounterBytes = blockModeCounterBytes;
		this.internalCounter = internalCounter || blockModeCounterBytes==0;
		this.key = key;
		this.randomForIV = randomForIV;
		this.counterStepInBytes=type.getBlockSizeBits()/8;
		this.supportRandomReadWrite=type.supportRandomReadWrite();
		//iv = new byte[getIVSizeBytesWithExternalCounter()];

		this.chacha =type.getAlgorithmName().toUpperCase().startsWith(SymmetricEncryptionType.CHACHA20_NO_RANDOM_ACCESS.getAlgorithmName().toUpperCase());
		this.gcm = type.getBlockMode().equalsIgnoreCase("GCM");

		initCipherForEncryptionWithNullIV(cipher);

		setMaxPlainTextSizeForEncoding(type.getMaxPlainTextSizeForEncoding());
		initBufferAllocatorArgs();

	}

	@Override
	public AbstractWrappedIVs<?, ?> getWrappedIVAndSecretKeyInstance() throws IOException {
		return useDerivedKeys?
				new WrappedIVsAndSecretKeys(this):
				new WrappedIVs(this);
	}
	@Override
	protected boolean useDerivedSecretKeys()
	{
		return useDerivedKeys;
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

	public byte getMaxExternalCounterLength()
	{
		return internalCounter?0:getSecretKey().getEncryptionAlgorithmType().getMaxCounterSizeInBytesUsedWithBlockMode();
	}


	@Override
	public int getIVSizeBytesWithExternalCounter()
	{
		return type.getIVSizeBytes();
	}	

	

	public int getBlockSizeBytes() {
		return cipher.getBlockSize();
	}
	@Override
	public void checkKeysNotCleaned()
	{
		if (key.isCleaned())
			throw new IllegalAccessError();
	}
	@Override
	public AbstractCipher getCipherInstance() throws IOException {
		checkKeysNotCleaned();
		return type.getCipherInstance();
	}

	@Override
	protected int getCounterStepInBytes() {
		return counterStepInBytes;
	}

	@Override
	public boolean supportRandomEncryptionAndRandomDecryption() {
		return supportRandomReadWrite;
	}

	@Override
	protected CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> getCPUUsageAsDecoyOutputStream(CommonCipherOutputStream os) throws IOException {
		return new CPUUsageAsDecoyOutputStream<>(os, key.getEncryptionAlgorithmType());
	}

	public SymmetricSecretKey getSecretKey() {
		return key;
	}

	public SymmetricEncryptionType getType() {
		return type;
	}

	@Override
	public AbstractSecureRandom getSecureRandomForIV()
	{
		return randomForIV;
	}

	@Override
	public AbstractSecureRandom getSecureRandomForKeyGeneration()
	{
		return secureRandomForKeyGeneration;
	}

	@Override
	protected boolean includeIV() {
		return true;
	}







	@Override
	public CPUUsageAsDecoyInputStream<CommonCipherInputStream> getCPUUsageAsDecoyInputStream(CommonCipherInputStream in) throws IOException {
		return new CPUUsageAsDecoyInputStream<>(in, key.getEncryptionAlgorithmType());
	}

	@Override
	protected boolean allOutputGeneratedIntoDoFinalFunction() {
		return gcm || (chacha && type.getAlgorithmName().toUpperCase().contains("POLY1305"));
	}




	private void invertFakeIv()
	{
		if (mustAlterIVForOutputSizeComputation())
		{
			fakeIV[0] = (byte) ~fakeIV[0];
		}
	}

	@Override
	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher)
			throws IOException
	{
		invertFakeIv();
		cipher.init(Cipher.ENCRYPT_MODE, key, fakeIV);

	}
	@Override
	public void initCipherForDecryptionWithNullIV(AbstractCipher cipher)
			throws IOException
	{
		invertFakeIv();
		cipher.init(Cipher.DECRYPT_MODE, key, fakeIV);

	}

	@Override
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException
	{
		checkKeysNotCleaned();
		SymmetricSecretKey k;

		if (useDerivedKeys)
			k=((WrappedIVsAndSecretKeys)wrappedIVAndSecretKey).getCurrentSecretKey();
		else
			k=key;
		if (k.isCleaned())
			throw new IOException();
		AbstractWrappedIV<?, ?, ?> iv=wrappedIVAndSecretKey.getCurrentIV();
		if (supportRandomReadWrite)
			iv.setCounter(counter);
		cipher.init(Cipher.ENCRYPT_MODE, k, iv.getIv());
	}

	@Override
	protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
		checkKeysNotCleaned();
		SymmetricSecretKey k;
		if (useDerivedKeys)
			k=((WrappedIVsAndSecretKeys)wrappedIVAndSecretKey).getCurrentSecretKey();
		else
			k=key;
		if (k.isCleaned())
			throw new IOException();
		AbstractWrappedIV<?, ?, ?> iv=wrappedIVAndSecretKey.getCurrentIV();
		if (supportRandomReadWrite)
			iv.setCounter(counter);
		cipher.init(Cipher.DECRYPT_MODE, k, iv.getIv());

	}
	@Override
	public boolean isPowerMonitoringSideChannelAttackPossible() {
		return key.getEncryptionAlgorithmType().isPowerMonitoringAttackPossible();
	}

	@Override
	public boolean isTimingSideChannelAttackPossible() {
		return key.getEncryptionAlgorithmType().isTimingAttackPossibleIntoThisMachine();
	}

	@Override
	public boolean isFrequencySideChannelAttackPossible() {
		return key.getEncryptionAlgorithmType().isFrequencyAttackPossible();
	}



	protected boolean mustAlterIVForOutputSizeComputation()
	{
		return chacha || gcm;
	}


	@Override
	public void initCipherForDecryption(AbstractCipher cipher) {
		throw new IllegalAccessError();

	}

	public boolean isInternalCounter() {
		return internalCounter;
	}

	SymmetricKeyWrapperType getSymmetricKeyWrapperType()
	{
		return DEFAULT_SYMMETRIC_KEY_WRAPPER_TYPE;
	}

}
