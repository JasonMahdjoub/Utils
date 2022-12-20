/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.util.io.RandomInputStream;
import com.distrimind.util.io.RandomOutputStream;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.2
 * @since Utils 1.4
 */
public class P2PASymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {

	private final AbstractEncryptionIOAlgorithm p2pEncryption;
	private final AbstractKeyPair<?, ?> myKeyPair;
	private final IASymmetricPublicKey distantPublicKey;
	public P2PASymmetricEncryptionAlgorithm(AbstractSecureRandom random, AbstractKeyPair<?, ?> myKeyPair, IASymmetricPublicKey distantPublicKey)
			throws IOException {
		super();
		if (distantPublicKey == null)
			throw new NullPointerException("distantPublicKey");
		if (!myKeyPair.areTimesValid())
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "The key times are not valid !");
		if (!distantPublicKey.areTimesValid())
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "The key times are not valid !");
		if (distantPublicKey.isDestroyed())
			throw new IllegalArgumentException();
		if (myKeyPair.isCleaned())
			throw new IllegalArgumentException();
		if (random==null)
			throw new NullPointerException();
		this.myKeyPair=myKeyPair;
		this.distantPublicKey=distantPublicKey;

		try {
			if (myKeyPair instanceof HybridASymmetricKeyPair && distantPublicKey instanceof HybridASymmetricPublicKey) {
				p2pEncryption = new HybridP2PEncryption(random, (HybridASymmetricKeyPair) myKeyPair, (HybridASymmetricPublicKey) distantPublicKey);
			} else if (myKeyPair instanceof ASymmetricKeyPair && distantPublicKey instanceof ASymmetricPublicKey)
				p2pEncryption = new P2PEncryption(random, (ASymmetricKeyPair) myKeyPair, (ASymmetricPublicKey) distantPublicKey);
			else
				throw new IllegalArgumentException();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	@Override
	public int getMaxPlainTextSizeForEncoding() {
		return p2pEncryption.getMaxPlainTextSizeForEncoding();
	}

	@Override
	void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
		p2pEncryption.setMaxPlainTextSizeForEncoding(maxPlainTextSizeForEncoding);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length, byte[] externalCounter)
			throws IOException
	{

		p2pEncryption.decode(is, associatedData, offAD, lenAD, os, lenAD, externalCounter );
	}
	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {

		p2pEncryption.encode(bytes, off, len, associatedData, offAD, lenAD, os, externalCounter);
	}
	@Override
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {

		p2pEncryption.encode(is, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] externalCounter) throws IOException {

		return p2pEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, externalCounter);
	}

	@Override
	public byte[] decode(byte[] bytes) throws IOException {

		return p2pEncryption.decode(bytes);
	}

	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException {

		return p2pEncryption.decode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData) throws IOException {

		return p2pEncryption.decode(bytes, associatedData);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len) throws IOException {

		return p2pEncryption.decode(bytes, off, len);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException {

		return p2pEncryption.decode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {

		return p2pEncryption.decode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData) throws IOException {

		return p2pEncryption.decode(is, associatedData);
	}

	@Override
	public byte[] decode(RandomInputStream is) throws IOException {

		return p2pEncryption.decode(is);
	}

	@Override
	protected boolean mustAlterIVForOutputSizeComputation() {
		return p2pEncryption.mustAlterIVForOutputSizeComputation();
	}

	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException {

		return p2pEncryption.decode(is, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {

		return p2pEncryption.decode(is, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException {

		p2pEncryption.decode(is, associatedData, os);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, byte[] externalCounter) throws IOException {

		p2pEncryption.decode(is, os, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os) throws IOException {

		p2pEncryption.decode(is, os);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {

		p2pEncryption.decode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {

		p2pEncryption.decode(is, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, int length) throws IOException {

		p2pEncryption.decode(is, os, length);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, int length, byte[] externalCounter) throws IOException {

		p2pEncryption.decode(is, os, length, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os, int length) throws IOException {

		p2pEncryption.decode(is, associatedData, os, length);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length) throws IOException {

		p2pEncryption.decode(is, associatedData, offAD, lenAD, os, length);
	}

	@Override
	public RandomInputStream getCipherInputStreamForDecryption(RandomInputStream is) throws IOException {

		return p2pEncryption.getCipherInputStreamForDecryption(is);
	}


	@Override
	public byte[] encode(byte[] bytes) throws IOException {

		return p2pEncryption.encode(bytes);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData) throws IOException {

		return p2pEncryption.encode(bytes, associatedData);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException {

		return p2pEncryption.encode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len) throws IOException {

		return p2pEncryption.encode(bytes, off, len);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException {

		return p2pEncryption.encode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {

		return p2pEncryption.encode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, RandomOutputStream os) throws IOException {

		p2pEncryption.encode(bytes, off, len, os);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {

		p2pEncryption.encode(bytes, off, len, associatedData, offAD, lenAD, os);
	}

	@Override
	public void encode(RandomInputStream is, RandomOutputStream os) throws IOException {

		p2pEncryption.encode(is, os);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException {

		p2pEncryption.encode(is, associatedData, os);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {

		p2pEncryption.encode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public boolean isPowerMonitoringSideChannelAttackPossible() {
		return p2pEncryption.isPowerMonitoringSideChannelAttackPossible();
	}

	@Override
	public boolean isTimingSideChannelAttackPossible() {
		return p2pEncryption.isTimingSideChannelAttackPossible();
	}

	@Override
	public boolean isFrequencySideChannelAttackPossible() {
		return p2pEncryption.isFrequencySideChannelAttackPossible();
	}


	@Override
	public RandomInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] externalCounter) throws IOException {

		return p2pEncryption.getCipherInputStreamForDecryption(is, externalCounter);
	}

	@Override
	public RandomInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException {

		return p2pEncryption.getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD);
	}

	@Override
	protected void readIvsFromEncryptedStream(RandomInputStream is, int headLengthBytes, AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys) throws IOException {
		p2pEncryption.readIvsFromEncryptedStream(is, headLengthBytes, manualIvsAndSecretKeys);
	}

	@Override
	protected boolean allOutputGeneratedIntoDoFinalFunction() {
		return p2pEncryption.allOutputGeneratedIntoDoFinalFunction();
	}



	@Override
	protected int getCounterStepInBytes() {
		return p2pEncryption.getCounterStepInBytes();
	}

	@Override
	public boolean supportRandomEncryptionAndRandomDecryption() {
		return p2pEncryption.supportRandomEncryptionAndRandomDecryption();
	}






	@Override
	protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
		p2pEncryption.initCipherForDecryptionWithIvAndCounter(cipher, wrappedIVAndSecretKey, counter);
	}



	@Override
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
		p2pEncryption.initCipherForEncryptionWithIvAndCounter(cipher, wrappedIVAndSecretKey, counter);
	}

	@Override
	public RandomInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pEncryption.getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void initCipherForDecryption(AbstractCipher cipher) throws IOException {
		checkKeysNotCleaned();
		p2pEncryption.initCipherForDecryption(cipher);
	}

	@Override
	public long getOutputSizeAfterDecryption(long inputLen) throws IOException {
		return p2pEncryption.getOutputSizeAfterDecryption(inputLen);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException {
		return p2pEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return p2pEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	protected CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> getCPUUsageAsDecoyOutputStream(CommonCipherOutputStream os) throws IOException {
		return p2pEncryption.getCPUUsageAsDecoyOutputStream(os);
	}

	@Override
	public void checkKeysNotCleaned() {
		if (distantPublicKey.isDestroyed())
			throw new IllegalAccessError();
		if (myKeyPair.isCleaned())
			throw new IllegalAccessError();
	}

	@Override
	protected RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter, final AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, boolean replaceMainKeyWhenClosingStream) throws IOException {
		checkKeysNotCleaned();
		return p2pEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, manualIvsAndSecretKeys, replaceMainKeyWhenClosingStream);
	}


	@Override
	public AbstractCipher getCipherInstance() throws IOException {
		checkKeysNotCleaned();
		return p2pEncryption.getCipherInstance();
	}

	@Override
	public int getIVSizeBytesWithExternalCounter() {
		return p2pEncryption.getIVSizeBytesWithExternalCounter();
	}
	@Override
	protected boolean includeIV() {
		return p2pEncryption.includeIV();
	}


	@Override
	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher) throws IOException {

		p2pEncryption.initCipherForEncryptionWithNullIV(cipher);
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return p2pEncryption.isPostQuantumEncryption();
	}


	@Override
	public byte getBlockModeCounterBytes() {
		return p2pEncryption.getBlockModeCounterBytes();
	}

	@Override
	public boolean useExternalCounter() {
		return p2pEncryption.useExternalCounter();
	}

	public byte getMaxExternalCounterLength()
	{
		return p2pEncryption.getMaxExternalCounterLength();
	}

	@Override
	public void initBufferAllocatorArgs() throws IOException {
		p2pEncryption.initBufferAllocatorArgs();
	}

	@Override
	public long getOutputSizeAfterEncryption(long inputLen) throws IOException {
		return p2pEncryption.getOutputSizeAfterEncryption(inputLen);
	}

	@Override
	public void initCipherForEncryption(AbstractCipher cipher) throws IOException {

		p2pEncryption.initCipherForEncryption(cipher);
	}

	private static class HybridP2PEncryption extends AbstractEncryptionIOAlgorithm
	{
		private final P2PEncryption nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricKeyPair myKeyPair;
		private final HybridASymmetricPublicKey distantPublicKey;

		@Override
		public void checkKeysNotCleaned()
		{
			if (myKeyPair.isCleaned())
				throw new IllegalAccessError();
			if (distantPublicKey.isDestroyed())
				throw new IllegalAccessError();
		}

		public HybridP2PEncryption(AbstractSecureRandom random,
								   HybridASymmetricKeyPair myKeyPair,
								   HybridASymmetricPublicKey distantPublicKey) throws IOException {
			super();
			try {
				nonPQCEncryption = new P2PEncryption(random, myKeyPair.getNonPQCKeyPair(), distantPublicKey.getNonPQCPublicKey());
				PQCEncryption = new P2PEncryption(random,  myKeyPair.getPQCKeyPair(), distantPublicKey.getPQCPublicKey());
				if (nonPQCEncryption.includeIV() != PQCEncryption.includeIV())
					throw new IllegalArgumentException();
				this.myKeyPair = myKeyPair;
				this.distantPublicKey = distantPublicKey;
				setMaxPlainTextSizeForEncoding(Math.min(nonPQCEncryption.getMaxPlainTextSizeForEncoding(), PQCEncryption.getMaxPlainTextSizeForEncoding()));
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

		@Override
		void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
			this.maxPlainTextSizeForEncoding=maxPlainTextSizeForEncoding;
			this.maxEncryptedPartLength =(int)getOutputSizeAfterEncryption(maxPlainTextSizeForEncoding);
		}


		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
			initCipherForEncryption(cipher );
		}

		@Override
		public boolean isPowerMonitoringSideChannelAttackPossible() {
			return nonPQCEncryption.isPowerMonitoringSideChannelAttackPossible() || PQCEncryption.isPowerMonitoringSideChannelAttackPossible();
		}

		@Override
		public boolean isTimingSideChannelAttackPossible() {
			return nonPQCEncryption.isTimingSideChannelAttackPossible() || PQCEncryption.isTimingSideChannelAttackPossible();
		}

		@Override
		public boolean isFrequencySideChannelAttackPossible() {
			return nonPQCEncryption.isFrequencySideChannelAttackPossible() || PQCEncryption.isFrequencySideChannelAttackPossible();
		}


		@Override
		public AbstractCipher getCipherInstance()  {
			if (myKeyPair.isCleaned())
				throw new IllegalAccessError();
			if (distantPublicKey.isDestroyed())
				throw new IllegalAccessError();
			throw new IllegalAccessError();
		}

		@Override
		public void initCipherForDecryptionWithNullIV(AbstractCipher cipher) {
			this.initCipherForDecryption(cipher);
		}

		@Override
		protected int getCounterStepInBytes() {
			return 0;
		}

		@Override
		public boolean supportRandomEncryptionAndRandomDecryption() {
			return false;
		}

		@Override
		protected CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> getCPUUsageAsDecoyOutputStream(CommonCipherOutputStream os) throws IOException {
			return new CPUUsageAsDecoyOutputStream<>(os);
		}

		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return Math.max(nonPQCEncryption.getIVSizeBytesWithExternalCounter(), PQCEncryption.getIVSizeBytesWithExternalCounter());
		}

		@Override
		protected boolean includeIV() {
			return false;
		}


		@Override
		public void initCipherForEncryptionWithNullIV(AbstractCipher cipher) {
			throw new IllegalAccessError();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return true;
		}



		@Override
		protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) {
			initCipherForDecryption(cipher );
		}


		@Override
		protected boolean allOutputGeneratedIntoDoFinalFunction() {
			return false;
		}

		@Override
		public long getOutputSizeAfterDecryption(long inputLen) throws IOException {
			return nonPQCEncryption.getOutputSizeAfterDecryption(PQCEncryption.getOutputSizeAfterDecryption(inputLen));
		}

		@Override
		public long getOutputSizeAfterEncryption(long inputLen) throws IOException {
			return PQCEncryption.getOutputSizeAfterEncryption(nonPQCEncryption.getOutputSizeAfterEncryption(inputLen));
		}

		@Override
		protected RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter, final AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, boolean replaceMainKeyWhenClosingStream) throws IOException {
			return nonPQCEncryption.getCipherOutputStreamForEncryption(PQCEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, manualIvsAndSecretKeys, replaceMainKeyWhenClosingStream), true, associatedData, offAD, lenAD, externalCounter, manualIvsAndSecretKeys, replaceMainKeyWhenClosingStream);
		}

		@Override
		public RandomInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
			checkKeysNotCleaned();
			return nonPQCEncryption.getCipherInputStreamForDecryption(PQCEncryption.getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD, externalCounter), associatedData, offAD, lenAD, externalCounter);
		}



		@Override
		public void initCipherForDecryption(AbstractCipher cipher) {
			throw new IllegalAccessError();
		}
	}

	public IASymmetricPublicKey getDistantPublicKey() {
		if (this.p2pEncryption instanceof P2PEncryption)
			return ((P2PEncryption) p2pEncryption).getDistantPublicKey();
		else
			return ((HybridP2PEncryption) p2pEncryption).distantPublicKey;
	}
	public AbstractKeyPair<?, ?> getMyKeyPair() {
		if (this.p2pEncryption instanceof P2PEncryption)
			return ((P2PEncryption) p2pEncryption).getMyKeyPair();
		else
			return ((HybridP2PEncryption) p2pEncryption).myKeyPair;
	}

	@Override
	public void initCipherForDecryptionWithNullIV(AbstractCipher cipher) throws IOException {
		p2pEncryption.initCipherForDecryptionWithNullIV(cipher);
	}

	@Override
	public boolean useDerivedSecretKeys() {
		return p2pEncryption.useDerivedSecretKeys();
	}

	@Override
	public void zeroize() {
		p2pEncryption.zeroize();
	}

	@Override
	public void clean() {
		p2pEncryption.clean();
	}

	@Override
	public void destroy() {
		p2pEncryption.destroy();
	}

	@Override
	public boolean isDestroyed() {
		return p2pEncryption.isDestroyed();
	}


	@Override
	public void registerCleanerIfNotDone(Cleaner cleaner) {
		p2pEncryption.registerCleanerIfNotDone(cleaner);
	}

	@Override
	public boolean isCleaned() {
		return p2pEncryption.isCleaned();
	}


	@Override
	public AbstractWrappedIVs<?, ?> getWrappedIVAndSecretKeyInstance() throws IOException {
		return p2pEncryption.getWrappedIVAndSecretKeyInstance();
	}

	@Override
	public boolean isUsingSideChannelMitigation() {
		return p2pEncryption.isUsingSideChannelMitigation();
	}

	@Override
	public int getIVSizeBytesWithoutExternalCounter() {
		return p2pEncryption.getIVSizeBytesWithoutExternalCounter();
	}

	@Override
	public AbstractSecureRandom getSecureRandomForIV() {
		return p2pEncryption.getSecureRandomForIV();
	}

	@Override
	public AbstractSecureRandom getSecureRandomForKeyGeneration() {
		return p2pEncryption.getSecureRandomForKeyGeneration();
	}

	@Override
	public CPUUsageAsDecoyInputStream<CommonCipherInputStream> getCPUUsageAsDecoyInputStream(CommonCipherInputStream in) throws IOException {
		return p2pEncryption.getCPUUsageAsDecoyInputStream(in);
	}

	private static class P2PEncryption extends AbstractEncryptionIOAlgorithm {
		private final ASymmetricKeyPair myKeyPair;

		private final ASymmetricPublicKey distantPublicKey;

		private final ASymmetricEncryptionType type;

		private final AbstractSecureRandom random;

		@Override
		public boolean isPostQuantumEncryption() {
			return myKeyPair.isPostQuantumKey() && distantPublicKey.isPostQuantumKey();
		}
		@Override
		public void checkKeysNotCleaned()
		{
			if (myKeyPair.isCleaned())
				throw new IllegalAccessError();
			if (distantPublicKey.isDestroyed())
				throw new IllegalAccessError();
		}


		public P2PEncryption(AbstractSecureRandom random, ASymmetricKeyPair myKeyPair,
												ASymmetricPublicKey distantPublicKey) throws IOException, NoSuchAlgorithmException, NoSuchProviderException {
			super(distantPublicKey.getEncryptionAlgorithmType().getCipherInstance(),  0);
			if (myKeyPair==null)
				throw new NullPointerException();
			if (random==null)
				throw new NullPointerException();
			this.random=random;
			this.type = distantPublicKey.getEncryptionAlgorithmType();
			this.myKeyPair = myKeyPair;
			this.distantPublicKey = distantPublicKey;
			initCipherForEncryption(this.cipher);
			setMaxPlainTextSizeForEncoding(distantPublicKey.getMaxBlockSize());
			initBufferAllocatorArgs();
		}


		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
			initCipherForEncryption(cipher );
		}

		@Override
		public boolean isPowerMonitoringSideChannelAttackPossible() {
			return true;
		}

		@Override
		public boolean isTimingSideChannelAttackPossible() {
			return true;
		}

		@Override
		public boolean isFrequencySideChannelAttackPossible() {
			return true;
		}



		@Override
		public AbstractCipher getCipherInstance() throws IOException {
			checkKeysNotCleaned();
			try {
				return type.getCipherInstance();
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

		@Override
		public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
			cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey, random);
		}

		@Override
		protected int getCounterStepInBytes() {
			return 0;
		}

		@Override
		public boolean supportRandomEncryptionAndRandomDecryption() {
			return false;
		}

		@Override
		protected CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> getCPUUsageAsDecoyOutputStream(CommonCipherOutputStream os) throws IOException {
			return new CPUUsageAsDecoyOutputStream<>(os);
		}

		public ASymmetricPublicKey getDistantPublicKey() {
			return this.distantPublicKey;
		}

		public ASymmetricKeyPair getMyKeyPair() {
			return this.myKeyPair;
		}


		@Override
		protected boolean includeIV() {
			return false;
		}




		@Override
		protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
			initCipherForDecryption(cipher);
		}


		@Override
		protected boolean allOutputGeneratedIntoDoFinalFunction() {
			return false;
		}


		@Override
		public void initCipherForEncryptionWithNullIV(AbstractCipher _cipher)
				throws IOException {
			initCipherForEncryption(_cipher);

		}

		@Override
		public void initCipherForDecryptionWithNullIV(AbstractCipher cipher) throws IOException {
			initCipherForDecryption(cipher);
		}

		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return 0;
		}

		@Override
		public void initCipherForDecryption(AbstractCipher cipher) throws IOException {
			cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getASymmetricPrivateKey());
		}

	}
}
