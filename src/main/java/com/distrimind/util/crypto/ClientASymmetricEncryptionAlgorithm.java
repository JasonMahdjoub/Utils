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

import com.distrimind.util.io.RandomInputStream;
import com.distrimind.util.io.RandomOutputStream;

import javax.crypto.Cipher;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7
 */
public class ClientASymmetricEncryptionAlgorithm extends AbstractEncryptionOutputAlgorithm {

	private final AbstractEncryptionOutputAlgorithm client;
	private final IASymmetricPublicKey distantPublicKey;

	public ClientASymmetricEncryptionAlgorithm(AbstractSecureRandom random, IASymmetricPublicKey distantPublicKey) throws IOException {
		super();
		if (distantPublicKey.isDestroyed())
			throw new IllegalArgumentException();
		this.distantPublicKey=distantPublicKey;
		if (distantPublicKey instanceof HybridASymmetricPublicKey)
			client=new HybridClient(random, (HybridASymmetricPublicKey)distantPublicKey);
		else {
			try {
				client=new Client(random, (ASymmetricPublicKey)distantPublicKey);
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}
	}
	@Override
	public void checkKeysNotCleaned()
	{
		if (distantPublicKey.isDestroyed())
			throw new IllegalAccessError();
	}

	private static class HybridClient extends AbstractEncryptionOutputAlgorithm {
		private final Client nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricPublicKey hybridASymmetricPublicKey;
		public HybridClient(AbstractSecureRandom random, HybridASymmetricPublicKey distantPublicKey) throws IOException {
			super();
			try {
				this.nonPQCEncryption=new Client(random, distantPublicKey.getNonPQCPublicKey());
				this.PQCEncryption=new Client(random, distantPublicKey.getPQCPublicKey());
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
			this.hybridASymmetricPublicKey=distantPublicKey;
			//setMaxPlainTextSizeForEncoding(Math.min(nonPQCEncryption.getMaxPlainTextSizeForEncoding(), PQCEncryption.getMaxPlainTextSizeForEncoding()));
		}
		@Override
		public void checkKeysNotCleaned()
		{
			if (hybridASymmetricPublicKey.isDestroyed())
				throw new IllegalAccessError();
		}


		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
			initCipherForEncryption(cipher);
		}

		@Override
		public boolean isPowerMonitoringSideChannelAttackMitigationActivated() {
			return nonPQCEncryption.isPowerMonitoringSideChannelAttackMitigationActivated() || PQCEncryption.isPowerMonitoringSideChannelAttackMitigationActivated();
		}

		@Override
		public boolean isTimingSideChannelAttackMitigationActivated() {
			return nonPQCEncryption.isTimingSideChannelAttackMitigationActivated() || PQCEncryption.isTimingSideChannelAttackMitigationActivated();
		}

		@Override
		public boolean isFrequencySideChannelAttackMitigationActivated() {
			return nonPQCEncryption.isFrequencySideChannelAttackMitigationActivated() || PQCEncryption.isFrequencySideChannelAttackMitigationActivated();
		}

		@Override
		public AbstractCipher getCipherInstance()  {
			throw new IllegalAccessError();
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
		public long getOutputSizeAfterEncryption(long inputLen) throws IOException {
			return nonPQCEncryption.getOutputSizeAfterEncryption(PQCEncryption.getOutputSizeAfterEncryption(inputLen));
		}

		@Override
		protected RandomOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter, final AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, boolean replaceMainKeyWhenClosingStream) throws IOException {
			return nonPQCEncryption.getCipherOutputStreamForEncryption(PQCEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, manualIvsAndSecretKeys, replaceMainKeyWhenClosingStream), true, associatedData, offAD, lenAD, externalCounter, manualIvsAndSecretKeys, replaceMainKeyWhenClosingStream);
		}

	}



	@Override
	protected RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter, AbstractWrappedIVs<?, ?> manualIvsAndSecretKeys, boolean replaceMainKeyWhenClosingStream) throws IOException {
		return client.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, manualIvsAndSecretKeys,replaceMainKeyWhenClosingStream);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {
		client.encode(is, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException {
		return client.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return client.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD);
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return client.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	protected CPUUsageAsDecoyOutputStream<CommonCipherOutputStream> getCPUUsageAsDecoyOutputStream(CommonCipherOutputStream os) throws IOException {
		return client.getCPUUsageAsDecoyOutputStream(os);
	}


	@Override
	public byte getBlockModeCounterBytes() {
		return client.getBlockModeCounterBytes();
	}

	@Override
	public boolean useExternalCounter() {
		return client.useExternalCounter();
	}

	public byte getMaxExternalCounterLength()
	{
		return client.getMaxExternalCounterLength();
	}

	@Override
	public void initBufferAllocatorArgs() throws IOException {
		client.initBufferAllocatorArgs();
	}

	@Override
	public byte[] encode(byte[] bytes) throws IOException {
		return client.encode(bytes);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData) throws IOException {
		return client.encode(bytes, associatedData);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException {
		return client.encode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len) throws IOException {
		return client.encode(bytes, off, len);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return client.encode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return client.encode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, RandomOutputStream os) throws IOException {
		client.encode(bytes, off, len, os);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {
		client.encode(bytes, off, len, associatedData, offAD, lenAD, os);
	}




	@Override
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
		client.initCipherForEncryptionWithIvAndCounter(cipher, wrappedIVAndSecretKey, counter);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {
		client.encode(bytes, off, len, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public void encode(RandomInputStream is, RandomOutputStream os) throws IOException {
		client.encode(is, os);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException {
		client.encode(is, associatedData, os);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {
		client.encode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public boolean isPowerMonitoringSideChannelAttackMitigationActivated() {
		return this.client.isPowerMonitoringSideChannelAttackMitigationActivated();
	}

	@Override
	public boolean isTimingSideChannelAttackMitigationActivated() {
		return client.isTimingSideChannelAttackMitigationActivated();
	}

	@Override
	public boolean isFrequencySideChannelAttackMitigationActivated() {
		return client.isFrequencySideChannelAttackMitigationActivated();
	}


	@Override
	public AbstractCipher getCipherInstance() throws IOException {

		checkKeysNotCleaned();
		return client.getCipherInstance();
	}

	@Override
	public RandomOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] externalCounter) throws IOException {
		return client.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, externalCounter);
	}

	@Override
	protected int getCounterStepInBytes() {
		return client.getCounterStepInBytes();
	}

	@Override
	public boolean supportRandomEncryptionAndRandomDecryption() {
		return client.supportRandomEncryptionAndRandomDecryption();
	}

	@Override
	public int getMaxPlainTextSizeForEncoding() {
		return client.getMaxPlainTextSizeForEncoding();
	}

	@Override
	void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
		client.setMaxPlainTextSizeForEncoding(maxPlainTextSizeForEncoding);
	}

	@Override
	public int getIVSizeBytesWithExternalCounter() {
		return client.getIVSizeBytesWithExternalCounter();
	}

	@Override
	public long getOutputSizeAfterEncryption(long inputLen) throws IOException{
		return client.getOutputSizeAfterEncryption(inputLen);
	}

	@Override
	public boolean includeIV() {
		return client.includeIV();
	}

	@Override
	public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
		client.initCipherForEncryption(cipher);
	}


	@Override
	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher) throws IOException {
		client.initCipherForEncryptionWithNullIV(cipher);
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return client.isPostQuantumEncryption();
	}


	@Override
	public boolean useDerivedSecretKeys() {
		return client.useDerivedSecretKeys();
	}

	@Override
	public void zeroize() {
		client.zeroize();
	}

	@Override
	public void clean() {
		client.clean();
	}

	@Override
	public void destroy() {
		client.destroy();
	}

	@Override
	public boolean isDestroyed() {
		return client.isDestroyed();
	}


	@Override
	public void registerCleanerIfNotDone(Cleaner cleaner) {
		client.registerCleanerIfNotDone(cleaner);
	}

	@Override
	public boolean isCleaned() {
		return client.isCleaned();
	}


	@Override
	public AbstractWrappedIVs<?, ?> getWrappedIVAndSecretKeyInstance() throws IOException {
		return client.getWrappedIVAndSecretKeyInstance();
	}

	@Override
	public boolean isUsingSideChannelMitigation() {
		return client.isUsingSideChannelMitigation();
	}

	@Override
	public int getIVSizeBytesWithoutExternalCounter() {
		return client.getIVSizeBytesWithoutExternalCounter();
	}

	@Override
	public AbstractSecureRandom getSecureRandomForIV() {
		return client.getSecureRandomForIV();
	}

	@Override
	public AbstractSecureRandom getSecureRandomForKeyGeneration() {
		return client.getSecureRandomForKeyGeneration();
	}


	public IASymmetricPublicKey getDistantPublicKey() {
		if (this.client instanceof Client)
			return ((Client)client).getDistantPublicKey();
		else
			return ((HybridClient)client).hybridASymmetricPublicKey;
	}
	private static class Client extends AbstractEncryptionOutputAlgorithm {
		private final ASymmetricPublicKey distantPublicKey;

		private final ASymmetricEncryptionType type;

		private final AbstractSecureRandom random;


		public Client(AbstractSecureRandom random, ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
			super(distantPublicKey.getEncryptionAlgorithmType().getCipherInstance(),  0);
			this.type = distantPublicKey.getEncryptionAlgorithmType();
			this.distantPublicKey = distantPublicKey;
			this.random = random;
			initCipherForEncryption(this.cipher);
			setMaxPlainTextSizeForEncoding(distantPublicKey.getMaxBlockSize());

			initBufferAllocatorArgs();
		}
		@Override
		public void checkKeysNotCleaned()
		{
			if (distantPublicKey.isDestroyed())
				throw new IllegalAccessError();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return distantPublicKey.isPostQuantumKey();
		}



		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, AbstractWrappedIVs<?, ?> wrappedIVAndSecretKey, int counter) throws IOException {
			this.initCipherForEncryption(cipher);
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

		@Override
		protected boolean includeIV() {
			return false;
		}


		@Override
		public void initCipherForEncryptionWithNullIV(AbstractCipher _cipher)
				throws IOException {
			initCipherForEncryption(_cipher);

		}

		@Override
		public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
			cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey, random);
		}

		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return 0;
		}
	}
}
