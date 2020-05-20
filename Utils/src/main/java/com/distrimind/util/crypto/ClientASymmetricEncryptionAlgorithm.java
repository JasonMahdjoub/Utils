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

import com.distrimind.util.io.RandomInputStream;
import com.distrimind.util.io.RandomOutputStream;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7
 */
public class ClientASymmetricEncryptionAlgorithm extends AbstractEncryptionOutputAlgorithm {

	private final AbstractEncryptionOutputAlgorithm client;

	public ClientASymmetricEncryptionAlgorithm(AbstractSecureRandom random, IASymmetricPublicKey distantPublicKey) throws IOException {
		super();
		if (distantPublicKey instanceof HybridASymmetricPublicKey)
			client=new HybridClient(random, (HybridASymmetricPublicKey)distantPublicKey);
		else {
			try {
				client=new Client(random, (ASymmetricPublicKey)distantPublicKey);
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}
	}

	private static class HybridClient extends AbstractEncryptionOutputAlgorithm {
		private final Client nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricPublicKey hybridASymmetricPublicKey;
		public HybridClient(AbstractSecureRandom random, HybridASymmetricPublicKey distantPublicKey) throws IOException {
			super();
			try {
				this.nonPQCEncryption=new Client(random, distantPublicKey.getNonPQCPublicKey());
				this.PQCEncryption=new Client(random, distantPublicKey.getPQCPublicKey());
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
				throw new IOException(e);
			}
			this.hybridASymmetricPublicKey=distantPublicKey;
			setMaxPlainTextSizeForEncoding(Math.min(nonPQCEncryption.getMaxPlainTextSizeForEncoding(), PQCEncryption.getMaxPlainTextSizeForEncoding()));
		}

		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
			initCipherForEncrypt(cipher);
		}

		@Override
		protected AbstractCipher getCipherInstance()  {
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
		public int getIVSizeBytesWithExternalCounter() {
			return Math.max(nonPQCEncryption.getIVSizeBytesWithExternalCounter(), PQCEncryption.getIVSizeBytesWithExternalCounter());
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		public byte[] initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) {
			throw new IllegalAccessError();
		}

		@Override
		public void initCipherForEncryptWithNullIV(AbstractCipher cipher) {
			throw new IllegalAccessError();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return true;
		}


		@Override
		public long getOutputSizeForEncryption(long inputLen) throws IOException {
			return nonPQCEncryption.getOutputSizeForEncryption(PQCEncryption.getOutputSizeForEncryption(inputLen));
		}

		@Override
		protected RandomOutputStream getCipherOutputStream(final RandomOutputStream os, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter, byte[][] manualIVs) throws IOException {
			return nonPQCEncryption.getCipherOutputStream(PQCEncryption.getCipherOutputStream(os, associatedData, offAD, lenAD, externalCounter), associatedData, offAD, lenAD, externalCounter);
		}
	}

	@Override
	public byte getBlockModeCounterBytes() {
		return client.getBlockModeCounterBytes();
	}

	@Override
	public boolean useExternalCounter() {
		return client.useExternalCounter();
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
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		client.initCipherForEncryptionWithIvAndCounter(cipher, iv, counter);
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
	public AbstractCipher getCipherInstance() throws IOException {
		return client.getCipherInstance();
	}

	@Override
	public RandomOutputStream getCipherOutputStream(RandomOutputStream os, byte[] externalCounter) throws IOException {
		return client.getCipherOutputStream(os, externalCounter);
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
	public long getOutputSizeForEncryption(long inputLen) throws IOException{
		return client.getOutputSizeForEncryption(inputLen);
	}

	@Override
	public boolean includeIV() {
		return client.includeIV();
	}

	@Override
	public void initCipherForEncrypt(AbstractCipher cipher) throws IOException {
		client.initCipherForEncrypt(cipher);
	}

	@Override
	public byte[] initCipherForEncrypt(AbstractCipher cipher, byte[] externalCounter) throws IOException {
		return client.initCipherForEncrypt(cipher, externalCounter);
	}

	@Override
	public void initCipherForEncryptWithNullIV(AbstractCipher cipher) throws IOException {
		client.initCipherForEncryptWithNullIV(cipher);
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return client.isPostQuantumEncryption();
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

		public Client(AbstractSecureRandom random, ASymmetricPublicKey distantPublicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException, IOException {
			super(distantPublicKey.getEncryptionAlgorithmType().getCipherInstance(), 0);
			this.type = distantPublicKey.getEncryptionAlgorithmType();
			this.distantPublicKey = distantPublicKey;
			this.random = random;
			setMaxPlainTextSizeForEncoding(distantPublicKey.getMaxBlockSize());

			initCipherForEncrypt(this.cipher);
			initBufferAllocatorArgs();
		}

		@Override
		public boolean isPostQuantumEncryption() {
			return distantPublicKey.isPostQuantumKey();
		}

		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
			initCipherForEncrypt(cipher);
		}

		@Override
		protected AbstractCipher getCipherInstance() throws IOException {
			try {
				return type.getCipherInstance();
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
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

		public ASymmetricPublicKey getDistantPublicKey() {
			return this.distantPublicKey;
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		public byte[] initCipherForEncrypt(AbstractCipher _cipher, byte[] externalCounter)
				throws IOException {
			initCipherForEncryptWithNullIV(_cipher);
			return null;
		}

		@Override
		public void initCipherForEncryptWithNullIV(AbstractCipher _cipher)
				throws IOException {
			try {
				_cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey, random);
			} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
				throw new IOException(e);
			}

		}


		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return 0;
		}
	}
}
