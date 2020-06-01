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
 * @version 3.1
 * @since Utils 1.4
 */
public class P2PASymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm {

	private final AbstractEncryptionIOAlgorithm p2pencryption;

	public P2PASymmetricEncryptionAlgorithm(AbstractKeyPair<?, ?> myKeyPair, IASymmetricPublicKey distantPublicKey)
			throws IOException {
		super();
		if (distantPublicKey == null)
			throw new NullPointerException("distantPublicKey");
		try {
			if (myKeyPair instanceof HybridASymmetricKeyPair && distantPublicKey instanceof HybridASymmetricPublicKey) {
				p2pencryption = new HybridP2PEncryption((HybridASymmetricKeyPair) myKeyPair, (HybridASymmetricPublicKey) distantPublicKey);
			} else if (myKeyPair instanceof ASymmetricKeyPair && distantPublicKey instanceof ASymmetricPublicKey)
				p2pencryption = new P2PEncryption((ASymmetricKeyPair) myKeyPair, (ASymmetricPublicKey) distantPublicKey);
			else
				throw new IllegalArgumentException();
		} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}
	public P2PASymmetricEncryptionAlgorithm(ASymmetricAuthenticatedSignatureType nonPQCSignatureType,
											ASymmetricAuthenticatedSignatureType PQCSignatureType,
											HybridASymmetricKeyPair myKeyPair, HybridASymmetricPublicKey distantPublicKey)
			throws IOException {
		super();
		if (distantPublicKey == null)
			throw new NullPointerException("distantPublicKey");
		p2pencryption=new HybridP2PEncryption(nonPQCSignatureType, PQCSignatureType, myKeyPair, distantPublicKey);
	}

	public P2PASymmetricEncryptionAlgorithm(ASymmetricAuthenticatedSignatureType signatureType, ASymmetricKeyPair myKeyPair,
						 ASymmetricPublicKey distantPublicKey) throws IOException {
		super();
		try {
			p2pencryption=new P2PEncryption(signatureType, myKeyPair, distantPublicKey);
		} catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	@Override
	public int getMaxPlainTextSizeForEncoding() {
		return p2pencryption.getMaxPlainTextSizeForEncoding();
	}

	@Override
	void setMaxPlainTextSizeForEncoding(int maxPlainTextSizeForEncoding) throws IOException {
		p2pencryption.setMaxPlainTextSizeForEncoding(maxPlainTextSizeForEncoding);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length, byte[] externalCounter)
			throws IOException
	{
		p2pencryption.decode(is, associatedData, offAD, lenAD, os, lenAD, externalCounter );
	}
	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {
		p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD, os, externalCounter);
	}
	@Override
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {
		p2pencryption.encode(is, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public CommonCipherOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] externalCounter) throws IOException {
		return p2pencryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, externalCounter);
	}

	@Override
	public byte[] decode(byte[] bytes) throws IOException {
		return p2pencryption.decode(bytes);
	}

	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException {
		return p2pencryption.decode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] decode(byte[] bytes, byte[] associatedData) throws IOException {
		return p2pencryption.decode(bytes, associatedData);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len) throws IOException {
		return p2pencryption.decode(bytes, off, len);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return p2pencryption.decode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] decode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pencryption.decode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData) throws IOException {
		return p2pencryption.decode(is, associatedData);
	}

	@Override
	public byte[] decode(RandomInputStream is) throws IOException {
		return p2pencryption.decode(is);
	}

	@Override
	protected boolean mustAlterIVForOutputSizeComputation() {
		return p2pencryption.mustAlterIVForOutputSizeComputation();
	}

	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return p2pencryption.decode(is, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pencryption.decode(is, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException {
		p2pencryption.decode(is, associatedData, os);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, byte[] externalCounter) throws IOException {
		p2pencryption.decode(is, os, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os) throws IOException {
		p2pencryption.decode(is, os);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {
		p2pencryption.decode(is, associatedData, offAD, lenAD, os);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, byte[] externalCounter) throws IOException {
		p2pencryption.decode(is, associatedData, offAD, lenAD, os, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, int length) throws IOException {
		p2pencryption.decode(is, os, length);
	}

	@Override
	public void decode(RandomInputStream is, RandomOutputStream os, int length, byte[] externalCounter) throws IOException {
		p2pencryption.decode(is, os, length, externalCounter);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, RandomOutputStream os, int length) throws IOException {
		p2pencryption.decode(is, associatedData, os, length);
	}

	@Override
	public void decode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os, int length) throws IOException {
		p2pencryption.decode(is, associatedData, offAD, lenAD, os, length);
	}

	@Override
	public CommonCipherInputStream getCipherInputStreamForDecryption(RandomInputStream is) throws IOException {
		return p2pencryption.getCipherInputStreamForDecryption(is);
	}


	@Override
	public byte[] encode(byte[] bytes) throws IOException {
		return p2pencryption.encode(bytes);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData) throws IOException {
		return p2pencryption.encode(bytes, associatedData);
	}

	@Override
	public byte[] encode(byte[] bytes, byte[] associatedData, byte[] externalCounter) throws IOException {
		return p2pencryption.encode(bytes, associatedData, externalCounter);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len) throws IOException {
		return p2pencryption.encode(bytes, off, len);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD);
	}

	@Override
	public byte[] encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, RandomOutputStream os) throws IOException {
		p2pencryption.encode(bytes, off, len, os);
	}

	@Override
	public void encode(byte[] bytes, int off, int len, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {
		p2pencryption.encode(bytes, off, len, associatedData, offAD, lenAD, os);
	}

	@Override
	public void encode(RandomInputStream is, RandomOutputStream os) throws IOException {
		p2pencryption.encode(is, os);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, RandomOutputStream os) throws IOException {
		p2pencryption.encode(is, associatedData, os);
	}

	@Override
	public void encode(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, RandomOutputStream os) throws IOException {
		p2pencryption.encode(is, associatedData, offAD, lenAD, os);
	}


	@Override
	protected byte[] readIV(RandomInputStream is, byte[] externalCounter) throws IOException {
		return p2pencryption.readIV(is, externalCounter);
	}

	@Override
	public CommonCipherInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] externalCounter) throws IOException {
		return p2pencryption.getCipherInputStreamForDecryption(is, externalCounter);
	}

	@Override
	public CommonCipherInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return p2pencryption.getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD);
	}

	@Override
	protected byte[][] readIvsFromEncryptedStream(RandomInputStream is) throws IOException {
		return p2pencryption.readIvsFromEncryptedStream(is);
	}

	@Override
	protected boolean allOutputGeneratedIntoDoFinalFunction() {
		return false;
	}

	@Override
	protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		p2pencryption.initCipherForEncryptionWithIvAndCounter(cipher, iv, counter);
	}

	@Override
	protected int getCounterStepInBytes() {
		return p2pencryption.getCounterStepInBytes();
	}

	@Override
	public boolean supportRandomEncryptionAndRandomDecryption() {
		return p2pencryption.supportRandomEncryptionAndRandomDecryption();
	}



	@Override
	protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
		p2pencryption.initCipherForDecryptionWithIvAndCounter(cipher, iv, counter);
	}

	@Override
	public void initCipherForDecryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
		p2pencryption.initCipherForDecryptionWithIv(cipher, iv);
	}


	@Override
	protected void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
		p2pencryption.initCipherForEncryptionWithIv(cipher, iv);
	}

	@Override
	public CommonCipherInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pencryption.getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	public void initCipherForDecryption(AbstractCipher cipher) throws IOException {
		p2pencryption.initCipherForDecryption(cipher);
	}

	@Override
	public long getOutputSizeAfterDecryption(long inputLen) throws IOException {
		return p2pencryption.getOutputSizeAfterDecryption(inputLen);
	}

	@Override
	public CommonCipherOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream) throws IOException {
		return p2pencryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream);
	}

	@Override
	public CommonCipherOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return p2pencryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD);
	}

	@Override
	public CommonCipherOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
		return p2pencryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter);
	}

	@Override
	protected CommonCipherOutputStream getCipherOutputStreamForEncryption(RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter, byte[][] manualIvs) throws IOException {
		return p2pencryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, manualIvs);
	}

	@Override
	public void initCipherForDecryption(AbstractCipher cipher, byte[] iv, byte[] externalCounter) throws IOException {
		p2pencryption.initCipherForDecryption(cipher, iv, externalCounter);
	}

	@Override
	public AbstractCipher getCipherInstance() throws IOException {
		return p2pencryption.getCipherInstance();
	}

	@Override
	public int getIVSizeBytesWithExternalCounter() {
		return p2pencryption.getIVSizeBytesWithExternalCounter();
	}

	@Override
	protected boolean includeIV() {
		return p2pencryption.includeIV();
	}

	@Override
	public byte[] initCipherForEncryption(AbstractCipher cipher, byte[] externalCounter) throws IOException {
		return p2pencryption.initCipherForEncryption(cipher, externalCounter);
	}

	@Override
	public void initCipherForEncryptionWithNullIV(AbstractCipher cipher) throws IOException {
		p2pencryption.initCipherForEncryptionWithNullIV(cipher);
	}

	@Override
	public boolean isPostQuantumEncryption() {
		return p2pencryption.isPostQuantumEncryption();
	}


	@Override
	public byte getBlockModeCounterBytes() {
		return p2pencryption.getBlockModeCounterBytes();
	}

	@Override
	public boolean useExternalCounter() {
		return p2pencryption.useExternalCounter();
	}

	@Override
	public void initBufferAllocatorArgs() throws IOException {
		p2pencryption.initBufferAllocatorArgs();
	}

	@Override
	public long getOutputSizeAfterEncryption(long inputLen) throws IOException {
		return p2pencryption.getOutputSizeAfterEncryption(inputLen);
	}

	@Override
	public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
		p2pencryption.initCipherForEncryption(cipher);
	}

	private static class HybridP2PEncryption extends AbstractEncryptionIOAlgorithm
	{
		private final P2PEncryption nonPQCEncryption, PQCEncryption;
		private final HybridASymmetricKeyPair myKeyPair;
		private final HybridASymmetricPublicKey distantPublicKey;

		public HybridP2PEncryption(HybridASymmetricKeyPair myKeyPair,
							 HybridASymmetricPublicKey distantPublicKey) throws IOException {
			super();
			try {
				nonPQCEncryption=new P2PEncryption(myKeyPair.getNonPQCKeyPair(), distantPublicKey.getNonPQCPublicKey());PQCEncryption=new P2PEncryption(myKeyPair.getPQCKeyPair(), distantPublicKey.getPQCPublicKey());
				if (nonPQCEncryption.includeIV()!=PQCEncryption.includeIV())
					throw new IllegalArgumentException();
				this.myKeyPair=myKeyPair;
				this.distantPublicKey=distantPublicKey;
				//setMaxPlainTextSizeForEncoding(getMaxPlainTextSizeForEncoding());

			} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
				throw new IOException(e);
			}

		}

		public HybridP2PEncryption(ASymmetricAuthenticatedSignatureType nonPQCSignatureType,
								   ASymmetricAuthenticatedSignatureType PQCSignatureType,
								   HybridASymmetricKeyPair myKeyPair,
								   HybridASymmetricPublicKey distantPublicKey) throws IOException {
			super();
			try {
				nonPQCEncryption = new P2PEncryption(nonPQCSignatureType, myKeyPair.getNonPQCKeyPair(), distantPublicKey.getNonPQCPublicKey());
				PQCEncryption = new P2PEncryption(PQCSignatureType, myKeyPair.getPQCKeyPair(), distantPublicKey.getPQCPublicKey());
				if (nonPQCEncryption.includeIV() != PQCEncryption.includeIV())
					throw new IllegalArgumentException();
				this.myKeyPair = myKeyPair;
				this.distantPublicKey = distantPublicKey;
				setMaxPlainTextSizeForEncoding(Math.min(nonPQCEncryption.getMaxPlainTextSizeForEncoding(), PQCEncryption.getMaxPlainTextSizeForEncoding()));
			} catch (NoSuchPaddingException | NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}



		@Override
		public void initCipherForDecryption(AbstractCipher cipher, byte[] iv, byte[] externalCounter)  {
			throw new IllegalAccessError();
		}

		@Override
		protected void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
			initCipherForEncryption(cipher );
		}

		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
			initCipherForEncryption(cipher );
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
		public int getIVSizeBytesWithExternalCounter() {
			return Math.max(nonPQCEncryption.getIVSizeBytesWithExternalCounter(), PQCEncryption.getIVSizeBytesWithExternalCounter());
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		public byte[] initCipherForEncryption(AbstractCipher cipher, byte[] externalCounter) {
			throw new IllegalAccessError();
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
		protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) {
			initCipherForDecryption(cipher);
		}

		@Override
		public void initCipherForDecryptionWithIv(AbstractCipher cipher, byte[] iv) {
			initCipherForDecryption(cipher);
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
		protected CommonCipherOutputStream getCipherOutputStreamForEncryption(final RandomOutputStream os, boolean closeOutputStreamWhenClosingCipherOutputStream, byte[] associatedData, int offAD, int lenAD, final byte[] externalCounter, byte[][] manualIVs) throws IOException {
			return nonPQCEncryption.getCipherOutputStreamForEncryption(PQCEncryption.getCipherOutputStreamForEncryption(os, closeOutputStreamWhenClosingCipherOutputStream, associatedData, offAD, lenAD, externalCounter, manualIVs), true, associatedData, offAD, lenAD, externalCounter, manualIVs);
		}

		@Override
		public CommonCipherInputStream getCipherInputStreamForDecryption(RandomInputStream is, byte[] associatedData, int offAD, int lenAD, byte[] externalCounter) throws IOException {
			return nonPQCEncryption.getCipherInputStreamForDecryption(PQCEncryption.getCipherInputStreamForDecryption(is, associatedData, offAD, lenAD, externalCounter), associatedData, offAD, lenAD, externalCounter);
		}



		@Override
		public void initCipherForDecryption(AbstractCipher cipher) {
			initCipherForDecryption(cipher, null, null);
		}
	}

	public IASymmetricPublicKey getDistantPublicKey() {
		if (this.p2pencryption instanceof P2PEncryption)
			return ((P2PEncryption)p2pencryption).getDistantPublicKey();
		else
			return ((HybridP2PEncryption)p2pencryption).distantPublicKey;
	}
	public AbstractKeyPair<?, ?> getMyKeyPair() {
		if (this.p2pencryption instanceof P2PEncryption)
			return ((P2PEncryption)p2pencryption).getMyKeyPair();
		else
			return ((HybridP2PEncryption)p2pencryption).myKeyPair;
	}



	private static class P2PEncryption extends AbstractEncryptionIOAlgorithm {
		private final ASymmetricKeyPair myKeyPair;

		private final ASymmetricPublicKey distantPublicKey;

		private final ASymmetricEncryptionType type;

		private final ASymmetricAuthenticatedSignatureType signatureType;

		@Override
		public boolean isPostQuantumEncryption() {
			return myKeyPair.isPostQuantumKey() && distantPublicKey.isPostQuantumKey();
		}

		public P2PEncryption(ASymmetricKeyPair myKeyPair, ASymmetricPublicKey distantPublicKey)
				throws NoSuchAlgorithmException, NoSuchPaddingException,
				NoSuchProviderException, IOException {
			this(myKeyPair.getEncryptionAlgorithmType().getDefaultSignatureAlgorithm(), myKeyPair, distantPublicKey);
		}

		public P2PEncryption(ASymmetricAuthenticatedSignatureType signatureType, ASymmetricKeyPair myKeyPair,
												ASymmetricPublicKey distantPublicKey) throws IOException, NoSuchPaddingException, NoSuchAlgorithmException, NoSuchProviderException {
			super(myKeyPair.getEncryptionAlgorithmType().getCipherInstance(), 0);
			if (signatureType == null)
				throw new NullPointerException("signatureType");
			if (distantPublicKey == null)
				throw new NullPointerException("distantPublicKey");

			this.type = myKeyPair.getEncryptionAlgorithmType();
			this.myKeyPair = myKeyPair;
			this.distantPublicKey = distantPublicKey;
			this.signatureType = signatureType;
			setMaxPlainTextSizeForEncoding(distantPublicKey.getMaxBlockSize());
			initBufferAllocatorArgs();
		}

		@Override
		protected void initCipherForEncryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
			initCipherForEncryption(cipher );
		}


		@Override
		protected void initCipherForEncryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
			initCipherForEncryption(cipher );
		}


		@Override
		public AbstractCipher getCipherInstance() throws IOException {
			try {
				return type.getCipherInstance();
			} catch (NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

		@Override
		public void initCipherForEncryption(AbstractCipher cipher) throws IOException {
			initCipherForEncryptionWithNullIV(cipher);
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

		public ASymmetricKeyPair getMyKeyPair() {
			return this.myKeyPair;
		}

		public ASymmetricAuthenticatedSignatureType getSignatureType() {
			return signatureType;
		}

		@Override
		protected boolean includeIV() {
			return false;
		}

		@Override
		protected void initCipherForDecryptionWithIvAndCounter(AbstractCipher cipher, byte[] iv, int counter) throws IOException {
			initCipherForDecryption(cipher);
		}

		@Override
		public void initCipherForDecryptionWithIv(AbstractCipher cipher, byte[] iv) throws IOException {
			initCipherForDecryption(cipher);
		}

		@Override
		protected boolean allOutputGeneratedIntoDoFinalFunction() {
			return false;
		}


		@Override
		public void initCipherForDecryption(AbstractCipher _cipher, byte[] iv, byte[] externalCounter)
				throws IOException {
			initCipherForDecryption(_cipher);
		}

		@Override
		public byte[] initCipherForEncryption(AbstractCipher _cipher, byte[] externalCounter)
				throws IOException {
			initCipherForEncryptionWithNullIV(_cipher);
			return null;
		}

		@Override
		public void initCipherForEncryptionWithNullIV(AbstractCipher _cipher)
				throws IOException {
			try {
				_cipher.init(Cipher.ENCRYPT_MODE, distantPublicKey);
			} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
				throw new IOException(e);
			}

		}


		@Override
		public int getIVSizeBytesWithExternalCounter() {
			return 0;
		}

		@Override
		public void initCipherForDecryption(AbstractCipher cipher) throws IOException {
			try {
				cipher.init(Cipher.DECRYPT_MODE, myKeyPair.getASymmetricPrivateKey());
			} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}

	}
}
