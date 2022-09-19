package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language

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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;
import com.distrimind.util.io.RandomInputStream;

import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.0.0
 */
@SuppressWarnings("NullableProblems")
abstract class CommonCipherInputStream extends RandomInputStream {
	private long posEncrypted;
	private long posPlainText;
	private boolean closed;
	private boolean doFinal;


	private final int maxEncryptedPartLength;
	private RandomInputStream is;
	//private final boolean includeIV;
	private AbstractWrappedIVs<?> wrappedIVAndSecretKey;
	private final int IVSizeBytesWithoutExternalCounter;
	private byte[] externalCounter;
	protected AbstractCipher cipher;
	private byte[] associatedData;
	private int offAD, lenAD;
	private final byte[] buffer;
	private byte[] outputBuffer;
	private final boolean supportRandomAccess;
	private final int counterStepInBytes;
	private final int maxPlainTextSizeForEncoding;
	private int outputBufferLength =0;
	private int outputBufferIndex =0;
	private Long length;
	private final boolean allInDoFinal;
	private boolean initPossible;
	private final boolean includeIV;

	protected abstract void initCipherForDecryptionWithIvAndCounter(AbstractWrappedIVs<?> wrappedIVAndSecretKey, int counter) throws IOException;
	protected abstract void initCipherForDecryption() throws IOException;
	protected abstract long getOutputSizeAfterDecryption(long inputLength) throws IOException;

	CommonCipherInputStream(IClientServer iEncryptionInputAlgorithm, boolean allInDoFinal, int maxEncryptedPartLength, RandomInputStream is, boolean includeIV, int IVSizeBytesWithoutExternalCounter, byte maxCounterLength, byte[] externalCounter, AbstractCipher cipher, byte[] associatedData, int offAD, int lenAD, byte[] buffer, boolean supportRandomAccess, int counterStepInBytes, int maxPlainTextSizeForEncoding) throws IOException {
		if (maxCounterLength>0) {
			if (externalCounter == null)
				throw new NullPointerException("External counter is null");
			if (externalCounter.length > maxCounterLength)
				throw new IllegalArgumentException("maxCounterLength="+maxCounterLength+", externalCounter.length="+externalCounter.length);
		}
		else{
			if (externalCounter!=null)
				throw new IllegalArgumentException("External counter be null");
		}
		this.includeIV=includeIV;
		this.allInDoFinal=allInDoFinal;
		this.maxEncryptedPartLength = maxEncryptedPartLength;
		this.IVSizeBytesWithoutExternalCounter = IVSizeBytesWithoutExternalCounter;
		this.cipher = cipher;
		this.buffer = buffer;
		this.supportRandomAccess = supportRandomAccess;
		this.counterStepInBytes = counterStepInBytes;
		this.maxPlainTextSizeForEncoding = maxPlainTextSizeForEncoding;
		set(iEncryptionInputAlgorithm, is, associatedData, offAD, lenAD, externalCounter);
	}
	protected abstract void checkKeysNotCleaned();
	@SuppressWarnings("unchecked")
	static void set(IClientServer iEncryptionInputAlgorithm, final RandomInputStream cipherInputStream, final RandomInputStream is, final byte[] associatedData, @SuppressWarnings("SameParameterValue") final int offAD, final int lenAD, final byte[] externalCounter) throws IOException {
		if (cipherInputStream instanceof CPUUsageAsDecoyInputStream) {
			CPUUsageAsDecoyInputStream<CommonCipherInputStream> o=((CPUUsageAsDecoyInputStream<CommonCipherInputStream>) cipherInputStream);
			o.reset();
			o.getSourceRandomInputStream()
					.set(iEncryptionInputAlgorithm, is, associatedData, offAD, lenAD, externalCounter);
		}
		else
			((CommonCipherInputStream)cipherInputStream)
					.set(iEncryptionInputAlgorithm, is, associatedData, offAD, lenAD, externalCounter);
	}
	private void set(IClientServer iEncryptionInputAlgorithm, final RandomInputStream is, final byte[] associatedData, final int offAD, final int lenAD, final byte[] externalCounter) throws IOException {
		checkKeysNotCleaned();
		posEncrypted =0;
		posPlainText=0;
		closed=false;
		doFinal=false;
		initPossible=true;
		this.is = is;
		this.externalCounter = externalCounter;
		this.associatedData = associatedData;
		this.offAD = offAD;
		this.lenAD = lenAD;
		this.outputBuffer=null;
		this.wrappedIVAndSecretKey=iEncryptionInputAlgorithm.getWrappedIVAndSecretKeyInstance();
		if (includeIV == (wrappedIVAndSecretKey == null))
			throw new IllegalArgumentException(""+includeIV);
		if (is.currentPosition()!=0)
			is.seek(0);
	}

	@Override
	public long length() throws IOException {
		if (length==null)
			length= getOutputSizeAfterDecryption(is.length());
		return length;
	}

	private int checkInit() throws IOException {
		long mod= posEncrypted %maxEncryptedPartLength;
		if (mod==0)
		{
			checkDoFinal(false);
			if (is.available()>0)
			{
				if (initPossible) {
					if (wrappedIVAndSecretKey != null) {
						wrappedIVAndSecretKey.pushNewElementAndSetCurrentIV(0, is, externalCounter);
						initCipherForDecryptionWithIvAndCounter(wrappedIVAndSecretKey, 0);
						posEncrypted += IVSizeBytesWithoutExternalCounter;
					} else {
						initCipherForDecryption();
					}
					if (associatedData != null && lenAD > 0)
						cipher.updateAAD(associatedData, offAD, lenAD);
					mod = posEncrypted % maxEncryptedPartLength;
					initPossible = false;
				}
			}
			else
				return 0;

		}
		return (int) ( maxEncryptedPartLength-mod);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return read(b, off, len, false);
	}
	private void checkOutputBuffer() throws IOException {
		if (outputBuffer==null)
			outputBuffer=new byte[128+cipher.getOutputSize(this.buffer.length)];
	}
	private void checkDoFinal(boolean endStream) throws IOException {
		if (doFinal && (posEncrypted %maxEncryptedPartLength==0 || endStream))
		{
			try {
				if (allInDoFinal || cipher.getClass()==BCMcElieceCipher.class)
				{
					byte[] f=cipher.doFinal();
					if (outputBufferLength>0) {
						int l = f.length + outputBufferLength;
						if (outputBuffer.length < l + outputBufferIndex) {
							byte[] b = new byte[l];
							System.arraycopy(outputBuffer, outputBufferIndex, b, 0, outputBufferLength);
							System.arraycopy(f, 0, b, outputBufferLength, f.length);
							outputBufferIndex = 0;
							outputBuffer=b;
						}
						else
							System.arraycopy(f, 0, outputBuffer, outputBufferIndex+outputBufferLength, f.length);
						outputBufferLength+=f.length;
					}
					else
					{
						outputBuffer=f;
						outputBufferLength=f.length;
						outputBufferIndex=0;
					}
				}
				else {
					outputBufferLength += cipher.doFinal(outputBuffer, outputBufferLength + outputBufferIndex);
				}
				doFinal=false;
			} catch (IllegalStateException e) {
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			}
		}
	}

	private int readOutputBuffer(final byte[] b, int off, final int len) {
		if (outputBufferLength >0) {
			int s=Math.min(len, outputBufferLength);
			System.arraycopy(outputBuffer, outputBufferIndex, b, off, s);
			posPlainText+=s;
			outputBufferLength-=s;
			if (outputBufferLength<=0)
			{
				outputBufferIndex =0;
				outputBufferLength =0;
			}
			else
				outputBufferIndex +=s;
			return s;
		}
		else
			return 0;
	}
	private int readOutputBuffer() {
		if (outputBufferLength >0) {
			int v=outputBuffer[outputBufferIndex++] & 0xFF;
			++posPlainText;
			if (--outputBufferLength==0)
			{
				outputBufferIndex =0;
			}
			return v;
		}
		else
			return -1;
	}
	private int read(final byte[] b, int off, final int originalLen, final boolean fully) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		checkLimits(b, off, originalLen);
		if (originalLen==0)
			return 0;
		int len=originalLen;

		int total=0;
		do {

			int s = checkInit();
			int s2 = readOutputBuffer(b, off, len);
			len -= s2;
			off += s2;
			total += s2;
			if (len == 0) {
				return total;
			}
			if (s <= 0) {
				checkDoFinal(true);
				if (fully) {
					if (total != originalLen)
						throw new IOException();
				} else if (total == 0)
					return -1;
				else
					return total;
			}
			s = Math.min(s, len);
			checkOutputBuffer();
			do {
				int s3 = Math.min(s, buffer.length);
				s2 = is.read(buffer, 0, s3);

				if (s2 == -1) {
					//length=is.currentPosition();
					checkDoFinal(true);
					s = readOutputBuffer(b, off, len);
					total += s;
					if (fully) {
						if (total != originalLen)
							throw new EOFException();
					}
					if (total == 0) {
						return -1;
					} else
						return total;
				}
				posEncrypted += s2;

				if (s2 > 0) {
					int w = cipher.update(buffer, 0, s2, b, off);
					posPlainText += w;
					total += w;
					off += w;
					len -= w;
					doFinal = true;
					initPossible = true;
				}

				s -= s2;

				if (!fully && s3 != s2)
					return total;

			} while (s > 0);
			checkDoFinal(false);
		} while (len > 0);
		return total;

	}
	private final byte[] one=new byte[1];
	@Override
	public int read() throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		for (;;) {
			checkInit();
			int v = readOutputBuffer();
			if (v >= 0)
				return v;
			v = is.read(one, 0, 1);
			++posEncrypted;
			if (v < 0) {
				checkOutputBuffer();
				checkDoFinal(true);
				return readOutputBuffer();
			} else {

				int w = cipher.update(one, 0, 1, outputBuffer, outputBufferLength);

				doFinal = true;
				initPossible=true;
				if (w > 0) {
					outputBufferLength += w;
					posPlainText += w;
					return readOutputBuffer();
				}

			}
		}
	}
	protected abstract long getOutputSizeAfterEncryption(long length) throws IOException;

	@Override
	public void seek(final long _pos) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		if (_pos<0)
			throw new IllegalArgumentException();
		if (_pos>length())
			throw new IllegalArgumentException();
		if (!supportRandomAccess)
			throw new IOException("Random decryption impossible");

		if (wrappedIVAndSecretKey!=null) {
			long counter = _pos % maxPlainTextSizeForEncoding;
			if (counter%counterStepInBytes!=0)
				throw new IOException("The position is not aligned with the cipher block size");
			long round=_pos / maxPlainTextSizeForEncoding;
			long p = round*maxEncryptedPartLength;
			is.seek(p);
			wrappedIVAndSecretKey.pushNewElementAndSetCurrentIV(round, is, externalCounter);

			p += counter+IVSizeBytesWithoutExternalCounter;
			counter/=counterStepInBytes;
			is.seek(posEncrypted =p);
			initCipherForDecryptionWithIvAndCounter(wrappedIVAndSecretKey, (int)counter);
		}
		else
		{
			long add=cipher.getOutputSize((int)(_pos % maxPlainTextSizeForEncoding));
			is.seek(posEncrypted =((_pos / maxPlainTextSizeForEncoding * maxEncryptedPartLength)+add));
			initCipherForDecryption();
		}
		posPlainText=_pos;
		if (associatedData != null && lenAD > 0)
			cipher.updateAAD(associatedData, offAD, lenAD);

	}

	@Override
	public long currentPosition() {
		return posPlainText;
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		read(tab, off, len, true);
	}

	@Override
	public void close() throws IOException {
		if (closed)
			return;

		closed=true;

	}

	@Deprecated
	@Override
	public String readLine() throws IOException {
		return new DataInputStream(this).readLine();
	}

}
