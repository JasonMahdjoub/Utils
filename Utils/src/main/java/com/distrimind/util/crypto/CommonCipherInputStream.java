package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.DataInputStream;
import java.io.EOFException;
import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.0.0
 */
abstract class CommonCipherInputStream extends RandomInputStream {
	private long pos=0;
	private boolean closed=false;

	private final int maxEncryptedPartLength;
	private final RandomInputStream is;
	private final boolean includeIV;
	private final byte[] iv;
	private final int IVSizeBytesWithoutExternalCounter;
	private final byte[] externalCounter;
	protected final AbstractCipher cipher;
	private final byte[] associatedData;
	private final int offAD, lenAD;
	private final byte[] buffer;
	private byte[] outputBuffer;
	private final boolean supportRandomAccess;
	private final int counterStepInBytes;
	private final int maxPlainTextSizeForEncoding;
	private boolean doFinal=false;
	private int outputBufferLength =0;
	private int outputBufferIndex =0;

	protected abstract void initCipherForDecryptionWithIvAndCounter(byte[] iv, int counter) throws IOException;
	protected abstract void initCipherForDecrypt() throws IOException;

	CommonCipherInputStream(int maxEncryptedPartLength, RandomInputStream is, boolean includeIV, byte[] iv, int IVSizeBytesWithoutExternalCounter, boolean useExternalCounter, byte[] externalCounter, AbstractCipher cipher, byte[] associatedData, int offAD, int lenAD, byte[] buffer, boolean supportRandomAccess, int counterStepInBytes, int maxPlainTextSizeForEncoding) {
		if (useExternalCounter && externalCounter==null)
			throw new NullPointerException("External counter is null");
		else if (!useExternalCounter && externalCounter!=null)
			throw new IllegalArgumentException("External counter be null");
		this.maxEncryptedPartLength = maxEncryptedPartLength;
		this.is = is;
		this.includeIV = includeIV;
		this.iv = iv;
		this.IVSizeBytesWithoutExternalCounter = IVSizeBytesWithoutExternalCounter;
		this.externalCounter = externalCounter;
		this.cipher = cipher;
		this.associatedData = associatedData;
		this.offAD = offAD;
		this.lenAD = lenAD;
		this.buffer = buffer;
		this.outputBuffer=new byte[128];
		this.supportRandomAccess = supportRandomAccess;
		this.counterStepInBytes = counterStepInBytes;
		this.maxPlainTextSizeForEncoding = maxPlainTextSizeForEncoding;
	}

	@Override
	public long length() throws IOException {
		return is.length();
	}
	private long lastLoadedIvPos=-1;

	private int checkInit() throws IOException {
		if (pos!=lastLoadedIvPos && pos%maxEncryptedPartLength==0)
		{
			if (pos<is.length())
			{
				if (includeIV) {
					is.readFully(iv, 0, IVSizeBytesWithoutExternalCounter);
					if (externalCounter!=null)
						System.arraycopy(externalCounter, 0, iv, IVSizeBytesWithoutExternalCounter, externalCounter.length);
					initCipherForDecryptionWithIvAndCounter(iv, 0);
					pos+=IVSizeBytesWithoutExternalCounter;
				}
				else
				{
					initCipherForDecrypt();
				}
				lastLoadedIvPos=pos;
				if (associatedData!=null && lenAD>0)
					cipher.updateAAD(associatedData, offAD, lenAD);
				return maxEncryptedPartLength;
			}
			else
				return 0;

		}
		return (int) (pos % maxEncryptedPartLength);
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		return read(b, off, len, false);
	}

	private void checkDoFinal() throws MessageExternalizationException {
		if (doFinal && pos%maxEncryptedPartLength==0)
		{
			try {
				outputBufferLength +=cipher.doFinal(outputBuffer, outputBufferIndex);
				doFinal=false;
			} catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			}
		}
	}

	private int readOutputBuffer(final byte[] b, int off, final int len) {
		if (outputBufferLength >0) {
			int s=Math.min(len, outputBufferLength);
			System.arraycopy(outputBuffer, outputBufferIndex, b, off, s);
			outputBufferIndex +=s;
			if (outputBufferIndex == outputBufferLength)
			{
				outputBufferIndex =0;
				outputBufferLength =0;
			}
			else
				outputBufferLength -=s;
			return s;
		}
		else
			return 0;
	}
	private int readOutputBuffer() {
		if (outputBufferLength >0) {
			int v=outputBuffer[outputBufferIndex++] & 0xFF;
			if (outputBufferIndex == outputBufferLength)
			{
				outputBufferIndex =0;
				outputBufferLength =0;
			}
			else
				--outputBufferLength;
			return v;
		}
		else
			return -1;
	}
	private int read(final byte[] b, int off, final int originalLen, final boolean fully) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		int len=originalLen;
		checkLimits(b, off, len);
		int total=0;
		do {
			int s= readOutputBuffer(b, off, len);
			len-=s;
			off+=s;
			total+=s;
			if (len==0)
				return total;
			s=checkInit();
			if (s<=0)
			{
				if (fully) {
					if (total!=originalLen)
						throw new IOException();
				}
				else if (total==0)
					return -1;
				else
					return total;
			}
			s=Math.min(s, len);

			do {
				int s3=Math.min(s, buffer.length);
				try {
					int s2=is.read(buffer, 0, s3);
					pos+=s2;
					if (s2==-1)
					{
						checkDoFinal();
						s= readOutputBuffer(b, off, len);
						total+=s;
						if (fully)
						{
							if (total!=originalLen)
								throw new EOFException();
						}
						if (total==0)
						{
							return -1;
						}
						else
							return total;
					}
					int w;
					if (s2>0) {
						int outLen=cipher.getOutputSize(s2);
						if (outLen>len)
						{
							outLen+=outputBufferLength+outputBufferIndex;
							if (outLen>outputBuffer.length)
							{
								byte[] t=new byte[outLen];
								System.arraycopy(outputBuffer, outputBufferIndex, t, 0, outputBufferLength);
								outputBufferIndex=0;
								outputBuffer=t;
							}
							w = cipher.update(buffer, 0, s2, outputBuffer, outputBufferIndex+outputBufferLength);
							outputBufferLength+=w;
							w=readOutputBuffer(b, off, len);
						}
						else
							w = cipher.update(buffer, 0, s2, b, off);
						doFinal = true;
					}
					else
						w=0;

					s-=s2;
					total+=w;
					off+=w;
					len-=w;

					if (!fully && s3!=s2)
						return total;
				} catch (ShortBufferException e) {
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
				}

			} while(s>0);
			if (pos%maxEncryptedPartLength==0)
				checkDoFinal();
		} while (len>0);
		return total;
	}
	private final byte[] one=new byte[1];
	@Override
	public int read() throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		checkInit();
		int v= readOutputBuffer();
		if (v>=0)
			return v;
		v=is.read(one, 0, 1);
		++pos;
		if (v<0) {
			checkDoFinal();
			return readOutputBuffer();
		}
		else
		{
			try
			{
				int w=cipher.update(one, 0, 1, outputBuffer, outputBufferLength);
				doFinal = true;
				if (w>0) {
					outputBufferLength+=w;

					checkDoFinal();
					return readOutputBuffer();
				}
				else
					return -1;
			} catch (ShortBufferException e) {
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
			}

		}
	}

	@Override
	public void seek(long _pos) throws IOException {
		if (closed)
			throw new IOException("Stream closed");
		if (_pos<0)
			throw new IllegalArgumentException();
		if (_pos>is.length())
			throw new IllegalArgumentException();
		if (!supportRandomAccess)
			throw new IOException("Random decryption impossible");

		if (includeIV) {
			long p = _pos / maxEncryptedPartLength ;
			is.seek(p);
			is.readFully(iv, 0, IVSizeBytesWithoutExternalCounter);
			lastLoadedIvPos=pos+IVSizeBytesWithoutExternalCounter;
			if (externalCounter!=null)
				System.arraycopy(externalCounter, 0, iv, IVSizeBytesWithoutExternalCounter, externalCounter.length);

			int counter = (int) (_pos % maxEncryptedPartLength)-IVSizeBytesWithoutExternalCounter;

			if (counter > 0) {
				p += IVSizeBytesWithoutExternalCounter + (counter = cipher.getOutputSize(counter));
				counter /= counterStepInBytes;

			}
			else
				counter=0;
			is.seek(pos=p);
			initCipherForDecryptionWithIvAndCounter(iv, counter);
		}
		else
		{
			long add=cipher.getOutputSize((int)(_pos % maxEncryptedPartLength));
			is.seek(pos=((lastLoadedIvPos=_pos / maxEncryptedPartLength * maxPlainTextSizeForEncoding)+add));
			initCipherForDecrypt();
		}
		if (associatedData != null && lenAD > 0)
			cipher.updateAAD(associatedData, offAD, lenAD);

	}

	@Override
	public long currentPosition() {
		return pos;
	}

	@Override
	public boolean isClosed() {
		return closed;
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException {
		//noinspection ResultOfMethodCallIgnored
		read(tab, off, len, true);
	}

	@Override
	public void close() {
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
