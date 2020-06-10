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

import com.distrimind.util.Bits;
import com.distrimind.util.io.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 4.16.0
 */
@SuppressWarnings("UnusedReturnValue")
public class EncryptionSignatureHashEncoder {

	static final MessageDigestType defaultMessageType=MessageDigestType.SHA2_256;
	public static final int maxKeyIdentifierValue=(1<<16)-1;
	static final int headSize=11;
	static final int headSizeMinusOne=headSize-1;
	static void checkLimits(byte[] data, int off, int len)
	{
		if (data==null)
			throw new NullPointerException();
		if (data.length==0)
			throw new IllegalArgumentException();
		if (off<0 || off>=data.length)
			throw new IllegalArgumentException();
		if (len<=0)
			throw new IllegalArgumentException();
		if (off+len>data.length)
			throw new IllegalArgumentException();
	}
	static byte getCode(byte[] associatedData, SymmetricSecretKey secretKeyForSignature, ASymmetricKeyPair keyPair, MessageDigestType messageDigestType)
	{
		int res=(secretKeyForSignature==null || !secretKeyForSignature.useAuthenticatedSignatureAlgorithm())?0:1;
		res+=(keyPair==null || !keyPair.useAuthenticatedSignatureAlgorithm())?0:2;
		res+=messageDigestType==null?0:4;
		res+=associatedData==null?0:8;
		return (byte)res;

	}
	private byte getCode()
	{
		if (code==null)
		{
			if (associatedData != null && (cipher == null || !cipher.getType().supportAssociatedData()) && symmetricSigner == null && asymmetricSigner == null)
				throw new IllegalArgumentException();
			int res = symmetricSigner == null ? 0 : 1;
			res += asymmetricSigner == null ? 0 : 2;
			res += digest == null ? 0 : 4;
			res += associatedData == null ? 0 : 8;
			res += cipher == null ? 0 : 16;
			code=(byte)res;
		}
		return code;
	}


	RandomInputStream inputStream=null;
	private SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	private SymmetricAuthenticatedSignerAlgorithm symmetricSigner=null;
	private ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner=null;
	private AbstractMessageDigest digest=null;
	private Long minimumOutputSize=null;
	private byte[] bufferRef=new byte[256];
	private SignerRandomOutputStream signerOut;
	private HashRandomOutputStream hashOut;
	private final LimitedRandomOutputStream limitedRandomOutputStream;
	private static final NullRandomOutputStream nullRandomInputStream=new NullRandomOutputStream();
	private AbstractMessageDigest defaultMessageDigest=null;
	private AbstractEncryptionOutputAlgorithm.CommonCipherOutputStream cipherOutputStream;
	private byte[] externalCounter=null;
	private Byte code=null;
	private short currentKeyID=-1;
	private ROSForEncryption rosForEncryption=null;
	//private SecretKeyProvider secretKeyProvider=null;

	public EncryptionSignatureHashEncoder() throws IOException {
		limitedRandomOutputStream=new LimitedRandomOutputStream(nullRandomInputStream, 0);
	}

	public EncryptionSignatureHashEncoder withRandomInputStream(RandomInputStream inputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()==0)
			throw new IllegalArgumentException();
		this.inputStream=inputStream;
		return this;
	}
	public EncryptionSignatureHashEncoder withExternalCounter(byte[] externalCounter) {
		if (externalCounter==null)
			throw new NullPointerException();
		this.externalCounter=externalCounter;
		return this;
	}
	public EncryptionSignatureHashEncoder withSecretKeyProvider(AbstractSecureRandom random, EncryptionProfileProvider encryptionProfileProvider) throws IOException {
		return withSecretKeyProvider(random, encryptionProfileProvider, encryptionProfileProvider.getDefaultKeyID());
	}
	public EncryptionSignatureHashEncoder withSecretKeyProvider(AbstractSecureRandom random, EncryptionProfileProvider encryptionProfileProvider, short keyID) throws IOException {
		if (random==null)
			throw new NullPointerException();
		if (encryptionProfileProvider ==null)
			throw new NullPointerException();
		SymmetricSecretKey secretKey=encryptionProfileProvider.getSecretKeyForEncryption(keyID, false);
		this.cipher=secretKey==null?null:new SymmetricEncryptionAlgorithm(random, secretKey);
		try {
			MessageDigestType t=encryptionProfileProvider.getMessageDigest(keyID, false);
			this.digest=t==null?null:t.getMessageDigestInstance();
			secretKey=encryptionProfileProvider.getSecretKeyForSignature(keyID, false);
			this.symmetricSigner=secretKey==null?null:new SymmetricAuthenticatedSignerAlgorithm(secretKey);
			IASymmetricPrivateKey privateKey=encryptionProfileProvider.getSecretKeyForPrivateKey(keyID);
			this.asymmetricSigner=privateKey==null?null:new ASymmetricAuthenticatedSignerAlgorithm(privateKey);

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		code=null;
		this.currentKeyID=keyID;
		return this;
	}


	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
	}

	public EncryptionSignatureHashEncoder withCipher(SymmetricEncryptionAlgorithm cipher) {
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		code=null;
		this.currentKeyID=0;
		return this;
	}
	public EncryptionSignatureHashEncoder withoutAssociatedData()
	{
		this.associatedData=null;
		this.offAD=0;
		this.lenAD=0;
		code=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withAssociatedData(byte[] associatedData)
	{
		return withAssociatedData(associatedData, 0, associatedData.length);
	}
	public EncryptionSignatureHashEncoder withAssociatedData(byte[] associatedData, int offAD, int lenAD)
	{
		if (associatedData==null)
			throw new NullPointerException();
		checkLimits(associatedData, offAD, lenAD);
		this.associatedData=associatedData;
		this.offAD=offAD;
		this.lenAD=lenAD;
		code=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForSignature(SymmetricSecretKey secretKeyForSignature) throws IOException {
		if (secretKeyForSignature==null)
			throw new NullPointerException();
		if (!secretKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			return withSymmetricSigner(new SymmetricAuthenticatedSignerAlgorithm(secretKeyForSignature));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}
	public EncryptionSignatureHashEncoder withSymmetricSigner(SymmetricAuthenticatedSignerAlgorithm symmetricSigner) throws IOException {
		if (symmetricSigner==null)
			throw new NullPointerException();
		if (this.cipher!=null && this.cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.symmetricSigner=symmetricSigner;
		minimumOutputSize=null;
		code=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withASymmetricSigner(ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner)
	{
		if (asymmetricSigner==null)
			throw new NullPointerException();
		this.asymmetricSigner=asymmetricSigner;
		minimumOutputSize=null;
		code=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withASymmetricPrivateKeyForSignature(IASymmetricPrivateKey privateKeyForSignature) throws IOException{
		if (privateKeyForSignature==null)
			throw new NullPointerException();
		if (!privateKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			this.asymmetricSigner=new ASymmetricAuthenticatedSignerAlgorithm(privateKeyForSignature);
			minimumOutputSize=null;
			code=null;
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		return this;
	}
	public EncryptionSignatureHashEncoder withMessageDigest(AbstractMessageDigest messageDigest)
	{
		if (digest==null)
			throw new NullPointerException();
		this.digest=messageDigest;
		minimumOutputSize=null;
		code=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			minimumOutputSize=null;
			code=null;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		return this;
	}
	/*private int computeAssociatedData() throws IOException {
		return computeAssociatedData(cipher.getOutputSizeAfterEncryption(inputStream.length()-inputStream.currentPosition()));
	}*/
	private int computeAssociatedData(long dataLen)
	{
		int lenBuffer=headSize+(associatedData!=null?lenAD:0);
		if (bufferRef.length<lenBuffer)
			bufferRef=new byte[lenBuffer];
		Bits.putShort(bufferRef, 0, currentKeyID);
		Bits.putLong(bufferRef, 2, dataLen);
		bufferRef[10]=getCode();
		if (associatedData!=null)
		{
			System.arraycopy(associatedData, offAD, bufferRef, headSize, lenAD);
		}
		return lenBuffer;

	}
	public void encode(final RandomOutputStream originalOutputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();
		try(RandomOutputStream ros=getRandomOutputStream(originalOutputStream, inputStream.length()))
		{
			inputStream.transferTo(ros);
		}
	}
	public RandomOutputStream getRandomOutputStream(final RandomOutputStream originalOutputStream) throws IOException {
		return getRandomOutputStream(originalOutputStream, -1);
	}

	private class ROSForEncryption extends RandomOutputStream
	{
		private RandomOutputStream originalOutputStream;
		private long inputStreamLength;
		private long originalOutputLength;
		private long maximumOutputLengthAfterEncoding;
		private int lenBuffer;
		private byte[] buffer;
		private long dataLen;
		private boolean closed;
		private RandomOutputStream outputStream;
		private AbstractMessageDigest digest;
		private RandomOutputStream dataOutputStream;
		private boolean bufferToInit;
		private ROSForEncryption(final RandomOutputStream originalOutputStream, final long inputStreamLength) throws IOException {
			init(originalOutputStream, inputStreamLength);
		}
		void init(final RandomOutputStream originalOutputStream, final long inputStreamLength) throws IOException {
			if (originalOutputStream==null)
				throw new NullPointerException();
			if (inputStreamLength<0 && cipher.getType().isAuthenticatedAlgorithm())
				throw new IllegalArgumentException("Cannot use RandomOutputStream for encryption when using authenticated algorithm");
			this.originalOutputStream=originalOutputStream;
			this.inputStreamLength=inputStreamLength;
			this.closed=false;
			try
			{
				//long dataInputLength = inputStream.length();
				if (inputStreamLength==0)
					throw new IllegalArgumentException();
				if (inputStreamLength>0) {
					originalOutputLength = originalOutputStream.length();
					maximumOutputLengthAfterEncoding = getMaximumOutputLength(inputStreamLength);
					originalOutputStream.ensureLength(maximumOutputLengthAfterEncoding);
				}
				else {
					originalOutputLength = -1;
					maximumOutputLengthAfterEncoding = -1;
				}
				byte code = getCode();
				digest = EncryptionSignatureHashEncoder.this.digest;
				if (symmetricSigner != null && asymmetricSigner != null && digest == null) {
					digest = defaultMessageDigest;
					if (digest == null) {
						defaultMessageDigest = digest = defaultMessageType.getMessageDigestInstance();
					}

				}

				outputStream = originalOutputStream;
				if (digest != null) {
					digest.reset();
					if (hashOut == null)
						hashOut = new HashRandomOutputStream(outputStream, digest);
					else
						hashOut.set(outputStream, digest);
					outputStream = hashOut;
				} else if (symmetricSigner != null) {
					symmetricSigner.init();
					if (signerOut == null)
						signerOut = new SignerRandomOutputStream(outputStream, symmetricSigner);
					else
						signerOut.set(outputStream, symmetricSigner);
					outputStream = signerOut;
				} else if (asymmetricSigner != null) {
					asymmetricSigner.init();
					if (signerOut == null)
						signerOut = new SignerRandomOutputStream(outputStream, asymmetricSigner);
					else
						signerOut.set(outputStream, asymmetricSigner);
					outputStream = signerOut;
				}


				originalOutputStream.writeByte(code);
				originalOutputStream.writeShort(currentKeyID);
				buffer = null;
				lenBuffer = 0;
				if (cipher != null) {
					dataLen = inputStreamLength>0?cipher.getOutputSizeAfterEncryption(inputStreamLength):-1;
					originalOutputStream.writeLong(dataLen);
					if (dataLen>0)
						limitedRandomOutputStream.set(outputStream, outputStream.currentPosition(), dataLen);
					else
						limitedRandomOutputStream.set(outputStream, outputStream.currentPosition());

					if (cipher.getType().supportAssociatedData()) {
						lenBuffer = computeAssociatedData(dataLen);
						buffer = bufferRef;
						if (cipherOutputStream == null)
							cipherOutputStream = cipher.getCipherOutputStreamForEncryption(limitedRandomOutputStream, false, buffer, 0, lenBuffer, externalCounter);
						else
							cipherOutputStream.set(limitedRandomOutputStream, null, externalCounter, buffer, 0, lenBuffer, false);
					} else {
						if (cipherOutputStream == null)
							cipherOutputStream = cipher.getCipherOutputStreamForEncryption(limitedRandomOutputStream, false, null, 0, 0, externalCounter);
						else
							cipherOutputStream.set(limitedRandomOutputStream, null, externalCounter, null, 0, 0, false);
					}
					dataOutputStream=cipherOutputStream;
				} else {
					originalOutputStream.writeLong(dataLen = inputStreamLength);
					limitedRandomOutputStream.set(outputStream, outputStream.currentPosition());
					dataOutputStream=limitedRandomOutputStream;
				}
				bufferToInit=false;
				if (outputStream != originalOutputStream && buffer == null) {
					buffer = bufferRef;
					lenBuffer = 10;
					Bits.putShort(buffer, 0, currentKeyID);
					if (dataLen>0) {
						Bits.putLong(buffer, 2, dataLen);
						bufferToInit = true;
					}
				}
			}catch(NoSuchAlgorithmException | NoSuchProviderException e)
			{
				closed=true;
				free();
				throw new IOException(e);
			}

		}

		@Override
		public long length() throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			return dataOutputStream.length();
		}

		@Override
		public void write(byte[] b, int off, int len) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			dataOutputStream.write(b, off, len);
		}

		@Override
		public void setLength(long newLength) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			dataOutputStream.setLength(newLength);
		}

		@Override
		public void seek(long _pos) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			dataOutputStream.setLength(_pos);
		}

		@Override
		public long currentPosition() throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			return dataOutputStream.currentPosition();
		}

		@Override
		public boolean isClosed() {
			return closed;
		}

		@Override
		protected RandomInputStream getRandomInputStreamImpl() throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			return dataOutputStream.getRandomInputStream();
		}

		@Override
		public void flush() throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			dataOutputStream.flush();
		}

		@Override
		public void close() throws IOException {
			if (cipher!=null)
				dataOutputStream.close();
			else
				dataOutputStream.flush();
			if (inputStreamLength<0)
			{
				dataLen=dataOutputStream.currentPosition();
				if (bufferToInit)
					Bits.putLong(buffer, 2, dataLen);
			}


			dataOutputStream=null;

			if (digest!=null) {
				digest.update(code);
				digest.update(buffer, 0, headSizeMinusOne);
				byte []hash = digest.digest();

				if (symmetricSigner != null) {
					symmetricSigner.init();
					if (associatedData!=null)
						symmetricSigner.update(associatedData, offAD, lenAD);
					symmetricSigner.update(hash);
					byte[] signature = symmetricSigner.getSignature();
					digest.reset();
					digest.update(hash);
					digest.update(signature);
					hash=digest.digest();
					originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
				}

				if (asymmetricSigner != null) {
					asymmetricSigner.init();
					asymmetricSigner.update(hash);
					byte[] signature = asymmetricSigner.getSignature();
					digest.reset();
					digest.update(hash);
					digest.update(signature);
					hash=digest.digest();
					originalOutputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
				}
				originalOutputStream.writeBytesArray(hash, false, digest.getDigestLength());
			} else if (symmetricSigner!=null)
			{
				if (lenBuffer==headSizeMinusOne)
					symmetricSigner.update(code);
				symmetricSigner.update(buffer, 0, lenBuffer);
				byte[] signature = symmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.update(code);
				asymmetricSigner.update(buffer, 0, headSizeMinusOne);
				byte[] signature = asymmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
			}
			long curPos=originalOutputStream.currentPosition();
			if (inputStreamLength<0) {
				originalOutputStream.seek(3);
				originalOutputStream.writeLong(dataLen);
				originalOutputStream.seek(curPos);
			}
			if (maximumOutputLengthAfterEncoding>0 && curPos<maximumOutputLengthAfterEncoding && curPos>originalOutputLength) {
				originalOutputStream.setLength(Math.max(curPos, originalOutputLength));
			}
			outputStream.flush();
			free();
			closed=true;
		}

		@Override
		public void write(int b) throws IOException {

		}
	}

	private RandomOutputStream getRandomOutputStream(final RandomOutputStream originalOutputStream, final long inputStreamLength) throws IOException {
		if (rosForEncryption==null)
			rosForEncryption=new ROSForEncryption(originalOutputStream, inputStreamLength);
		else
			rosForEncryption.init(originalOutputStream, inputStreamLength);
		return rosForEncryption;
	}



	public boolean checkPartialHash(SubStreamParameters subStreamParameters, SubStreamHashResult hashResultFromEncryptedStream) throws IOException {
		try {
			AbstractMessageDigest md = subStreamParameters.getMessageDigestType().getMessageDigestInstance();
			md.reset();
			long dataLen=inputStream.length();
			RandomByteArrayOutputStream out=new RandomByteArrayOutputStream(headSize);
			code=getCode();
			out.writeByte(code);
			out.writeShort(currentKeyID);

			if (cipher==null)
			{
				out.writeLong(dataLen);
				out.flush();
				RandomInputStream in=new AggregatedRandomInputStreams(new RandomByteArrayInputStream(out.getBytes()), inputStream);
				byte[] hash=subStreamParameters.partialHash(in, md).digest();
				return Arrays.equals(hash, hashResultFromEncryptedStream.getHash());
			}
			else {
				out.writeLong(dataLen=cipher.getOutputSizeAfterEncryption(dataLen));
				out.flush();

				if (cipher.getType().supportAssociatedData()) {
					lenAD = computeAssociatedData(dataLen);
					associatedData=bufferRef;
					offAD=0;
				}
				return cipher.checkPartialHashWithNonEncryptedStream(out.getBytes(), hashResultFromEncryptedStream, subStreamParameters, inputStream, associatedData, offAD, lenAD, md);
			}
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	private long getMinimumOutputSize()
	{
		if (minimumOutputSize==null)
			minimumOutputSize=getMinimumOutputLengthAfterEncoding();
		return minimumOutputSize;
	}

	public long getMaximumOutputLength() throws IOException {

		return getMaximumOutputLength(inputStream.length());
	}

	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		if (inputStreamLength<=0)
			throw new IllegalArgumentException();
		long res=getMinimumOutputSize();

		if (cipher!=null) {
			res += cipher.getOutputSizeAfterEncryption(inputStreamLength);
		}
		else
			res+=inputStreamLength;
		return res;
	}
	long getMinimumOutputLengthAfterEncoding()
	{
		long res=headSize;

		if (symmetricSigner!=null) {
			int v=symmetricSigner.getMacLengthBytes();
			res += v + (v>Short.MAX_VALUE?4:2);
		}
		if(asymmetricSigner!=null) {
			int v=asymmetricSigner.getMacLengthBytes();
			res += v + (v>Short.MAX_VALUE?4:2);
		}
		if (digest!=null || (asymmetricSigner!=null && symmetricSigner!=null))
		{
			int v;
			if (digest==null) {
				v=defaultMessageType.getDigestLengthInBits() / 8;
			}
			else {
				v=digest.getMessageDigestType().getDigestLengthInBits() / 8;
			}
			if (v>Short.MAX_VALUE)
				v+=4;
			else
				v+=2;
			res+=v;
		}
		return res;
	}


	private void free() throws IOException {
		if (signerOut!=null)
			signerOut.set(nullRandomInputStream, symmetricSigner==null?asymmetricSigner:symmetricSigner);
		if (hashOut!=null)
			hashOut.set(nullRandomInputStream, digest==null?defaultMessageDigest:digest);
		limitedRandomOutputStream.set(nullRandomInputStream, 0);
	}


	public SymmetricSecretKey getSymmetricSecretKeyForEncryption()
	{
		return cipher==null?null:cipher.getSecretKey();
	}

	public SymmetricSecretKey getSymmetricSecretKeyForSignature()
	{
		return symmetricSigner==null?null:symmetricSigner.getSecretKey();
	}

	public IASymmetricPrivateKey getPrivateKeyForSignature()
	{
		return asymmetricSigner==null?null:asymmetricSigner.getPrivateKey();
	}

	public MessageDigestType getMessageDigestType()
	{
		return digest==null?null:digest.getMessageDigestType();
	}

	public EncryptionSignatureHashEncoder withoutSymmetricEncryption()
	{
		cipher=null;
		this.currentKeyID=0;
		minimumOutputSize=null;
		code=null;
		return this;
	}

	public EncryptionSignatureHashEncoder withoutSymmetricSignature()
	{
		symmetricSigner=null;
		minimumOutputSize=null;
		code=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withoutASymmetricSignature()
	{
		asymmetricSigner=null;
		minimumOutputSize=null;
		code=null;
		return this;
	}

	public EncryptionSignatureHashEncoder withoutMessageDigest()
	{
		digest=null;
		minimumOutputSize=null;
		code=null;
		return this;
	}

}
