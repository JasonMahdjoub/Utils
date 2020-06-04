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
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
@SuppressWarnings("UnusedReturnValue")
public class EncryptionSignatureHashEncoder {

	static final MessageDigestType defaultMessageType=MessageDigestType.SHA2_256;
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

	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
	}

	public EncryptionSignatureHashEncoder withCipher(SymmetricEncryptionAlgorithm cipher) {
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		code=null;
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
	public EncryptionSignatureHashEncoder withASymmetricPrivateKeyForSignature(ASymmetricPrivateKey privateKeyForSignature) throws IOException{
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
		int lenBuffer=9+(associatedData!=null?lenAD:0);
		if (bufferRef.length<lenBuffer)
			bufferRef=new byte[lenBuffer];
		Bits.putLong(bufferRef, 0, dataLen);
		bufferRef[8]=getCode();
		if (associatedData!=null)
		{
			System.arraycopy(associatedData, offAD, bufferRef, 9, lenAD);
		}
		return lenBuffer;

	}
	public void encode(final RandomOutputStream originalOutputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();

		if (originalOutputStream==null)
			throw new NullPointerException();

		try {
			long originalOutputLength=originalOutputStream.length();
			long dataInputLength=inputStream.length();
			long maximumOutputLengthAfterEncoding=getMaximumOutputLength(dataInputLength);
			originalOutputStream.ensureLength(maximumOutputLengthAfterEncoding);

			byte code=getCode();
			AbstractMessageDigest digest=this.digest;
			if (symmetricSigner!=null && asymmetricSigner!=null && digest==null) {
				digest = defaultMessageDigest;
				if (digest==null) {
					defaultMessageDigest=digest = defaultMessageType.getMessageDigestInstance();
				}

			}

			RandomOutputStream outputStream=originalOutputStream;
			if (digest!=null) {
				digest.reset();
				if (hashOut == null)
					hashOut = new HashRandomOutputStream(outputStream, digest);
				else
					hashOut.set(outputStream, digest);
				outputStream = hashOut;
			}
			else if (symmetricSigner!=null)
			{
				symmetricSigner.init();
				if (signerOut==null)
					signerOut=new SignerRandomOutputStream(outputStream, symmetricSigner );
				else
					signerOut.set(outputStream, symmetricSigner);
				outputStream=signerOut;
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.init();
				if (signerOut==null)
					signerOut=new SignerRandomOutputStream(outputStream, asymmetricSigner );
				else
					signerOut.set(outputStream, asymmetricSigner);
				outputStream=signerOut;
			}

			long dataLen;
			originalOutputStream.writeByte(code);
			byte[] buffer=null;
			int lenBuffer=0;
			if (cipher != null) {
				dataLen=cipher.getOutputSizeAfterEncryption(dataInputLength);
				originalOutputStream.writeLong(dataLen);
				limitedRandomOutputStream.set(outputStream, originalOutputStream.currentPosition(), dataLen);

				if (cipher.getType().supportAssociatedData()) {
					lenBuffer=computeAssociatedData(dataLen);
					buffer=bufferRef;
					if (cipherOutputStream==null)
						cipherOutputStream=cipher.getCipherOutputStreamForEncryption(limitedRandomOutputStream, false, buffer, 0, lenBuffer, externalCounter);
					else
						cipherOutputStream.set(limitedRandomOutputStream, null, externalCounter, buffer, 0, lenBuffer, false);
				}
				else {
					if (cipherOutputStream == null)
						cipherOutputStream = cipher.getCipherOutputStreamForEncryption(limitedRandomOutputStream, false, null,0 ,0, externalCounter);
					else
						cipherOutputStream.set(limitedRandomOutputStream, null, externalCounter, null, 0,0, false);
				}
				try {
					inputStream.transferTo(cipherOutputStream);
				}
				finally {
					cipherOutputStream.close();
				}
			}
			else
			{
				originalOutputStream.writeLong(dataLen=dataInputLength);
				outputStream.write(inputStream);
			}
			if (outputStream!=originalOutputStream && buffer==null) {
				buffer=bufferRef;
				lenBuffer=8;
				Bits.putLong(buffer, 0, dataLen);
			}


			if (digest!=null) {
				digest.update(code);
				digest.update(buffer, 0, 8);
				byte []hash = digest.digest();

				if (symmetricSigner != null) {
					symmetricSigner.init();
					if (lenBuffer>8)
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
				if (lenBuffer==8)
					symmetricSigner.update(code);
				symmetricSigner.update(buffer, 0, lenBuffer);
				byte[] signature = symmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.update(code);
				asymmetricSigner.update(buffer, 0, 8);
				byte[] signature = asymmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
			}
			long curPos=originalOutputStream.currentPosition();
			if (curPos<maximumOutputLengthAfterEncoding && curPos>originalOutputLength)
				originalOutputStream.setLength(Math.max(curPos, originalOutputLength));


			outputStream.flush();
		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException e)
		{
			throw new IOException(e);
		}
		finally {
			free();
		}
	}



	public boolean checkPartialHash(SubStreamParameters subStreamParameters, SubStreamHashResult hashResultFromEncryptedStream) throws IOException {
		try {
			AbstractMessageDigest md = subStreamParameters.getMessageDigestType().getMessageDigestInstance();
			md.reset();
			long dataLen=inputStream.length();
			RandomByteArrayOutputStream out=new RandomByteArrayOutputStream(9);
			code=getCode();
			out.writeByte(code);
			out.writeLong(dataLen);
			out.flush();

			if (cipher==null)
			{
				RandomInputStream in=new AggregatedRandomInputStreams(new RandomByteArrayInputStream(out.getBytes()), inputStream);
				byte[] hash=subStreamParameters.partialHash(in, md).digest();
				return Arrays.equals(hash, hashResultFromEncryptedStream.getHash());
			}
			else {

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
		long res=9;

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






}
