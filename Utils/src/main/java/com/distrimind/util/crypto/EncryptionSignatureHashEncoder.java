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
import com.distrimind.util.Reference;
import com.distrimind.util.io.*;

import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

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
	static byte getCode(SymmetricEncryptionAlgorithm cipher, byte[] associatedData, SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest)
	{
		if (associatedData!=null && (cipher==null || !cipher.getType().supportAssociatedData()) && symmetricSigner==null && asymmetricSigner==null)
			throw new IllegalArgumentException();
		int res=symmetricSigner==null?0:1;
		res+=asymmetricSigner==null?0:2;
		res+=digest==null?0:4;
		res+=associatedData==null?0:8;
		res+=cipher==null?0:16;
		return (byte)res;
	}


	private RandomInputStream inputStream=null;
	private SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	private SymmetricAuthenticatedSignerAlgorithm symmetricSigner=null;
	private ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner=null;
	private AbstractMessageDigest digest=null;
	private Long minimumOutputSize=null;
	private final Reference<byte[]> bufferRef=new Reference<>(new byte[256]);
	private SignerRandomOutputStream signerOut;
	private HashRandomOutputStream hashOut;
	private final LimitedRandomOutputStream limitedRandomOutputStream;
	private static final NullRandomOutputStream nullRandomInputStream=new NullRandomOutputStream();
	private final Reference<AbstractMessageDigest> defaultMessageDigest=new Reference<>();
	public EncryptionSignatureHashEncoder() throws IOException {
		limitedRandomOutputStream=new LimitedRandomOutputStream(nullRandomInputStream, 0);
	}

	public EncryptionSignatureHashEncoder withRandomInputStream(RandomInputStream inputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()-inputStream.currentPosition()==0)
			throw new IllegalArgumentException();
		this.inputStream=inputStream;
		return this;
	}

	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
	}

	public EncryptionSignatureHashEncoder withCipher(SymmetricEncryptionAlgorithm cipher) {
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		return this;
	}
	public EncryptionSignatureHashEncoder withoutAssociatedData()
	{
		this.associatedData=null;
		this.offAD=0;
		this.lenAD=0;
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
		if (signerOut==null)
			signerOut=new SignerRandomOutputStream(nullRandomInputStream, this.symmetricSigner );
		return this;
	}
	public EncryptionSignatureHashEncoder withASymmetricSigner(ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner)
	{
		if (asymmetricSigner==null)
			throw new NullPointerException();
		this.asymmetricSigner=asymmetricSigner;
		minimumOutputSize=null;
		if (signerOut==null)
			signerOut=new SignerRandomOutputStream(nullRandomInputStream, this.symmetricSigner );
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
			if (signerOut==null)
				signerOut=new SignerRandomOutputStream(nullRandomInputStream, this.symmetricSigner );
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
		if (hashOut==null)
			hashOut=new HashRandomOutputStream(nullRandomInputStream, this.digest);
		return this;
	}
	public EncryptionSignatureHashEncoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			minimumOutputSize=null;
			if (hashOut==null)
				hashOut=new HashRandomOutputStream(nullRandomInputStream, this.digest);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		return this;
	}
	public void encode(final RandomOutputStream originalOutputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();

		if (originalOutputStream==null)
			throw new NullPointerException();
		if (associatedData!=null) {
			if (cipher==null)
				throw new IllegalArgumentException();
			checkLimits(associatedData, offAD, lenAD);
		}

		try {
			long originalOutputLength=originalOutputStream.length();
			long maximumOutputLengthAfterEncoding=getMaximumOutputLengthAfterEncoding(inputStream.length(), cipher, getMinimumOutputSize());
			originalOutputStream.ensureLength(maximumOutputLengthAfterEncoding);

			byte code=getCode(cipher, associatedData, symmetricSigner, asymmetricSigner, digest);

			if (symmetricSigner!=null && asymmetricSigner!=null && digest==null) {
				digest = defaultMessageDigest.get();
				if (digest==null)
					defaultMessageDigest.set(digest=defaultMessageType.getMessageDigestInstance());
			}

			RandomOutputStream outputStream=originalOutputStream;
			if (digest!=null) {
				digest.reset();
				hashOut.set(outputStream, digest);
				outputStream = hashOut;
			}
			else if (symmetricSigner!=null)
			{
				symmetricSigner.init();
				signerOut.set(outputStream, symmetricSigner);
				outputStream=signerOut;
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.init();
				signerOut.set(outputStream, asymmetricSigner);
				outputStream=signerOut;
			}

			long dataLen;
			originalOutputStream.writeByte(code);
			byte[] buffer=null;
			int lenBuffer=0;
			if (cipher != null) {
				dataLen=cipher.getOutputSizeAfterEncryption(inputStream.length()-inputStream.currentPosition());
				originalOutputStream.writeLong(dataLen);
				limitedRandomOutputStream.set(outputStream, originalOutputStream.currentPosition(), dataLen);

				if (cipher.getType().supportAssociatedData()) {
					buffer=bufferRef.get();
					lenBuffer=9+(associatedData!=null?lenAD:0);
					if (buffer.length<lenBuffer)
						bufferRef.set(buffer=new byte[lenBuffer]);
					Bits.putLong(buffer, 0, dataLen);
					buffer[8]=code;
					if (associatedData!=null)
					{
						System.arraycopy(associatedData, offAD, buffer, 9, lenAD);
					}
					cipher.encode(inputStream, buffer, 0, lenBuffer, limitedRandomOutputStream);
				}
				else
					cipher.encode(inputStream, limitedRandomOutputStream);
			}
			else
			{
				dataLen=inputStream.length()-inputStream.currentPosition();
				originalOutputStream.writeLong(dataLen);
				outputStream.write(inputStream);
			}
			if (outputStream!=originalOutputStream && buffer==null) {
				buffer=bufferRef.get();
				lenBuffer=8;
				Bits.putLong(buffer, 0, dataLen);
			}


			if (digest!=null) {
				digest.update(code);
				digest.update(buffer, 0, lenBuffer);
				if (associatedData!=null)
					digest.update(associatedData, offAD, lenAD);

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
				symmetricSigner.update(code);
				symmetricSigner.update(buffer, 0, lenBuffer);
				if (associatedData!=null)
					symmetricSigner.update(associatedData, offAD, lenAD);
				if (associatedData!=null)
					symmetricSigner.update(associatedData, offAD, lenAD);
				byte[] signature = symmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.update(code);
				asymmetricSigner.update(buffer, 0, lenBuffer);
				if (associatedData!=null)
					asymmetricSigner.update(associatedData, offAD, lenAD);
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
			byte[] head=null;
			byte code;
			List<SubStreamParameter> lparameters=subStreamParameters.getParameters();
			for (SubStreamParameter p : lparameters)
			{
				if (p.getStreamStartIncluded()>=9)
					break;
				else
				{
					long end=Math.min(9, p.getStreamEndExcluded());
					if (head==null)
					{
						RandomByteArrayOutputStream out=new RandomByteArrayOutputStream(9);
						code=getCode(cipher, associatedData, symmetricSigner, asymmetricSigner, digest);
						out.writeByte(code);
						out.writeLong(inputStream.length());
						out.flush();
						head=out.getBytes();
					}
					md.update(head, (int)p.getStreamStartIncluded(), (int)(end-p.getStreamStartIncluded()));
				}
			}
			ArrayList<SubStreamParameter> l=new ArrayList<>(lparameters.size());
			for (SubStreamParameter p : lparameters)
			{
				if (p.getStreamStartIncluded()<9)
				{
					if (p.getStreamEndExcluded()>9)
					{
						l.add(new SubStreamParameter(0, p.getStreamEndExcluded()-9));
					}
				}
				else
					l.add(new SubStreamParameter(p.getStreamStartIncluded()-9, p.getStreamEndExcluded()-9));
			}
			subStreamParameters=new SubStreamParameters(subStreamParameters.getMessageDigestType(), l);
			if (cipher==null)
			{
				byte[] hash=subStreamParameters.partialHash(inputStream, md).digest();
				return Arrays.equals(hash, hashResultFromEncryptedStream.getHash());
			}
			else {
				return cipher.checkPartialHashWithNonEncryptedStream(hashResultFromEncryptedStream, subStreamParameters, inputStream, associatedData, offAD, lenAD, md);
			}
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	private long getMinimumOutputSize()
	{
		if (minimumOutputSize==null)
			minimumOutputSize=getMinimumOutputLengthAfterEncoding(symmetricSigner, asymmetricSigner, digest);
		return minimumOutputSize;
	}

	public long getMaximumOutputLength() throws IOException {

		return getMaximumOutputLengthAfterEncoding(inputStream.length(), cipher, getMinimumOutputSize());
	}

	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		return getMaximumOutputLengthAfterEncoding(inputStreamLength, cipher, getMinimumOutputSize());
	}

	static long getMaximumOutputLengthAfterEncoding(long inputStreamLength, SymmetricEncryptionAlgorithm cipher, long minimumOuputSize) throws IOException {
		if (inputStreamLength<=0)
			throw new IllegalArgumentException();
		long res=minimumOuputSize;

		if (cipher!=null) {
			res += cipher.getOutputSizeAfterEncryption(inputStreamLength);
		}
		else
			res+=inputStreamLength;
		return res;
	}
	static long getMinimumOutputLengthAfterEncoding(SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest)
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
	static long getMinimumInputLengthAfterDecoding(SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest)
	{
		long res=9;

		if (symmetricChecker!=null) {
			int v=symmetricChecker.getMacLengthBytes();
			res += v + (v>Short.MAX_VALUE?4:2);
		}
		if(asymmetricChecker!=null) {
			int v=asymmetricChecker.getMacLengthBytes();
			res += v + (v>Short.MAX_VALUE?4:2);
		}
		if (digest!=null || (symmetricChecker!=null && asymmetricChecker!=null))
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
	static long getMaximumOutputLengthAfterDecoding(long inputStreamLength, SymmetricEncryptionAlgorithm cipher, long minimumInputSize) throws IOException {
		if (inputStreamLength<=0)
			throw new IllegalArgumentException();
		long res=inputStreamLength-minimumInputSize;

		if (res<=0)
			throw new IllegalArgumentException();
		if (cipher!=null)
			return cipher.getOutputSizeAfterDecryption(res);
		else
			return res;
	}
	private void free() throws IOException {
		if (signerOut!=null)
			signerOut.set(nullRandomInputStream, symmetricSigner==null?asymmetricSigner:symmetricSigner);
		if (hashOut!=null)
			hashOut.set(nullRandomInputStream, digest);
		limitedRandomOutputStream.set(nullRandomInputStream, 0);
	}






}
