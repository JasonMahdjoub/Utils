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

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class EncryptionWriter {
	private static final MessageDigestType defaultMessageType=MessageDigestType.SHA2_256;
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

	private static byte getCode(byte[] associatedData, SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest)
	{
		int res=symmetricSigner==null?0:1;
		res+=asymmetricSigner==null?0:2;
		res+=digest==null?0:4;
		res+=associatedData==null?0:8;
		return (byte)res;
	}

	private static boolean hasSymmetricSignature(byte code)
	{
		return (code & 1)==1;
	}

	private static boolean hasASymmetricSignature(byte code)
	{
		return (code & 2)==2;
	}

	private static boolean hasHash(byte code)
	{
		return (code & 4)==4;
	}
	private static boolean hasAssociatedData(byte code)
	{
		return (code & 8)==8;
	}
	private final RandomInputStream inputStream;
	private final RandomOutputStream outputStream;
	private SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	private SymmetricAuthenticatedSignerAlgorithm symmetricSigner=null;
	private ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner=null;
	private AbstractMessageDigest digest=null;
	public EncryptionWriter(RandomInputStream inputStream, RandomOutputStream outputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()-inputStream.currentPosition()==0)
			throw new IllegalArgumentException();
		if (outputStream==null)
			throw new NullPointerException();
		this.inputStream=inputStream;
		this.outputStream=outputStream;
	}

	public EncryptionWriter withCipher(SymmetricEncryptionAlgorithm cipher)
	{
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		return this;
	}
	public EncryptionWriter withCipherAndAssociatedData(SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD)
	{
		if (cipher==null)
			throw new NullPointerException();
		if (associatedData==null)
			throw new NullPointerException();
		checkLimits(associatedData, offAD, lenAD);
		this.cipher=cipher;
		this.associatedData=associatedData;
		this.offAD=offAD;
		this.lenAD=lenAD;
		return this;
	}
	public EncryptionWriter withSymmetricSigner(SymmetricAuthenticatedSignerAlgorithm symmetricSigner)
	{
		if (symmetricSigner==null)
			throw new NullPointerException();
		this.symmetricSigner=symmetricSigner;
		return this;
	}
	public EncryptionWriter withSymmetricSecretKeyForSignature(SymmetricSecretKey secretKeyForSignature) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (secretKeyForSignature==null)
			throw new NullPointerException();
		if (!secretKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		this.symmetricSigner=new SymmetricAuthenticatedSignerAlgorithm(secretKeyForSignature);
		return this;
	}
	public EncryptionWriter withASymmetricSigner(ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner)
	{
		if (asymmetricSigner==null)
			throw new NullPointerException();
		this.asymmetricSigner=asymmetricSigner;
		return this;
	}
	public EncryptionWriter withASymmetricPrivateKeyForSignature(ASymmetricPrivateKey privateKeyForSignature) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (privateKeyForSignature==null)
			throw new NullPointerException();
		if (!privateKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		this.asymmetricSigner=new ASymmetricAuthenticatedSignerAlgorithm(privateKeyForSignature);
		return this;
	}
	public EncryptionWriter withMessageDigest(AbstractMessageDigest messageDigest)
	{
		if (digest==null)
			throw new NullPointerException();
		this.digest=messageDigest;
		return this;
	}
	public EncryptionWriter withMessageDigestType(MessageDigestType messageDigestType) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (messageDigestType==null)
			throw new NullPointerException();
		this.digest=messageDigestType.getMessageDigestInstance();
		return this;
	}
	public void encrypt() throws IOException {
		encryptAndSignImpl(inputStream, outputStream, cipher, associatedData, offAD, lenAD, symmetricSigner, asymmetricSigner, digest);
	}


	private static void encryptAndSignImpl(RandomInputStream inputStream, RandomOutputStream originalOutputStream, SymmetricEncryptionAlgorithm cipher,byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();
		if (originalOutputStream==null)
			throw new NullPointerException();
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);

		try {
			byte code=getCode(associatedData, symmetricSigner, asymmetricSigner, digest);
			if (symmetricSigner!=null && asymmetricSigner!=null && digest==null)
				digest=defaultMessageType.getMessageDigestInstance();
			RandomOutputStream outputStream=originalOutputStream;
			if (digest!=null) {
				digest.reset();
				outputStream = new HashRandomOutputStream(outputStream, digest);
			}
			else if (symmetricSigner!=null)
			{
				symmetricSigner.init();
				outputStream=new SignerRandomOutputStream(outputStream, symmetricSigner);
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.init();
				outputStream=new SignerRandomOutputStream(outputStream, asymmetricSigner);
			}


			long dataLen;
			originalOutputStream.writeByte(code);
			if (cipher != null) {

				originalOutputStream.writeLong(-1);
				long dataPos=originalOutputStream.currentPosition();
				if (associatedData!=null)
					cipher.encode(inputStream, associatedData, offAD, lenAD, outputStream);
				else
					cipher.encode(inputStream, outputStream);
				long newPos=originalOutputStream.currentPosition();
				dataLen=newPos-dataPos;
				originalOutputStream.seek(dataPos);
				originalOutputStream.writeLong(dataLen);
				originalOutputStream.seek(newPos);
			}
			else
			{
				dataLen=inputStream.length()-inputStream.currentPosition();
				originalOutputStream.writeLong(dataLen);
				outputStream.write(inputStream);
			}
			byte[] lenBuffer=null;
			if (outputStream!=originalOutputStream) {
				lenBuffer = new byte[8];
				Bits.putLong(lenBuffer, 0, dataLen);
			}


			if (digest!=null) {
				digest.update(code);
				digest.update(lenBuffer);

				byte []hash = digest.digest();

				if (symmetricSigner != null) {
					byte[] signature = symmetricSigner.sign(hash);
					digest.reset();
					digest.update(hash);
					hash=digest.digest();
					originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
				}

				if (asymmetricSigner != null) {
					byte[] signature = asymmetricSigner.sign(hash);
					digest.reset();
					digest.update(hash);
					hash=digest.digest();
					originalOutputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
				}
				originalOutputStream.writeBytesArray(hash, false, digest.getDigestLength());
			} else if (symmetricSigner!=null)
			{
				symmetricSigner.update(code);
				symmetricSigner.update(lenBuffer);
				byte[] signature = symmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.update(code);
				asymmetricSigner.update(lenBuffer);
				byte[] signature = asymmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
			}

		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | ShortBufferException e)
		{
			throw new IOException(e);
		}
	}

	static void decryptAndCheckHashAndSignaturesImpl(RandomInputStream originalInputStream, RandomOutputStream outputStream, SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (originalInputStream==null)
			throw new NullPointerException();
		if (originalInputStream.length()<=0)
			throw new IllegalArgumentException();
		if (outputStream==null)
			throw new NullPointerException();
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);

		try {
			byte code=originalInputStream.readByte();
			boolean symCheckOK=hasSymmetricSignature(code);
			boolean asymCheckOK=hasASymmetricSignature(code);
			boolean hashCheckOK=hasHash(code);
			boolean hasAssociatedData=hasAssociatedData(code);
			if (hasAssociatedData && associatedData==null)
				throw new NullPointerException();
			else if (!hasAssociatedData && associatedData!=null)
				throw new IllegalArgumentException();
			if (symCheckOK && symmetricChecker==null)
				throw new NullPointerException("symmetricChecker");
			if (asymCheckOK && asymmetricChecker==null)
				throw new NullPointerException("asymmetricChecker");
			if (hashCheckOK) {
				if (digest == null)
					throw new NullPointerException("digest");
			}
			else if (digest!=null && digest.getMessageDigestType()!=defaultMessageType)
				throw new IllegalArgumentException("digest");

			if (symCheckOK && asymCheckOK && !hashCheckOK)
				digest=defaultMessageType.getMessageDigestInstance();

			long dataLen=originalInputStream.readLong();
			long dataPos=originalInputStream.currentPosition();
			RandomInputStream inputStream=originalInputStream;
			if (digest!=null) {
				digest.reset();
				inputStream = new HashRandomInputStream(inputStream, digest);
			}
			else if (symmetricChecker!=null)
			{
				originalInputStream.seek(dataPos+dataLen);
				symmetricChecker.init(originalInputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes()));
				inputStream=new SignatureCheckerRandomInputStream(inputStream, symmetricChecker);
			}
			else if (asymmetricChecker!=null)
			{
				originalInputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(originalInputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				inputStream=new SignatureCheckerRandomInputStream(inputStream, asymmetricChecker);
			}
			LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);

			if (cipher != null) {
				if (associatedData!=null)
					cipher.decode(lis, associatedData, offAD, lenAD, outputStream);
				else
					cipher.decode(lis, outputStream);
			}
			else
			{
				outputStream.write(lis);
			}
			byte[] lenBuffer=null;
			if (digest!=null || symmetricChecker!=null || asymmetricChecker!=null) {
				lenBuffer= new byte[8];
				Bits.putLong(lenBuffer, 0, dataLen);

			}

			if (digest!=null) {
				digest.update(code);
				digest.update(lenBuffer);
				byte[] hash = digest.digest();
				byte[] hash2=hash;
				byte[] hash3=hash;
				byte[] symSign;
				byte[] asymSign;
				if (symCheckOK)
				{
					symSign=inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash2=digest.digest();
				}
				if (asymCheckOK)
				{
					asymSign=inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash2);
					digest.update(asymSign);
					hash3=digest.digest();
				}
				byte[] hashToCheck=inputStream.readBytesArray(false, digest.getDigestLength());
				if (!Arrays.equals(hash3, hashToCheck))
					throw new MessageExternalizationException(Integrity.FAIL);

				if (symmetricChecker != null) {

					if (!symmetricChecker.verify(hash, hash))
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}

				if (asymmetricChecker != null) {
					if (!asymmetricChecker.verify(hash, hash2))
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}
			}
			else if (symmetricChecker!=null)
			{
				symmetricChecker.update(code);
				symmetricChecker.update(lenBuffer);
				if (!symmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			} else if (asymmetricChecker!=null)
			{
				asymmetricChecker.update(code);
				asymmetricChecker.update(lenBuffer);
				if (!asymmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | ShortBufferException | InvalidParameterSpecException e)
		{
			throw new IOException(e);
		}
	}

	static Integrity checkHashAndSignatureImpl(final RandomInputStream inputStream, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();


		try {

			byte code=inputStream.readByte();
			boolean symCheckOK=hasSymmetricSignature(code);
			boolean asymCheckOK=hasASymmetricSignature(code);
			boolean hashCheckOK=hasHash(code);
			if (symCheckOK && symmetricChecker==null)
				throw new NullPointerException("symmetricChecker");
			if (asymCheckOK && asymmetricChecker==null)
				throw new NullPointerException("asymmetricChecker");
			if (hashCheckOK) {
				if (digest == null)
					throw new NullPointerException("digest");
			}
			else if (digest!=null && digest.getMessageDigestType()!=defaultMessageType)
				throw new IllegalArgumentException("digest");
			if (!symCheckOK && !asymCheckOK && !hashCheckOK)
				return Integrity.OK;
			if (symCheckOK && asymCheckOK && !hashCheckOK)
				digest=defaultMessageType.getMessageDigestInstance();

			long dataLen=inputStream.readLong();
			long dataPos=inputStream.currentPosition();
			byte[] lenBuffer= new byte[8];
			Bits.putLong(lenBuffer, 0, dataLen);

			if (digest!=null) {

				digest.reset();
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				digest.update(lis);
				digest.update(code);
				digest.update(lenBuffer);


				byte[] hash = digest.digest();
				byte[] hash2=hash;
				byte[] hash3=hash;
				byte[] symSign;
				byte[] asymSign;
				if (symCheckOK)
				{
					symSign=inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash2=digest.digest();
				}
				if (asymCheckOK)
				{
					asymSign=inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash2);
					digest.update(asymSign);
					hash3=digest.digest();
				}
				byte[] hashToCheck=inputStream.readBytesArray(false, digest.getDigestLength());
				if (!Arrays.equals(hash3, hashToCheck))
					return Integrity.FAIL;

				if (symmetricChecker != null) {
					if (!symmetricChecker.verify(hash, hash))
						return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
				}

				if (asymmetricChecker != null) {
					if (!asymmetricChecker.verify(hash, hash2))
						return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
				}
				return Integrity.OK;
			}
			else if (symmetricChecker!=null)
			{

				inputStream.seek(dataPos+dataLen);
				symmetricChecker.init(inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes()));
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				symmetricChecker.update(lis);
				symmetricChecker.update(code);
				symmetricChecker.update(lenBuffer);
				if (symmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;

			}
			else
			{

				inputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				asymmetricChecker.update(lis);
				asymmetricChecker.update(code);
				asymmetricChecker.update(lenBuffer);
				if (asymmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
			}


		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | InvalidParameterSpecException e)
		{
			return Integrity.FAIL;
		}
	}
	private static final int maxSymSigSizeBytes;
	static {
		int v=0;
		for (SymmetricAuthentifiedSignatureType t : SymmetricAuthentifiedSignatureType.values()){
			v=Math.max(t.getSignatureSizeInBits()/8, v);
		}
		maxSymSigSizeBytes=v;
	}
	static Integrity checkHashAndPublicSignatureImpl(final RandomInputStream inputStream, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();


		try {

			byte code=inputStream.readByte();
			boolean symCheckOK=hasSymmetricSignature(code);
			boolean asymCheckOK=hasASymmetricSignature(code);
			boolean hashCheckOK=hasHash(code);

			if (asymCheckOK && asymmetricChecker==null)
				throw new NullPointerException("asymmetricChecker");
			if (hashCheckOK) {
				if (digest == null)
					throw new NullPointerException("digest");
			}
			else if (digest!=null && digest.getMessageDigestType()!=defaultMessageType)
				throw new IllegalArgumentException("digest");
			if (!asymCheckOK && !hashCheckOK)
				return Integrity.OK;
			if (symCheckOK && asymCheckOK && !hashCheckOK)
				digest=defaultMessageType.getMessageDigestInstance();

			long dataLen=inputStream.readLong();
			long dataPos=inputStream.currentPosition();
			byte[] lenBuffer = new byte[8];
			Bits.putLong(lenBuffer, 0, dataLen);

			if (digest!=null) {
				digest.reset();
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				digest.update(lis);
				digest.update(code);
				digest.update(lenBuffer);


				byte[] hash = digest.digest();
				byte[] hash2=hash;
				byte[] hash3=hash;
				byte[] symSign;
				byte[] asymSign;
				if (symCheckOK)
				{
					symSign=inputStream.readBytesArray(false, maxSymSigSizeBytes);
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash2=digest.digest();
				}
				if (asymCheckOK)
				{
					asymSign=inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash2);
					digest.update(asymSign);
					hash3=digest.digest();
				}
				byte[] hashToCheck=inputStream.readBytesArray(false, digest.getDigestLength());
				if (!Arrays.equals(hash3, hashToCheck))
					return Integrity.FAIL;

				if (symCheckOK && asymmetricChecker != null) {


					inputStream.readBytesArray(false, maxSymSigSizeBytes);
					if (!asymmetricChecker.verify(hash, inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes())))
						return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
				}

				return Integrity.OK;
			}
			else
			{

				inputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				asymmetricChecker.update(lis);
				asymmetricChecker.update(code);
				asymmetricChecker.update(lenBuffer);
				if (asymmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
			}


		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | InvalidParameterSpecException e)
		{
			return Integrity.FAIL;
		}
	}
}
