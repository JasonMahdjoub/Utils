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
import java.security.spec.InvalidParameterSpecException;
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
		if (associatedData!=null && cipher==null)
			throw new IllegalArgumentException();
		int res=symmetricSigner==null?0:1;
		res+=asymmetricSigner==null?0:2;
		res+=digest==null?0:4;
		res+=associatedData==null?0:8;
		res+=cipher==null?0:16;
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
	private static boolean hasCipher(byte code)
	{
		return (code & 16)==16;
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
	public EncryptionSignatureHashEncoder() {

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
	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryptionAndAssociatedData(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption, byte[] associatedData) throws IOException {
		return withSymmetricSecretKeyForEncryptionAndAssociatedData(random, symmetricSecretKeyForEncryption, associatedData, 0, associatedData.length);
	}
	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryptionAndAssociatedData(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption, byte[] associatedData, int offAD, int lenAD) throws IOException {
		return withCipherAndAssociatedData(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption), associatedData, offAD, lenAD);
	}

	public EncryptionSignatureHashEncoder withCipher(SymmetricEncryptionAlgorithm cipher) throws IOException {
		if (cipher==null)
			throw new NullPointerException();
		if (this.symmetricSigner!=null && cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication and a symmetric authenticated signer is already used. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.cipher=cipher;
		this.associatedData=null;
		return this;
	}
	public EncryptionSignatureHashEncoder withCipherAndAssociatedData(SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD) throws IOException {
		if (cipher==null)
			throw new NullPointerException();
		if (associatedData==null)
			throw new NullPointerException();
		if (!cipher.getType().supportAssociatedData())
			throw new IllegalArgumentException("Cipher does not support associated data !");
		checkLimits(associatedData, offAD, lenAD);
		if (this.symmetricSigner!=null && cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication and a symmetric authenticated signer is already used. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.cipher=cipher;
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
		return this;
	}
	public EncryptionSignatureHashEncoder withASymmetricSigner(ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner)
	{
		if (asymmetricSigner==null)
			throw new NullPointerException();
		this.asymmetricSigner=asymmetricSigner;
		minimumOutputSize=null;
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
		return this;
	}
	public EncryptionSignatureHashEncoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			minimumOutputSize=null;
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		return this;
	}
	public void encode(RandomOutputStream outputStream) throws IOException {
		if (outputStream==null)
			throw new NullPointerException();
		encryptAndSignImpl(inputStream, outputStream, cipher, associatedData, offAD, lenAD, symmetricSigner, asymmetricSigner, digest, getMinimumOutputSize());
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
			res += cipher.getOutputSizeForEncryption(inputStreamLength);
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
			return cipher.getOutputSizeForDecryption(res);
		else
			return res;
	}

	private static void encryptAndSignImpl(RandomInputStream inputStream, RandomOutputStream originalOutputStream, SymmetricEncryptionAlgorithm cipher,byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest, long minimumOutputSize) throws IOException {
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
			long maximumOutputLengthAfterEncoding=getMaximumOutputLengthAfterEncoding(inputStream.length(), cipher, minimumOutputSize);
			originalOutputStream.ensureLength(maximumOutputLengthAfterEncoding);

			byte code=getCode(cipher, associatedData, symmetricSigner, asymmetricSigner, digest);

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
					cipher.encode(inputStream, associatedData, offAD, lenAD, new LimitedRandomOutputStream(outputStream, dataPos));
				else
					cipher.encode(inputStream, new LimitedRandomOutputStream(outputStream, dataPos));
				long newPos=originalOutputStream.currentPosition();
				dataLen=newPos-dataPos;
				originalOutputStream.seek(dataPos-8);
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
				symmetricSigner.update(lenBuffer);
				if (associatedData!=null)
					symmetricSigner.update(associatedData, offAD, lenAD);
				byte[] signature = symmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.update(code);
				asymmetricSigner.update(lenBuffer);
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
	}
	private static byte checkCode(SymmetricEncryptionAlgorithm cipher, RandomInputStream originalInputStream, byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);

		byte code=checkCode(originalInputStream, symmetricChecker, asymmetricChecker, digest);
		boolean hasAssociatedData=hasAssociatedData(code);
		if (hasAssociatedData && associatedData==null)
			throw new NullPointerException("associatedData");
		else if (hasAssociatedData && cipher==null)
			throw new MessageExternalizationException(Integrity.FAIL, "associatedData");
		else if (!hasAssociatedData && associatedData!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
		if (hasAssociatedData && !cipher.getType().supportAssociatedData())
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
		boolean hasCipher=hasCipher(code);
		if (hasCipher && cipher==null)
			throw new NullPointerException("cipher");
		else if (!hasCipher && cipher!=null)
			throw new MessageExternalizationException(Integrity.FAIL, "cipher");
		return code;
	}
	private static byte checkCode(RandomInputStream originalInputStream, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		byte code=checkCode(originalInputStream, asymmetricChecker, digest);
		boolean symCheckOK=hasSymmetricSignature(code);
		if (symCheckOK && symmetricChecker==null)
			throw new NullPointerException("symmetricChecker");
		else if(!symCheckOK && symmetricChecker!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "symmetricChecker");
		return code;
	}
	private static byte checkCode(RandomInputStream originalInputStream, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		byte code=originalInputStream.readByte();

		boolean asymCheckOK=hasASymmetricSignature(code);
		boolean hashCheckOK=hasHash(code);

		if (asymCheckOK && asymmetricChecker==null)
			throw new NullPointerException("asymmetricChecker");
		else if(!asymCheckOK && asymmetricChecker!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "asymmetricChecker");
		if (hashCheckOK) {
			if (digest == null)
				throw new NullPointerException("digest");
		}
		else if (digest!=null && digest.getMessageDigestType()!=defaultMessageType)
			throw new MessageExternalizationException(Integrity.FAIL, "digest");
		return code;
	}

	static void decryptAndCheckHashAndSignaturesImpl(RandomInputStream originalInputStream, RandomOutputStream outputStream, SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest, long minimumInputLength) throws IOException {
		if (originalInputStream==null)
			throw new NullPointerException();
		if (originalInputStream.length()<=0)
			throw new IllegalArgumentException();
		if (outputStream==null)
			throw new NullPointerException();
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);

		try {
			long originalOutputLength=outputStream.length();
			long maximumOutputLengthAfterEncoding=getMaximumOutputLengthAfterDecoding(originalInputStream.length(), cipher, minimumInputLength);
			outputStream.ensureLength(maximumOutputLengthAfterEncoding);
			byte code=checkCode(cipher, originalInputStream, associatedData, offAD, lenAD, symmetricChecker, asymmetricChecker, digest);

			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null)
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
			LimitedRandomInputStream lis;
			try {
				lis = new LimitedRandomInputStream(inputStream, dataPos, dataLen);
			}
			catch (IllegalArgumentException | NullPointerException e)
			{
				throw new IOException(e);
			}

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
				byte[] symSign=null;
				byte[] asymSign=null;
				if (symmetricChecker!=null)
				{
					symSign=inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash3=hash2=digest.digest();
				}
				if (asymmetricChecker!=null)
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

				if (symmetricChecker!=null) {
					symmetricChecker.init(symSign, 0, symSign.length);
					if (associatedData!=null)
						symmetricChecker.update(associatedData, offAD, lenAD);
					symmetricChecker.update(hash);
					if (!symmetricChecker.verify())
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}

				if (asymmetricChecker!=null) {
					asymmetricChecker.init(asymSign, 0, asymSign.length);
					asymmetricChecker.update(hash);
					if (!asymmetricChecker.verify())
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}
			}
			else if (symmetricChecker!=null)
			{
				symmetricChecker.update(code);
				symmetricChecker.update(lenBuffer);
				if (associatedData!=null)
					symmetricChecker.update(associatedData, offAD, lenAD);
				if (!symmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			} else if (asymmetricChecker!=null)
			{
				asymmetricChecker.update(code);
				asymmetricChecker.update(lenBuffer);
				if (!asymmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			long curPos=outputStream.currentPosition();
			if (curPos<maximumOutputLengthAfterEncoding && curPos>originalOutputLength)
				outputStream.setLength(Math.max(curPos, originalOutputLength));
			outputStream.flush();
		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | InvalidParameterSpecException e)
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

			byte code=checkCode(inputStream, symmetricChecker, asymmetricChecker, digest);

			if (symmetricChecker==null && asymmetricChecker==null && digest==null)
				return Integrity.OK;
			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null)
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
				byte[] symSign=null;
				byte[] asymSign=null;
				if (symmetricChecker!=null)
				{
					symSign=inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes());
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash3=hash2=digest.digest();
				}
				if (asymmetricChecker!=null)
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

				if (symmetricChecker!=null) {
					if (!symmetricChecker.verify(hash, symSign))
						return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
				}

				if (asymmetricChecker!=null) {
					if (!asymmetricChecker.verify(hash2, asymSign))
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


		} catch (MessageExternalizationException e)
		{
			return e.getIntegrity();
		} catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | InvalidParameterSpecException | IllegalArgumentException | IOException | NullPointerException e)
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

			byte code=checkCode(inputStream, asymmetricChecker, digest);
			boolean symCheckOK=hasSymmetricSignature(code);
			if (symCheckOK && asymmetricChecker!=null && digest==null)
				digest=defaultMessageType.getMessageDigestInstance();
			if (asymmetricChecker==null && digest==null)
				return Integrity.OK;
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
				byte[] asymSign=null;
				if (symCheckOK)
				{
					byte[] symSign=inputStream.readBytesArray(false, maxSymSigSizeBytes);
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash3=hash2=digest.digest();
				}
				if (asymmetricChecker!=null)
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

				if (asymmetricChecker!=null) {
					if (!asymmetricChecker.verify(hash2, asymSign))
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


		} catch (MessageExternalizationException e)
		{
			return e.getIntegrity();
		} catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | InvalidParameterSpecException | IllegalArgumentException | IOException | NullPointerException e)
		{
			return Integrity.FAIL;
		}
	}
}
