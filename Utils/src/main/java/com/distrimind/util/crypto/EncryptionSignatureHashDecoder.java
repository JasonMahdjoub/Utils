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

import com.distrimind.util.Bits;
import com.distrimind.util.io.*;

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
public class EncryptionSignatureHashDecoder {

	private RandomInputStream inputStream=null;
	private SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	private SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker=null;
	private ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker=null;
	private AbstractMessageDigest digest=null;
	private byte[] buffer=new byte[256];
	Long minimumInputSize=null;
	private SignatureCheckerRandomInputStream checkerIn;
	private HashRandomInputStream hashIn;
	private final LimitedRandomInputStream limitedRandomInputStream;
	static final RandomInputStream nullRandomInputStream=new RandomByteArrayInputStream(new byte[0]);
	private AbstractMessageDigest defaultMessageDigest=null;
	private byte[] externalCounter=null;
	private CommonCipherInputStream cipherInputStream=null;

	public EncryptionSignatureHashDecoder() throws IOException {
		limitedRandomInputStream=new LimitedRandomInputStream(nullRandomInputStream, 0);
	}
	public EncryptionSignatureHashDecoder withRandomInputStream(RandomInputStream inputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()-inputStream.currentPosition()==0)
			throw new IllegalArgumentException();
		this.inputStream=inputStream;
		return this;
	}
	public EncryptionSignatureHashDecoder withExternalCounter(byte[] externalCounter) {
		if (externalCounter==null)
			throw new NullPointerException();
		this.externalCounter=externalCounter;
		return this;
	}

	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
	}

	public EncryptionSignatureHashDecoder withCipher(SymmetricEncryptionAlgorithm cipher) {
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		return this;
	}
	public EncryptionSignatureHashDecoder withoutAssociatedData()
	{
		this.associatedData=null;
		this.offAD=0;
		this.lenAD=0;
		return this;
	}
	@SuppressWarnings("UnusedReturnValue")
	public EncryptionSignatureHashDecoder withAssociatedData(byte[] associatedData)
	{
		return withAssociatedData(associatedData, 0, associatedData.length);
	}
	public EncryptionSignatureHashDecoder withAssociatedData(byte[] associatedData, int offAD, int lenAD)
	{
		if (associatedData==null)
			throw new NullPointerException();
		EncryptionSignatureHashEncoder.checkLimits(associatedData, offAD, lenAD);
		this.associatedData=associatedData;
		this.offAD=offAD;
		this.lenAD=lenAD;
		return this;
	}
	public EncryptionSignatureHashDecoder withMessageDigest(AbstractMessageDigest messageDigest)
	{
		if (digest==null)
			throw new NullPointerException();
		this.digest=messageDigest;
		minimumInputSize=null;
		if (hashIn==null)
			hashIn=new HashRandomInputStream(nullRandomInputStream, digest);
		return this;
	}
	@SuppressWarnings("UnusedReturnValue")
	public EncryptionSignatureHashDecoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			minimumInputSize=null;
			if (hashIn==null)
				hashIn=new HashRandomInputStream(nullRandomInputStream, digest);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		return this;
	}
	public EncryptionSignatureHashDecoder withSymmetricChecker(SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker) throws IOException {
		if (symmetricChecker==null)
			throw new NullPointerException();
		if (this.cipher!=null && this.cipher.getType().isAuthenticatedAlgorithm())
			throw new IOException("Symmetric encryption use authentication. No more symmetric authentication is needed. However ASymmetric authentication is possible.");
		this.symmetricChecker=symmetricChecker;
		minimumInputSize=null;
		if (checkerIn==null)
			checkerIn=new SignatureCheckerRandomInputStream(nullRandomInputStream, symmetricChecker);
		return this;
	}
	@SuppressWarnings("UnusedReturnValue")
	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForSignature(SymmetricSecretKey secretKeyForSignature) throws IOException {
		if (secretKeyForSignature==null)
			throw new NullPointerException();
		if (!secretKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			return withSymmetricChecker(new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKeyForSignature));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	public EncryptionSignatureHashDecoder withASymmetricChecker(ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker)
	{
		if (asymmetricChecker==null)
			throw new NullPointerException();
		this.asymmetricChecker=asymmetricChecker;
		minimumInputSize=null;
		if (checkerIn==null)
			checkerIn=new SignatureCheckerRandomInputStream(nullRandomInputStream, asymmetricChecker);
		return this;
	}

	@SuppressWarnings("UnusedReturnValue")
	public EncryptionSignatureHashDecoder withASymmetricPublicKeyForSignature(IASymmetricPublicKey publicKeyForSignature) throws IOException {
		if (publicKeyForSignature==null)
			throw new NullPointerException();
		if (!publicKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			this.asymmetricChecker=new ASymmetricAuthenticatedSignatureCheckerAlgorithm(publicKeyForSignature);
			minimumInputSize=null;
			if (checkerIn==null)
				checkerIn=new SignatureCheckerRandomInputStream(nullRandomInputStream, asymmetricChecker);
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		return this;
	}

	private long getMinimumInputSize()
	{
		if (minimumInputSize==null)
			minimumInputSize=EncryptionSignatureHashEncoder.getMinimumInputLengthAfterDecoding(symmetricChecker, asymmetricChecker, digest);
		return minimumInputSize;
	}
	private static final int maxSymSigSizeBytes;
	static {
		int v=0;
		for (SymmetricAuthentifiedSignatureType t : SymmetricAuthentifiedSignatureType.values()){
			v=Math.max(t.getSignatureSizeInBits()/8, v);
		}
		maxSymSigSizeBytes=v;
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
	private byte checkCodeForDecode() throws IOException {
		if (associatedData!=null)
			EncryptionSignatureHashEncoder.checkLimits(associatedData, offAD, lenAD);

		byte code=checkCodeForCheckHashAndSignature();
		boolean hasAssociatedData=hasAssociatedData(code);
		if (hasAssociatedData && associatedData==null)
			throw new NullPointerException("associatedData");
		else if (!hasAssociatedData && associatedData!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
		if (hasAssociatedData && (cipher==null || !cipher.getType().supportAssociatedData()) && symmetricChecker==null && asymmetricChecker==null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
		boolean hasCipher=hasCipher(code);
		if (hasCipher && cipher==null)
			throw new NullPointerException("cipher");
		else if (!hasCipher && cipher!=null)
			throw new MessageExternalizationException(Integrity.FAIL, "cipher");
		return code;
	}
	private byte checkCodeForCheckHashAndSignature() throws IOException {
		byte code=checkCodeForCheckHashAndPublicSignature();
		boolean symCheckOK=hasSymmetricSignature(code);
		if (symCheckOK && symmetricChecker==null)
			throw new NullPointerException("symmetricChecker");
		else if(!symCheckOK && symmetricChecker!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "symmetricChecker");
		return code;
	}
	private byte checkCodeForCheckHashAndPublicSignature() throws IOException {
		byte code=inputStream.readByte();

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
		else if (digest!=null && digest.getMessageDigestType()!=EncryptionSignatureHashEncoder.defaultMessageType)
			throw new MessageExternalizationException(Integrity.FAIL, "digest");
		return code;
	}

	private static void free(SignatureCheckerRandomInputStream checkerIn, HashRandomInputStream hashIn, LimitedRandomInputStream limitedRandomInputStream, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (checkerIn!=null)
			checkerIn.set(EncryptionSignatureHashDecoder.nullRandomInputStream, symmetricChecker==null?asymmetricChecker:symmetricChecker);
		if (hashIn!=null)
			hashIn.set(EncryptionSignatureHashDecoder.nullRandomInputStream, digest);
		free(limitedRandomInputStream);
	}
	private static void free(LimitedRandomInputStream limitedRandomInputStream) throws IOException {
		limitedRandomInputStream.set(EncryptionSignatureHashDecoder.nullRandomInputStream, 0);
	}

	public void decodeAndCheckHashAndSignaturesIfNecessary(RandomOutputStream outputStream) throws IOException {
		if (outputStream==null)
			throw new NullPointerException();
		RandomInputStream originalInputStream=inputStream;
		if (originalInputStream==null)
			throw new NullPointerException();
		if (originalInputStream.length()<=0)
			throw new IllegalArgumentException();

		if (associatedData!=null)
			EncryptionSignatureHashEncoder.checkLimits(associatedData, offAD, lenAD);

		try {
			long originalOutputLength=outputStream.length();
			long maximumOutputLengthAfterEncoding=getMaximumOutputLengthAfterDecoding(originalInputStream.length(), cipher, getMinimumInputSize());
			outputStream.ensureLength(maximumOutputLengthAfterEncoding);
			byte code=checkCodeForDecode();
			AbstractMessageDigest digest=this.digest;
			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null) {
				if (defaultMessageDigest==null)
					defaultMessageDigest=digest=EncryptionSignatureHashEncoder.defaultMessageType.getMessageDigestInstance();
				else
					digest = defaultMessageDigest;

			}

			long dataLen=originalInputStream.readLong();
			long dataPos=originalInputStream.currentPosition();
			RandomInputStream inputStream=originalInputStream;
			if (digest!=null) {
				digest.reset();
				hashIn.set(inputStream, digest);
				inputStream = hashIn;
			}
			else if (symmetricChecker!=null)
			{
				originalInputStream.seek(dataPos+dataLen);
				symmetricChecker.init(originalInputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes()));
				checkerIn.set(inputStream, symmetricChecker);
				inputStream=checkerIn;
			}
			else if (asymmetricChecker!=null)
			{
				originalInputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(originalInputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				checkerIn.set(inputStream, asymmetricChecker);
				inputStream=checkerIn;
			}

			try {
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
			}
			catch (IllegalArgumentException | NullPointerException e)
			{
				throw new IOException(e);
			}
			byte[] buffer=null;

			if (cipher != null) {
				if (cipher.getType().supportAssociatedData()) {
					int lenBuffer=9+(associatedData!=null?lenAD:0);
					if (this.buffer.length<lenBuffer)
						buffer=this.buffer=new byte[lenBuffer];
					else
						buffer=this.buffer;
					Bits.putLong(buffer, 0, dataLen);
					buffer[8]=code;
					if (associatedData!=null)
					{
						System.arraycopy(associatedData, offAD, buffer, 9, lenAD);
					}
					if (cipherInputStream==null)
						cipherInputStream=cipher.getCipherInputStreamForDecryption(limitedRandomInputStream,buffer, 0, lenBuffer, externalCounter );
					else
						cipherInputStream.set(limitedRandomInputStream,buffer, 0, lenBuffer, externalCounter );

				}
				else {
					if (cipherInputStream==null)
						cipherInputStream=cipher.getCipherInputStreamForDecryption(limitedRandomInputStream,null, 0, 0, externalCounter );
					else
						cipherInputStream.set(limitedRandomInputStream,null, 0, 0, externalCounter );
				}
				try {
					cipherInputStream.transferTo(outputStream);
				}
				finally {
					cipherInputStream.close();
				}

			}
			else
			{
				outputStream.write(limitedRandomInputStream);
			}
			if (buffer==null && (digest!=null || symmetricChecker!=null || asymmetricChecker!=null)) {
				buffer=this.buffer;
				Bits.putLong(buffer, 0, dataLen);

			}

			if (digest!=null) {
				digest.update(code);
				digest.update(buffer, 0, 8);
				if (associatedData!=null)
					digest.update(associatedData, offAD, lenAD);
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
					assert symSign != null;
					symmetricChecker.init(symSign, 0, symSign.length);
					if (associatedData!=null)
						symmetricChecker.update(associatedData, offAD, lenAD);
					symmetricChecker.update(hash);
					if (!symmetricChecker.verify())
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}

				if (asymmetricChecker!=null) {
					assert asymSign != null;
					asymmetricChecker.init(asymSign, 0, asymSign.length);
					asymmetricChecker.update(hash);
					if (!asymmetricChecker.verify())
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}
			}
			else if (symmetricChecker!=null)
			{
				symmetricChecker.update(code);
				symmetricChecker.update(buffer, 0, 8);
				if (associatedData!=null)
					symmetricChecker.update(associatedData, offAD, lenAD);
				if (associatedData!=null)
					symmetricChecker.update(associatedData, offAD, lenAD);
				if (!symmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			} else if (asymmetricChecker!=null)
			{
				asymmetricChecker.update(code);
				asymmetricChecker.update(buffer, 0, 8);
				if (associatedData!=null)
					asymmetricChecker.update(associatedData, offAD, lenAD);
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
		finally {
			free(checkerIn, hashIn, limitedRandomInputStream, symmetricChecker, asymmetricChecker, digest);
		}
	}
	public Integrity checkHashAndSignature() throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();


		try {

			byte code=checkCodeForCheckHashAndSignature();

			if (symmetricChecker==null && asymmetricChecker==null && digest==null)
				return Integrity.OK;
			AbstractMessageDigest digest=this.digest;
			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null) {
				if (defaultMessageDigest==null)
					defaultMessageDigest=digest=EncryptionSignatureHashEncoder.defaultMessageType.getMessageDigestInstance();
				else
					digest = defaultMessageDigest;
			}

			long dataLen=inputStream.readLong();
			long dataPos=inputStream.currentPosition();

			Bits.putLong(buffer, 0, dataLen);

			if (digest!=null) {

				digest.reset();
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				digest.update(limitedRandomInputStream);
				digest.update(code);
				digest.update(buffer, 0, 8);


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
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				symmetricChecker.update(limitedRandomInputStream);
				symmetricChecker.update(code);
				symmetricChecker.update(buffer, 0, 8);
				if (symmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;

			}
			else
			{

				inputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				asymmetricChecker.update(limitedRandomInputStream);
				asymmetricChecker.update(code);
				asymmetricChecker.update(buffer, 0, 8);
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
		finally {
			free(limitedRandomInputStream);
		}
	}
	public Integrity checkHashAndPublicSignature() throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();


		try {

			byte code=checkCodeForCheckHashAndPublicSignature();
			boolean symCheckOK=hasSymmetricSignature(code);
			AbstractMessageDigest digest=this.digest;
			if (symCheckOK && asymmetricChecker!=null && digest==null)
			{
				if (defaultMessageDigest==null)
					defaultMessageDigest=digest=EncryptionSignatureHashEncoder.defaultMessageType.getMessageDigestInstance();
				else
					digest = defaultMessageDigest;
			}
			if (asymmetricChecker==null && digest==null)
				return Integrity.OK;
			long dataLen=inputStream.readLong();
			long dataPos=inputStream.currentPosition();

			Bits.putLong(buffer, 0, dataLen);

			if (digest!=null) {
				digest.reset();
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				digest.update(limitedRandomInputStream);
				digest.update(code);
				digest.update(buffer, 0, 8);


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
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				asymmetricChecker.update(limitedRandomInputStream);
				asymmetricChecker.update(code);
				asymmetricChecker.update(buffer, 0, 8);
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
		finally {
			free(limitedRandomInputStream);
		}
	}
	public SubStreamHashResult computePartialHash(SubStreamParameters subStreamParameters) throws IOException {

		try {
			if (cipher == null) {
				return new SubStreamHashResult(subStreamParameters.generateHash(inputStream), null);
			} else {
				return cipher.getIVAndPartialHashedSubStreamFromEncryptedStream(inputStream, subStreamParameters);
			}
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}
	public long getMaximumOutputLength() throws IOException {
		return EncryptionSignatureHashEncoder.getMaximumOutputLengthAfterDecoding(inputStream.length(), cipher, getMinimumInputSize());
	}

	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		return EncryptionSignatureHashEncoder.getMaximumOutputLengthAfterDecoding(inputStreamLength, cipher, getMinimumInputSize());
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
}
