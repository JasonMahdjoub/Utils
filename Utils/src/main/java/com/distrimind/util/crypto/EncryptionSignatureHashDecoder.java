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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 4.16.0
 */
public class EncryptionSignatureHashDecoder {

	private RandomInputStream inputStream=null;
	SymmetricEncryptionAlgorithm cipher=null;
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
	private SymmetricSecretKey originalSecretKeyForEncryption=null;
	private EncryptionProfileProvider encryptionProfileProvider =null;
	private AbstractSecureRandom randomForCipher=null;
	private short secretKeyID=-1;
	private short oldSecretKeyID=-1;
	EncryptionSignatureHashEncoder encoder=null;
	private boolean changeCipherOfEncoder=false;
	private Byte code=null;
	private long dataLen=-1;

	public EncryptionSignatureHashDecoder connectWithEncoder(EncryptionSignatureHashEncoder encoder)
	{
		encoder.connectWithDecoder(this);
		return this;
	}

	public EncryptionSignatureHashDecoder() throws IOException {
		limitedRandomInputStream=new LimitedRandomInputStream(nullRandomInputStream, 0);
	}
	public EncryptionSignatureHashDecoder withRandomInputStream(RandomInputStream inputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()==0)
			throw new IllegalArgumentException();
		this.inputStream=inputStream;
		this.code=null;
		return this;
	}
	public EncryptionSignatureHashDecoder withExternalCounter(byte[] externalCounter) {
		if (externalCounter==null)
			throw new NullPointerException();
		this.externalCounter=externalCounter;
		return this;
	}
	public EncryptionSignatureHashDecoder withoutExternalCounter() {
		this.externalCounter=null;
		return this;
	}

	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withSymmetricSecretKeyForEncryption(random, symmetricSecretKeyForEncryption, (byte)0);
	}
	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption, byte externalCounterLength) throws IOException {
		if (externalCounterLength<=0)
			return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
		else
			return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption, externalCounterLength));
	}

	public EncryptionSignatureHashDecoder withCipher(SymmetricEncryptionAlgorithm cipher) {
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=cipher;
		this.randomForCipher=null;
		originalSecretKeyForEncryption=cipher.getSecretKey();
		return this;
	}
	private void checkProfileLoadedForPrivateCheck() throws IOException {
		if (encryptionProfileProvider !=null)
		{
			try {
				SymmetricSecretKey secretKey = encryptionProfileProvider.getSecretKeyForSignature(secretKeyID, true);
				if (secretKey == null)
					symmetricChecker = null;
				else if (symmetricChecker == null || secretKey != symmetricChecker.getSecretKey())
					symmetricChecker = new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKey);
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}
	}
	private void checkProfileLoadedForPublicCheck() throws IOException {

		if (encryptionProfileProvider !=null)
		{
			checkHeadRead();
			try {
				IASymmetricPublicKey publicKey=encryptionProfileProvider.getSecretKeyForPublicKey(secretKeyID);
				if (publicKey == null)
					asymmetricChecker = null;
				else if (asymmetricChecker == null || publicKey != asymmetricChecker.getDistantPublicKey())
					asymmetricChecker = new ASymmetricAuthenticatedSignatureCheckerAlgorithm(publicKey);
				MessageDigestType messageDigestType=encryptionProfileProvider.getMessageDigest(secretKeyID, true);
				if (messageDigestType == null)
					digest = null;
				else if (digest == null || messageDigestType != digest.getMessageDigestType())
					digest =messageDigestType.getMessageDigestInstance();
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				throw new IOException(e);
			}
		}
	}
	private void checkProfileLoadedForDecryption() throws IOException {
		if (encryptionProfileProvider !=null)
		{
			SymmetricSecretKey secretKey = encryptionProfileProvider.getSecretKeyForEncryption(secretKeyID, true);
			if (secretKey == null)
				cipher = null;
			else if (cipher == null || secretKey != cipher.getSecretKey())
				cipher = new SymmetricEncryptionAlgorithm(randomForCipher, secretKey);
		}
		else if (cipher!=null)
		{
			if (encoder!=null)
				encoder.incrementIVCounter();
			changeCipherOfEncoder=false;
			if (encoder!=null && secretKeyID!=encoder.currentKeyID) {
				int oldRound = encoder.currentKeyID & 0xFF;
				int round = secretKeyID & 0xFF;
				if (oldRound + 1 == round) {
					changeCipherOfEncoder = true;
				}
			}
			boolean externalCounterSizeChanged=(externalCounter==null && cipher.getBlockModeCounterBytes()!=0)
							|| (externalCounter!=null && cipher.getBlockModeCounterBytes()!=externalCounter.length);
			if (externalCounterSizeChanged|| oldSecretKeyID!=secretKeyID || changeCipherOfEncoder)
			{
				oldSecretKeyID=secretKeyID;
				if (externalCounterSizeChanged || (secretKeyID!=0 || cipher.getSecretKey()!=originalSecretKeyForEncryption))
					cipher=EncryptionSignatureHashEncoder.reloadCipher(cipher.getSecureRandom(), originalSecretKeyForEncryption, secretKeyID, externalCounter);

			}

		}
	}

	public EncryptionSignatureHashDecoder withSecretKeyProvider(AbstractSecureRandom random, EncryptionProfileProvider encryptionProfileProvider) {
		if (random==null)
			throw new NullPointerException();
		if (encryptionProfileProvider ==null)
			throw new NullPointerException();
		this.randomForCipher=random;
		this.encryptionProfileProvider = encryptionProfileProvider;
		this.cipher=null;
		originalSecretKeyForEncryption=null;
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
		return this;
	}
	@SuppressWarnings("UnusedReturnValue")
	public EncryptionSignatureHashDecoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			minimumInputSize=null;
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
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
		return this;
	}

	private long getMinimumInputSize()
	{
		if (minimumInputSize==null)
			minimumInputSize=getMinimumInputLengthAfterDecoding();
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
	public boolean hasSymmetricSignature() throws IOException {
		checkHeadRead();
		return (code & 1)==1;
	}

	public boolean hasASymmetricSignature() throws IOException {
		checkHeadRead();
		return (code & 2)==2;
	}

	public boolean isHashed() throws IOException {
		checkHeadRead();
		return (code & 4)==4;
	}
	public boolean hasAssociatedData() throws IOException {
		checkHeadRead();
		return (code & 8)==8;
	}
	public boolean isEncrypted() throws IOException {
		checkHeadRead();
		return (code & 16)==16;
	}
	private void checkCodeForDecode() throws IOException {
		if (associatedData!=null)
			EncryptionSignatureHashEncoder.checkLimits(associatedData, offAD, lenAD);

		checkCodeForCheckHashAndSignature();
		checkProfileLoadedForDecryption();
		boolean hasAssociatedData=hasAssociatedData();
		if (hasAssociatedData && associatedData==null)
			throw new NullPointerException("associatedData");
		else if (!hasAssociatedData && associatedData!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
		if (hasAssociatedData && (cipher==null || !cipher.getType().supportAssociatedData()) && symmetricChecker==null && asymmetricChecker==null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
		boolean hasCipher= isEncrypted();
		if (hasCipher && cipher==null)
			throw new NullPointerException("cipher");
		/*else if (!hasCipher && cipher!=null)
			throw new MessageExternalizationException(Integrity.FAIL, "cipher");*/
	}
	private void checkCodeForCheckHashAndSignature() throws IOException {
		checkCodeForCheckHashAndPublicSignature();
		checkProfileLoadedForPrivateCheck();
		boolean symCheckOK=hasSymmetricSignature();
		if (symCheckOK && symmetricChecker==null)
			throw new NullPointerException("symmetricChecker");
		else if(!symCheckOK && symmetricChecker!=null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "symmetricChecker");
	}
	private void checkCodeForCheckHashAndPublicSignature() throws IOException {
		checkProfileLoadedForPublicCheck();

		boolean asymCheckOK=hasASymmetricSignature();
		boolean hashCheckOK= isHashed();

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
	}

	private void freeAll() throws IOException {
		if (checkerIn!=null)
			checkerIn.set(EncryptionSignatureHashDecoder.nullRandomInputStream, symmetricChecker==null?asymmetricChecker:symmetricChecker);
		if (hashIn!=null)
			hashIn.set(EncryptionSignatureHashDecoder.nullRandomInputStream, digest==null?defaultMessageDigest:digest);

		freeLimitedRandomInputStream();
	}
	private void freeLimitedRandomInputStream() throws IOException {
		changeCipherOfEncoder=false;
		limitedRandomInputStream.set(EncryptionSignatureHashDecoder.nullRandomInputStream, 0);
	}

	private void checkHeadRead() throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=EncryptionSignatureHashEncoder.headSize)
			throw new IOException();
		if (code==null)
		{
			if (inputStream.currentPosition()!=0)
				inputStream.seek(0);
			code=inputStream.readByte();
			secretKeyID=inputStream.readShort();
			dataLen=inputStream.readLong();
		}
	}

	public long getDataStartPosition() {
		return EncryptionSignatureHashEncoder.headSize;
	}

	public long getDataSizeInBytesBeforeDecryption() throws IOException {
		checkHeadRead();
		return dataLen;
	}

	public long getDataSizeInBytesAfterDecryption() throws IOException {
		checkHeadRead();
		if (isEncrypted())
			return cipher.getOutputSizeAfterDecryption(dataLen);
		else
			return dataLen;
	}

	@SuppressWarnings("UnusedReturnValue")
	public long decodeAndCheckHashAndSignaturesIfNecessary(RandomOutputStream outputStream) throws IOException {
		if (outputStream==null)
			throw new NullPointerException();

		RandomInputStream originalInputStream=inputStream;
		if (originalInputStream==null)
			throw new NullPointerException();
		if (originalInputStream.length()<=0)
			throw new IllegalArgumentException();
		long res;
		try {
			long originalOutputLength=outputStream.length();
			long maximumOutputLengthAfterEncoding=getMaximumOutputLength();
			outputStream.ensureLength(maximumOutputLengthAfterEncoding);
			checkCodeForDecode();
			if (inputStream.currentPosition()!=EncryptionSignatureHashEncoder.headSize)
				inputStream.seek(EncryptionSignatureHashEncoder.headSize);

			AbstractMessageDigest digest=this.digest;
			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null) {
				if (defaultMessageDigest==null) {
					defaultMessageDigest = digest = EncryptionSignatureHashEncoder.defaultMessageType.getMessageDigestInstance();
				}
				else
					digest = defaultMessageDigest;

			}

			checkDataLength(inputStream, dataLen);
			RandomInputStream inputStream=originalInputStream;
			if (digest!=null) {
				digest.reset();
				if (hashIn==null)
					hashIn=new HashRandomInputStream(inputStream, digest);
				else
					hashIn.set(inputStream, digest);
				inputStream = hashIn;
			}
			else if (symmetricChecker!=null)
			{
				originalInputStream.seek(EncryptionSignatureHashEncoder.headSize+dataLen);
				symmetricChecker.init(originalInputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes()));
				if (checkerIn==null)
					checkerIn=new SignatureCheckerRandomInputStream(inputStream, symmetricChecker);
				else
					checkerIn.set(inputStream, symmetricChecker);
				inputStream=checkerIn;
			}
			else if (asymmetricChecker!=null)
			{
				originalInputStream.seek(EncryptionSignatureHashEncoder.headSize+dataLen);
				asymmetricChecker.init(originalInputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				if (checkerIn==null)
					checkerIn=new SignatureCheckerRandomInputStream(inputStream, asymmetricChecker);
				else
					checkerIn.set(inputStream, asymmetricChecker);
				inputStream=checkerIn;
			}

			try {
				limitedRandomInputStream.set(inputStream, EncryptionSignatureHashEncoder.headSize, dataLen);
			}
			catch (IllegalArgumentException | NullPointerException e)
			{
				throw new IOException(e);
			}
			byte[] buffer=null;
			int lenBuffer=0;
			if (isEncrypted()) {
				if (cipher.getType().supportAssociatedData()) {
					lenBuffer=EncryptionSignatureHashEncoder.headSize+(associatedData!=null?lenAD:0);
					if (this.buffer.length<lenBuffer)
						buffer=this.buffer=new byte[lenBuffer];
					else
						buffer=this.buffer;
					Bits.putShort(buffer, 0, secretKeyID);
					Bits.putLong(buffer, 2, dataLen);
					buffer[10]=code;
					if (associatedData!=null)
					{
						System.arraycopy(associatedData, offAD, buffer, EncryptionSignatureHashEncoder.headSize, lenAD);
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
					res=cipherInputStream.transferTo(outputStream);
				}
				finally {
					cipherInputStream.close();
				}

			}
			else
			{
				outputStream.write(limitedRandomInputStream);
				res=limitedRandomInputStream.length();
			}
			if (buffer==null && (digest!=null || symmetricChecker!=null || asymmetricChecker!=null)) {
				buffer=this.buffer;
				Bits.putShort(buffer, 0, secretKeyID);
				Bits.putLong(buffer, 2, dataLen);
				lenBuffer=10;

			}

			if (digest!=null) {
				digest.update(code);
				digest.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
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
					if (lenBuffer>EncryptionSignatureHashEncoder.headSizeMinusOne)
						symmetricChecker.update(associatedData, offAD, lenAD);
					symmetricChecker.update(hash);
					if (!symmetricChecker.verify())
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}

				if (asymmetricChecker!=null) {
					assert asymSign != null;
					asymmetricChecker.init(asymSign, 0, asymSign.length);
					asymmetricChecker.update(hash2);
					if (!asymmetricChecker.verify())
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}
			}
			else if (symmetricChecker!=null)
			{
				if (lenBuffer==EncryptionSignatureHashEncoder.headSizeMinusOne)
					symmetricChecker.update(code);
				symmetricChecker.update(buffer, 0, lenBuffer);
				if (!symmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			} else if (asymmetricChecker!=null)
			{
				asymmetricChecker.update(code);
				asymmetricChecker.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
				if (!asymmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			long curPos=outputStream.currentPosition();
			if (curPos<maximumOutputLengthAfterEncoding && curPos>originalOutputLength)
				outputStream.setLength(Math.max(curPos, originalOutputLength));
			outputStream.flush();
			if (changeCipherOfEncoder)
			{
				encoder.cipher=cipher;
				encoder.generatedIVCounter=0;
				encoder.currentKeyID=secretKeyID;
			}
			return res;
		}
		catch(NoSuchAlgorithmException | NoSuchProviderException e)
		{
			throw new IOException(e);
		}
		finally {
			freeAll();
		}
	}
	private void checkDataLength(RandomInputStream inputStream, long dataLen) throws IOException {
		if (dataLen<=0)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		if (dataLen>inputStream.length())
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
	}
	public Integrity checkHashAndSignature() throws IOException {


		try {
			checkCodeForCheckHashAndSignature();

			if (symmetricChecker==null && asymmetricChecker==null && digest==null)
				return Integrity.OK;
			AbstractMessageDigest digest=this.digest;
			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null) {
				if (defaultMessageDigest==null)
					defaultMessageDigest=digest=EncryptionSignatureHashEncoder.defaultMessageType.getMessageDigestInstance();
				else
					digest = defaultMessageDigest;
			}
			if (inputStream.currentPosition()!=EncryptionSignatureHashEncoder.headSize)
				inputStream.seek(EncryptionSignatureHashEncoder.headSize);

			checkDataLength(inputStream, dataLen);
			long dataPos=inputStream.currentPosition();
			Bits.putShort(buffer, 0, secretKeyID);
			Bits.putLong(buffer, 2, dataLen);

			if (digest!=null) {

				digest.reset();
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				digest.update(limitedRandomInputStream);
				digest.update(code);
				digest.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);


				byte[] hash = digest.digest();
				byte[] hash2=hash;
				byte[] hash3=hash;
				byte[] symSign=null;
				byte[] asymSign=null;
				if (symmetricChecker!=null)
				{
					symSign=inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes());
					digest.reset();
					if (associatedData!=null)
						symmetricChecker.update(associatedData, offAD, lenAD);
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
				symmetricChecker.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
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
				asymmetricChecker.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
				if (asymmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
			}


		} catch (MessageExternalizationException e)
		{
			return e.getIntegrity();
		} catch(NoSuchAlgorithmException | NoSuchProviderException | IllegalArgumentException | IOException | NullPointerException e)
		{
			return Integrity.FAIL;
		}
		finally {
			freeLimitedRandomInputStream();
		}
	}
	public Integrity checkHashAndPublicSignature() throws IOException {


		try {

			checkCodeForCheckHashAndPublicSignature();
			boolean symCheckOK=hasSymmetricSignature();
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
			if (inputStream.currentPosition()!=EncryptionSignatureHashEncoder.headSize)
				inputStream.seek(EncryptionSignatureHashEncoder.headSize);

			checkDataLength(inputStream, dataLen);
			long dataPos=inputStream.currentPosition();

			Bits.putShort(buffer, 0, secretKeyID);
			Bits.putLong(buffer, 2, dataLen);

			if (digest!=null) {
				digest.reset();
				limitedRandomInputStream.set(inputStream, dataPos, dataLen);
				digest.update(limitedRandomInputStream);
				digest.update(code);
				digest.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);


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
				asymmetricChecker.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
				if (asymmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;
			}


		} catch (MessageExternalizationException e)
		{
			return e.getIntegrity();
		} catch(NoSuchAlgorithmException | NoSuchProviderException | IllegalArgumentException | IOException | NullPointerException e)
		{
			return Integrity.FAIL;
		}
		finally {
			freeLimitedRandomInputStream();
		}
	}
	public SubStreamHashResult computePartialHash(MessageDigestType messageDigestType, long subStreamLengthInBytes, AbstractSecureRandom random) throws IOException {
		inputStream.seek(3);
		long dataLen=inputStream.readLong()+EncryptionSignatureHashEncoder.headSize;
		return computePartialHash(new SubStreamParameters(messageDigestType, dataLen, subStreamLengthInBytes, random, cipher==null?1:cipher.getCounterStepInBytes()));
	}
	public SubStreamHashResult computePartialHash(SubStreamParameters subStreamParameters) throws IOException {
		if (inputStream.currentPosition()!=0)
			inputStream.seek(0);
		try {
			if (cipher == null) {
				return new SubStreamHashResult(subStreamParameters.generateHash(inputStream), null);
			} else {
				return cipher.getIVAndPartialHashedSubStreamFromEncryptedStream(inputStream, subStreamParameters, EncryptionSignatureHashEncoder.headSize);
			}
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}
	public long getMaximumOutputLength() throws IOException {
		return getMaximumOutputLength(inputStream.length());
	}

	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		if (inputStreamLength<=0)
			throw new IllegalArgumentException();
		long res=inputStreamLength-getMinimumInputSize();

		if (res<=0)
			throw new IllegalArgumentException();
		if (cipher!=null)
			return cipher.getOutputSizeAfterDecryption(res);
		else
			return res;
	}

	private long getMinimumInputLengthAfterDecoding()
	{
		long res=EncryptionSignatureHashEncoder.headSize;

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
				v=EncryptionSignatureHashEncoder.defaultMessageType.getDigestLengthInBits() / 8;
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

	public SymmetricSecretKey getSymmetricSecretKeyForEncryption()
	{
		return cipher==null?null:cipher.getSecretKey();
	}

	public SymmetricSecretKey getSymmetricSecretKeyForSignature()
	{
		return symmetricChecker==null?null:symmetricChecker.getSecretKey();
	}

	public IASymmetricPublicKey getPublicKeyForSignature()
	{
		return asymmetricChecker==null?null:asymmetricChecker.getDistantPublicKey();
	}

	public MessageDigestType getMessageDigestType()
	{
		return digest==null?null:digest.getMessageDigestType();
	}

	public EncryptionSignatureHashDecoder withoutSymmetricEncryption()
	{
		cipher=null;
		this.randomForCipher=null;
		minimumInputSize=null;
		return this;
	}

	public EncryptionSignatureHashDecoder withoutSymmetricSignature()
	{
		symmetricChecker=null;
		minimumInputSize=null;
		return this;
	}
	public EncryptionSignatureHashDecoder withoutASymmetricSignature()
	{
		asymmetricChecker=null;
		minimumInputSize=null;
		return this;
	}

	public EncryptionSignatureHashDecoder withoutMessageDigest()
	{
		digest=null;
		minimumInputSize=null;
		return this;
	}


}
