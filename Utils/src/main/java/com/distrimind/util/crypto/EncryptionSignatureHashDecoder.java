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
import com.distrimind.util.Reference;
import com.distrimind.util.io.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 1.5
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
	CommonCipherInputStream cipherInputStream=null;
	private SymmetricSecretKey originalSecretKeyForEncryption=null;
	private EncryptionProfileProvider encryptionProfileProvider =null;
	private AbstractSecureRandom randomForCipher=null;
	private short secretKeyID=-1;
	private short oldSecretKeyID=-1;
	EncryptionSignatureHashEncoder encoder=null;
	private boolean changeCipherOfEncoder=false;
	private Byte code=null;
	private long dataLen=-1;
	private final RandomByteArrayInputStream randomByteArrayInputStream=new RandomByteArrayInputStream(emptyTab);
	private final LimitedRandomInputStream limitedRandomInputStream2=new LimitedRandomInputStream(randomByteArrayInputStream, 0 );
	private final RandomByteArrayOutputStream randomByteArrayOutputStream=new RandomByteArrayOutputStream();
	private final LimitedRandomOutputStream randomOutputStream=new LimitedRandomOutputStream(randomByteArrayOutputStream, 0 );
	private final NullRandomOutputStream nullRandomOutputStream=new NullRandomOutputStream();
	private static final byte[] emptyTab=new byte[0];

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
	public EncryptionSignatureHashDecoder withExternalCounter(byte[] externalCounter) throws IOException {
		if (externalCounter==null)
			throw new NullPointerException();
		if (this.externalCounter!=externalCounter) {
			this.externalCounter = externalCounter;
			reloadCipher();
		}
		return this;
	}
	public EncryptionSignatureHashDecoder withoutExternalCounter() throws IOException {
		if (this.externalCounter!=null) {
			this.externalCounter = null;
			reloadCipher();
		}
		return this;
	}

	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryption(SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withSymmetricSecretKeyForEncryption(symmetricSecretKeyForEncryption, (byte)0);
	}
	public EncryptionSignatureHashDecoder withSymmetricSecretKeyForEncryption(SymmetricSecretKey symmetricSecretKeyForEncryption, byte externalCounterLength) throws IOException {
		try {
			byte sc=symmetricSecretKeyForEncryption.getEncryptionAlgorithmType().getMaxCounterSizeInBytesUsedWithBlockMode();
			if (externalCounterLength <= 0)
				return withCipher(new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getSingleton(null), symmetricSecretKeyForEncryption));
			else
				return withCipher(new SymmetricEncryptionAlgorithm(SecureRandomType.DEFAULT.getSingleton(null), symmetricSecretKeyForEncryption, (byte)(Math.min(externalCounterLength, sc))));
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}
	public int getExternalCounterLength()
	{
		return externalCounter==null?0:externalCounter.length;
	}

	public int getAssociatedDataLength()
	{
		return lenAD;
	}

	public EncryptionSignatureHashDecoder withCipher(SymmetricEncryptionAlgorithm cipher) throws IOException {
		if (cipher==null)
			throw new NullPointerException();
		this.cipher=null;
		this.randomForCipher=cipher.getSecureRandom();
		originalSecretKeyForEncryption=cipher.getSecretKey();
		reloadCipher();
		cleanCache();
		return this;
	}

	private void checkProfileLoadedForPrivateCheck() throws IOException {
		if (encryptionProfileProvider !=null)
		{
			cleanCache();
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
			cleanCache();
			if (!encryptionProfileProvider.isValidProfileID(secretKeyID))
				throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			try {
				IASymmetricPublicKey publicKey=encryptionProfileProvider.getPublicKeyForSignature(secretKeyID);
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
			originalSecretKeyForEncryption = encryptionProfileProvider.getSecretKeyForEncryption(secretKeyID, true);
			if (originalSecretKeyForEncryption == null) {
				cipher = null;
				cleanCache();
			}
			else {
				reloadCipher();
			}
		}
		else if (cipher!=null)
		{
			if (encoder!=null)
				encoder.incrementIVCounter();
			reloadCipher();

		}
	}

	public EncryptionSignatureHashDecoder withEncryptionProfileProvider(EncryptionProfileProvider encryptionProfileProvider) throws IOException {
		if (encryptionProfileProvider ==null)
			throw new NullPointerException();
		try {
			this.randomForCipher=SecureRandomType.DEFAULT.getInstance(null);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		this.encryptionProfileProvider = encryptionProfileProvider;
		this.cipher=null;

		originalSecretKeyForEncryption=null;
		this.digest=null;
		this.asymmetricChecker=null;
		this.symmetricChecker=null;
		cleanCache();
		return this;
	}
	public EncryptionSignatureHashDecoder withoutAssociatedData()
	{
		if (this.associatedData!=null) {
			this.associatedData = null;
			this.offAD = 0;
			this.lenAD = 0;
			cleanCache();
		}
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

		if (this.associatedData!=associatedData || this.offAD!=offAD || this.lenAD!=lenAD) {
			EncryptionSignatureHashEncoder.checkLimits(associatedData, offAD, lenAD);
			this.associatedData = associatedData;
			this.offAD = offAD;
			this.lenAD = lenAD;
			cleanCache();
		}
		return this;
	}
	public EncryptionSignatureHashDecoder withMessageDigest(AbstractMessageDigest messageDigest)
	{
		if (digest==null)
			throw new NullPointerException();
		this.digest=messageDigest;
		cleanCache();
		return this;
	}
	@SuppressWarnings("UnusedReturnValue")
	public EncryptionSignatureHashDecoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			cleanCache();
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
		cleanCache();

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
		cleanCache();
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
			cleanCache();
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
	public static boolean isEncrypted(RandomInputStream ris) throws IOException {
		if (ris.currentPosition()!=0)
			ris.seek(0);
		return (ris.readByte() & 16)==16;
	}
	public static boolean isEncrypted(byte[] tab, int off) {
		return (tab[off] & 16)==16;
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
		boolean hasCipher= isEncrypted();
		if (hasCipher && cipher==null)
			throw new NullPointerException("cipher");
		if (hasAssociatedData && (cipher==null || !cipher.getType().supportAssociatedData()) && symmetricChecker==null)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "associatedData");
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
		randomByteArrayOutputStream.init(emptyTab);
		randomOutputStream.init(randomByteArrayOutputStream, 0);
		freeLimitedRandomInputStream();
	}
	private void freeLimitedRandomInputStream() throws IOException {
		changeCipherOfEncoder=false;
		limitedRandomInputStream.init(EncryptionSignatureHashDecoder.nullRandomInputStream, 0);
		randomByteArrayInputStream.init(emptyTab);
		limitedRandomInputStream2.init(randomByteArrayInputStream, 0 );
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
	public long getDataSizeInBytesAfterDecryptionOrAfterPublicSignatureChecking() throws IOException {
		checkHeadRead();
		if (isEncrypted()) {
			if (cipher==null)
				return dataLen;
			return cipher.getOutputSizeAfterDecryption(dataLen);
		}
		else
			return dataLen;
	}
	public long getDataSizeInBytesAfterDecryption() throws IOException {
		checkHeadRead();
		if (isEncrypted()) {
			return cipher.getOutputSizeAfterDecryption(dataLen);
		}
		else
			return dataLen;
	}
	public int decodeAndCheckHashAndSignaturesIfNecessary(byte[] cipherText, int cipherTextOff, int cipherTextLen, byte[] data, int dataOff, int dataLen) throws IOException {
		EncryptionSignatureHashEncoder.checkLimits(cipherText, cipherTextOff, cipherTextLen);
		EncryptionSignatureHashEncoder.checkLimits(data, dataOff, dataLen);
		if (cipherTextLen<=0)
			throw new IllegalArgumentException();
		if (dataLen<=0)
			throw new IllegalArgumentException();
		randomByteArrayInputStream.init(cipherText);
		limitedRandomInputStream2.init(randomByteArrayInputStream, cipherTextOff, cipherTextLen);
		withRandomInputStream(limitedRandomInputStream2);
		randomByteArrayOutputStream.init(data);
		randomOutputStream.init(randomByteArrayOutputStream, dataOff, dataLen);
		return (int)decodeAndCheckHashAndSignaturesIfNecessary(randomOutputStream);
	}
	public int decodeAndCheckHashAndSignaturesIfNecessaryWithSameInputAndOutputStreamSource(byte[] data, int dataOff, int dataLen) throws IOException {
		EncryptionSignatureHashEncoder.checkLimits(data, dataOff, dataLen);
		if (dataLen<=0)
			throw new IllegalArgumentException();
		randomByteArrayInputStream.init(data);
		limitedRandomInputStream2.init(randomByteArrayInputStream, dataOff, dataLen);
		withRandomInputStream(limitedRandomInputStream2);
		randomByteArrayOutputStream.init(data);
		randomOutputStream.init(randomByteArrayOutputStream, dataOff+EncryptionSignatureHashEncoder.headSize, dataLen-EncryptionSignatureHashEncoder.headSize);
		return (int)decodeAndCheckHashAndSignaturesIfNecessary(randomOutputStream, true, null, false);

	}
	private void init(RandomInputStream hashAndSignatures, RandomInputStream data) throws IOException {
		withRandomInputStream(new AggregatedRandomInputStreams(
				new LimitedRandomInputStream(hashAndSignatures, 0, EncryptionSignatureHashEncoder.headSize),
				data,
				new LimitedRandomInputStream(hashAndSignatures, EncryptionSignatureHashEncoder.headSize)
		));

	}
	private void init(byte[] hashAndSignatures, int hashAndSignaturesOff, int hashAndSignaturesLen, byte[] data, int dataOff, int dataLen) throws IOException {
		EncryptionSignatureHashEncoder.checkLimits(hashAndSignatures, hashAndSignaturesOff, hashAndSignaturesLen);
		EncryptionSignatureHashEncoder.checkLimits(data, dataOff, dataLen);
		RandomByteArrayInputStream hashAndSignaturesS=new RandomByteArrayInputStream(hashAndSignatures);
		RandomByteArrayInputStream dataS=new RandomByteArrayInputStream(data);
		withRandomInputStream(new AggregatedRandomInputStreams(
				new LimitedRandomInputStream(hashAndSignaturesS, hashAndSignaturesOff, EncryptionSignatureHashEncoder.headSize),
				new LimitedRandomInputStream(dataS, dataOff, dataLen),
				new LimitedRandomInputStream(hashAndSignaturesS, EncryptionSignatureHashEncoder.headSize+hashAndSignaturesOff, hashAndSignaturesLen-EncryptionSignatureHashEncoder.headSize)
			));
	}
	public Integrity checkHashAndPublicSignature(byte[] hashAndSignatures, int hashAndSignaturesOff, int hashAndSignaturesLen, byte[] data, int dataOff, int dataLen) throws IOException {
		init(hashAndSignatures, hashAndSignaturesOff, hashAndSignaturesLen, data, dataOff, dataLen);

		Integrity i=checkHashAndPublicSignature();
		if (i!=Integrity.OK)
			return i;
		return checkParametersForHashAndSignaturesAlone(true);
	}
	public Integrity checkHashAndPublicSignature(RandomInputStream hashAndSignatures, RandomInputStream data) throws IOException {
		init(hashAndSignatures, data);

		Integrity i= checkHashAndPublicSignature();
		if (i!=Integrity.OK)
			return i;
		return checkParametersForHashAndSignaturesAlone(true);
	}
	private Integrity checkParametersForHashAndSignaturesAlone(boolean duringPublicSignatureChecking) throws IOException {
		if (isEncrypted())
			return Integrity.FAIL;
		if (!duringPublicSignatureChecking && symmetricChecker==null && asymmetricChecker==null && digest==null)
			return Integrity.FAIL;
		return Integrity.OK;
	}
	public Integrity checkHashAndSignatures(byte[] hashAndSignatures, int hashAndSignaturesOff, int hashAndSignaturesLen, byte[] data, int dataOff, int dataLen) throws IOException {
		init(hashAndSignatures, hashAndSignaturesOff, hashAndSignaturesLen, data, dataOff, dataLen);

		Integrity i=checkHashAndSignatures();
		if (i!=Integrity.OK)
			return i;
		return checkParametersForHashAndSignaturesAlone(false);
	}
	public Integrity checkHashAndSignatures(RandomInputStream hashAndSignatures, RandomInputStream data) throws IOException {
		init(hashAndSignatures, data);

		Integrity i=checkHashAndSignatures();
		if (i!=Integrity.OK)
			return i;
		return checkParametersForHashAndSignaturesAlone(false);
	}
	public RandomInputStream decodeAndCheckHashAndSignaturesIfNecessary() throws IOException {
		return decodeAndCheckHashAndSignaturesIfNecessary((Reference<Long>)null);
	}
	public RandomInputStream decodeAndCheckHashAndSignaturesIfNecessary(Reference<Long> positionOfRandomInputStreamAfterDecoding) throws IOException {
		if (isEncrypted()) {
			final RandomOutputStream out=RandomCacheFileCenter.getSingleton().getNewBufferedRandomCacheFileOutputStream(true);
			decodeAndCheckHashAndSignaturesIfNecessary(out,  false, positionOfRandomInputStreamAfterDecoding, false);

			return new RandomInputStream(){
				final RandomOutputStream rout=out;
				final RandomInputStream ris=out.getRandomInputStream();
				@Override
				public long currentPosition() throws IOException {
					return ris.currentPosition();
				}

				@Override
				public long length() throws IOException {
					return ris.length();
				}

				@Override
				public void seek(long _pos) throws IOException {
					ris.seek(_pos);
				}

				@Override
				public boolean isClosed() {
					return ris.isClosed();
				}

				@Override
				public void readFully(byte[] tab, int off, int len) throws IOException {
					ris.readFully(tab, off, len);
				}

				@Override
				public String readLine() throws IOException {
					return ris.readLine();
				}

				@Override
				public int read() throws IOException {
					return ris.read();
				}

				@Override
				public void close() throws IOException {
					rout.close();
					ris.close();
				}
			};
		}
		else
		{
			long length=decodeAndCheckHashAndSignaturesIfNecessary(null, true, positionOfRandomInputStreamAfterDecoding, true);
			return new LimitedRandomInputStream(this.inputStream, EncryptionSignatureHashEncoder.headSize, length){
				@Override
				public void close() {

				}
			};
		}
	}
	public long decodeAndCheckHashAndSignaturesIfNecessary(RandomOutputStream outputStream) throws IOException {
		return decodeAndCheckHashAndSignaturesIfNecessary(outputStream, false, null, false);
	}
	public AbstractSecureRandom getCipherSecureRandom()
	{
		return cipher==null?null:cipher.getSecureRandom();
	}
	private long decodeAndCheckHashAndSignaturesIfNecessary(final RandomOutputStream outputStream, final boolean sameInputOutputSource, final Reference<Long> positionOfRandomInputStreamAfterDecoding, boolean outputStreamNull) throws IOException {
		if (outputStream==null && !outputStreamNull)
			throw new NullPointerException();
		if (outputStreamNull && !sameInputOutputSource)
			throw new IllegalAccessError();


		RandomInputStream originalInputStream=inputStream;
		if (originalInputStream==null)
			throw new NullPointerException();
		if (originalInputStream.length()<=0)
			throw new IllegalArgumentException();
		long res;
		try {
			long originalOutputLength=-1;
			long maximumOutputLengthAfterEncoding=-1;
			if (outputStream==null) {
				checkCodeForDecode();
			}
			else
			{
				originalOutputLength = outputStream.length();
				maximumOutputLengthAfterEncoding = getMaximumOutputLength();
				outputStream.ensureLength(maximumOutputLengthAfterEncoding);
			}

			if (sameInputOutputSource && isEncrypted())
				throw new IOException("You must use a different input/output stream when using a encryption");
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
				symmetricChecker.init(originalInputStream.readBytesArray(false, SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE));
				if (positionOfRandomInputStreamAfterDecoding!=null)
					positionOfRandomInputStreamAfterDecoding.set(originalInputStream.currentPosition());
				if (checkerIn==null)
					checkerIn=new SignatureCheckerRandomInputStream(inputStream, symmetricChecker);
				else
					checkerIn.set(inputStream, symmetricChecker);
				inputStream=checkerIn;
			}
			else if (asymmetricChecker!=null)
			{
				originalInputStream.seek(EncryptionSignatureHashEncoder.headSize+dataLen);
				asymmetricChecker.init(originalInputStream.readBytesArray(false, ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE));
				if (positionOfRandomInputStreamAfterDecoding!=null)
					positionOfRandomInputStreamAfterDecoding.set(originalInputStream.currentPosition());
				if (checkerIn==null)
					checkerIn=new SignatureCheckerRandomInputStream(inputStream, asymmetricChecker);
				else
					checkerIn.set(inputStream, asymmetricChecker);
				inputStream=checkerIn;
			} else if (positionOfRandomInputStreamAfterDecoding!=null)
				positionOfRandomInputStreamAfterDecoding.set(EncryptionSignatureHashEncoder.headSize+dataLen);

			try {
				limitedRandomInputStream.init(inputStream, EncryptionSignatureHashEncoder.headSize, dataLen);
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
					assert outputStream!=null;
					res=cipherInputStream.transferTo(outputStream);
				}
				finally {
					cipherInputStream.close();
				}

			}
			else
			{
				if (sameInputOutputSource) {
					res = limitedRandomInputStream.length();
					if (inputStream!=originalInputStream) {
						nullRandomOutputStream.write(limitedRandomInputStream);
						nullRandomOutputStream.setLength(0);
					}
					else
						limitedRandomInputStream.seek(res);
					if (outputStream!=null)
						outputStream.seek(outputStream.currentPosition()+res);
				}
				else {
					outputStream.write(limitedRandomInputStream);
					res = limitedRandomInputStream.length();
				}

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
					symSign=inputStream.readBytesArray(false, SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE);
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash3=hash2=digest.digest();
				}
				if (asymmetricChecker!=null)
				{
					asymSign=inputStream.readBytesArray(false, ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE);
					digest.reset();
					digest.update(hash2);
					digest.update(asymSign);
					hash3=digest.digest();
				}
				byte[] hashToCheck=inputStream.readBytesArray(false, MessageDigestType.MAX_HASH_LENGTH);
				if (positionOfRandomInputStreamAfterDecoding!=null)
					positionOfRandomInputStreamAfterDecoding.set(originalInputStream.currentPosition());
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
				if (lenBuffer==EncryptionSignatureHashEncoder.headSizeMinusOne && associatedData!=null)
					symmetricChecker.update(associatedData, offAD, lenAD);
				if (!symmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			} else if (asymmetricChecker!=null)
			{
				asymmetricChecker.update(code);
				asymmetricChecker.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
				if (!asymmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			if (outputStream!=null) {
				long curPos = outputStream.currentPosition();
				if (curPos < maximumOutputLengthAfterEncoding && curPos > originalOutputLength)
					outputStream.setLength(curPos);
				outputStream.flush();
			}
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
	public Integrity checkHashAndSignatures(byte[] cipherText, int cipherTextOff, int cipherTextLen) throws IOException {
		EncryptionSignatureHashEncoder.checkLimits(cipherText, cipherTextOff, cipherTextLen);
		if (cipherTextLen<=0)
			throw new IllegalArgumentException();
		randomByteArrayInputStream.init(cipherText);
		limitedRandomInputStream2.init(randomByteArrayInputStream, cipherTextOff, cipherTextLen);
		withRandomInputStream(limitedRandomInputStream2);
		return checkHashAndSignatures();
	}

	public long getLastDataLength()
	{
		return dataLen;
	}

	public Integrity checkHashAndSignatures() throws IOException {


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
				limitedRandomInputStream.init(inputStream, dataPos, dataLen);
				digest.update(limitedRandomInputStream);
				digest.update(code);
				digest.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);


				byte[] hash = digest.digest();
				byte[] hash2=hash;
				byte[] hash3=hash;
				byte[] asymSign=null;
				if (symmetricChecker!=null)
				{
					byte[] symSign=inputStream.readBytesArray(false, SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE);
					digest.reset();
					symmetricChecker.init(symSign);
					if (associatedData!=null)
						symmetricChecker.update(associatedData, offAD, lenAD);
					symmetricChecker.update(hash);
					digest.update(hash);
					digest.update(symSign);
					hash3=hash2=digest.digest();
				}
				if (asymmetricChecker!=null)
				{
					asymSign=inputStream.readBytesArray(false, ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE);
					digest.reset();
					digest.update(hash2);
					digest.update(asymSign);
					hash3=digest.digest();
				}
				byte[] hashToCheck=inputStream.readBytesArray(false, MessageDigestType.MAX_HASH_LENGTH);
				if (!Arrays.equals(hash3, hashToCheck))
					return Integrity.FAIL;

				if (symmetricChecker!=null) {
					if (!symmetricChecker.verify())
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
				symmetricChecker.init(inputStream.readBytesArray(false, SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE));
				limitedRandomInputStream.init(inputStream, dataPos, dataLen);
				symmetricChecker.update(limitedRandomInputStream);
				symmetricChecker.update(code);
				symmetricChecker.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);
				if (associatedData!=null)
					symmetricChecker.update(associatedData, offAD, lenAD);
				if (symmetricChecker.verify())
					return Integrity.OK;
				else
					return Integrity.FAIL_AND_CANDIDATE_TO_BAN;

			}
			else
			{

				inputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(inputStream.readBytesArray(false, ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE));
				limitedRandomInputStream.init(inputStream, dataPos, dataLen);
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
	public Integrity checkHashAndPublicSignature(byte[] cipherText, int cipherTextOff, int cipherTextLen) throws IOException {
		EncryptionSignatureHashEncoder.checkLimits(cipherText, cipherTextOff, cipherTextLen);
		if (cipherTextLen<=0)
			throw new IllegalArgumentException();
		randomByteArrayInputStream.init(cipherText);
		limitedRandomInputStream2.init(randomByteArrayInputStream, cipherTextOff, cipherTextLen);
		withRandomInputStream(limitedRandomInputStream2);
		return checkHashAndPublicSignature();
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
				limitedRandomInputStream.init(inputStream, dataPos, dataLen);
				digest.update(limitedRandomInputStream);
				digest.update(code);
				digest.update(buffer, 0, EncryptionSignatureHashEncoder.headSizeMinusOne);


				byte[] hash = digest.digest();
				byte[] hash2=hash;
				byte[] hash3=hash;
				byte[] asymSign=null;
				if (symCheckOK)
				{
					byte[] symSign=inputStream.readBytesArray(false, SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE);
					digest.reset();
					digest.update(hash);
					digest.update(symSign);
					hash3=hash2=digest.digest();
				}
				if (asymmetricChecker!=null)
				{
					asymSign=inputStream.readBytesArray(false, ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE);
					digest.reset();
					digest.update(hash2);
					digest.update(asymSign);
					hash3=digest.digest();
				}
				byte[] hashToCheck=inputStream.readBytesArray(false, MessageDigestType.MAX_HASH_LENGTH);
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
				asymmetricChecker.init(inputStream.readBytesArray(false, ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE));
				limitedRandomInputStream.init(inputStream, dataPos, dataLen);
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
		checkCodeForDecode();
		return getMaximumOutputLengthImpl(inputStream.length());
	}
	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		if (encryptionProfileProvider!=null)
			throw new IOException("Cannot use this function when using encryption profile provider. You must set an input stream and call method getMaximumOutputLength");
		return getMaximumOutputLengthImpl(inputStreamLength);
	}
	private long getMaximumOutputLengthImpl(long inputStreamLength) throws IOException {
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
			res += symmetricChecker.getMacLengthBytes() + SerializationTools.getSizeCoderSize(SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE);
		}
		if(asymmetricChecker!=null) {
			res += asymmetricChecker.getMacLengthBytes() + SerializationTools.getSizeCoderSize(ASymmetricAuthenticatedSignatureType.MAX_ASYMMETRIC_SIGNATURE_SIZE);
		}
		if (digest!=null || (symmetricChecker!=null && asymmetricChecker!=null))
		{
			res+=SerializationTools.getSizeCoderSize(MessageDigestType.MAX_HASH_LENGTH);
			if (digest==null) {
				res+=EncryptionSignatureHashEncoder.defaultMessageType.getDigestLengthInBits() / 8;
			}
			else {
				res+=digest.getMessageDigestType().getDigestLengthInBits() / 8;
			}

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

		cleanCache();
		return this;
	}

	public EncryptionSignatureHashDecoder withoutSymmetricSignature()
	{
		symmetricChecker=null;
		cleanCache();
		return this;
	}
	public EncryptionSignatureHashDecoder withoutASymmetricSignature()
	{
		asymmetricChecker=null;
		cleanCache();
		return this;
	}

	public EncryptionSignatureHashDecoder withoutMessageDigest()
	{
		digest=null;
		cleanCache();
		return this;
	}

	void reloadCipher() throws IOException {
		if (encoder!=null)
			encoder.reloadCipher();

		if ((cipher!=null && ((cipher.getSecretKey()!=originalSecretKeyForEncryption && originalSecretKeyForEncryption!=null)
				|| (externalCounter==null && cipher.getBlockModeCounterBytes()!=0)
				|| (externalCounter!=null && cipher.getBlockModeCounterBytes()!=externalCounter.length))) ||
				(cipher==null && originalSecretKeyForEncryption!=null)) {
			cipher = EncryptionSignatureHashEncoder.reloadCipher(randomForCipher, originalSecretKeyForEncryption, 0, externalCounter);
			cleanCache();
		}
	}

	void cleanCache() {
		minimumInputSize=null;
		cipherInputStream=null;
	}
}
