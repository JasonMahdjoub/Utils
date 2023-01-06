package com.distrimind.util.crypto;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

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

import com.distrimind.util.Bits;
import com.distrimind.util.concurrent.PoolExecutor;
import com.distrimind.util.io.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.6
 * @since Utils 4.16.0
 */
@SuppressWarnings("UnusedReturnValue")
public class EncryptionSignatureHashEncoder {

	public static long getMaximumOutputLengthWhateverParameters(long inputSizeInBytes)
	{
		return SymmetricEncryptionType.getMaxOutputSizeInBytesAfterEncryption(inputSizeInBytes)+ SymmetricAuthenticatedSignatureType.MAX_SYMMETRIC_SIGNATURE_SIZE+HybridASymmetricAuthenticatedSignatureType.MAX_HYBRID_ASYMMETRIC_SIGNATURE_SIZE+MessageDigestType.MAX_HASH_LENGTH_IN_BYTES;
	}

	static final MessageDigestType defaultMessageType=MessageDigestType.SHA2_256;
	public static final int maxKeyIdentifierValue=(1<<16)-1;
	public static final int headSize=11;
	static final int headSizeMinusOne=headSize-1;
	static void checkLimits(byte[] data, int off, int len)
	{
		if (data==null)
			throw new NullPointerException();
		if (data.length==0)
			throw new IllegalArgumentException();
		if (off<0 || off>=data.length)
			throw new IllegalArgumentException("data.length="+data.length+", off="+off+", len"+len);
		if (len<=0)
			throw new IllegalArgumentException("data.length="+data.length+", off="+off+", len"+len);
		if (off+len>data.length)
			throw new IllegalArgumentException("data.length="+data.length+", off="+off+", len="+len);
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
			if (associatedData != null && (cipher == null || !cipher.getType().supportAssociatedData()) && symmetricSigner == null)
				throw new IllegalArgumentException("cipher="+cipher);
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
	SymmetricEncryptionAlgorithm cipher=null;
	private byte[] associatedData=null;
	private int offAD=0;
	private int lenAD=0;
	SymmetricSecretKey originalSecretKeyForEncryption=null;
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
	private RandomOutputStream cipherOutputStream;
	private byte[] externalCounter=null;
	private Byte code=null;
	short currentKeyID=-1;
	long currentKeyGeneration=0;
	private ROSForEncryption rosForEncryption=null;
	private boolean useProvider=false;
	long generatedIVCounter=0;
	private EncryptionSignatureHashDecoder decoder=null;
	private final NullRandomOutputStream nullOutputStream=new NullRandomOutputStream();
	private final RandomByteArrayInputStream randomByteArrayInputStream=new RandomByteArrayInputStream(emptyTab);
	private final LimitedRandomInputStream limitedRandomInputStream=new LimitedRandomInputStream(randomByteArrayInputStream, 0 );
	private final RandomByteArrayOutputStream randomByteArrayOutputStream=new RandomByteArrayOutputStream();
	private final LimitedRandomOutputStream randomOutputStream=new LimitedRandomOutputStream(randomByteArrayOutputStream, 0 );
	private AbstractSecureRandom cipherRandom=null;
	private static final byte[] emptyTab=new byte[0];
	private long lastInputStreamLength =-1, lastMaximumOutputLength;

	private PoolExecutor poolExecutor=null;
	private boolean useAsContinuousNetworkStream=false;
	/**
	 * Use as continuous network stream. Main secret key is constantly regenerated.
	 * @return the current encoder
	 */
	public EncryptionSignatureHashEncoder useAsContinuousNetworkStream()
	{
		if (useProvider)
			throw new IllegalArgumentException("Cannot use provider and use encoder as network stream");
		useAsContinuousNetworkStream=true;
		return this;
	}

	void incrementIVCounter() throws IOException {
		if (originalSecretKeyForEncryption==null)
			return;
		if (useProvider)
			return;
		++generatedIVCounter;
		if (generatedIVCounter>cipher.getType().getMaxIVGenerationWithOneSecretKey())
		{
			generatedIVCounter=0;
			++currentKeyGeneration;
			reloadCipher();
		}
	}

	static SymmetricEncryptionAlgorithm reloadCipher(AbstractSecureRandom random, SymmetricSecretKey secretKey, long currentKeyGeneration, byte[] externalCounter) throws IOException {
		try {
			SymmetricSecretKey sk = currentKeyGeneration==0?secretKey:secretKey.getHashedSecretKey(MessageDigestType.BC_FIPS_SHA3_256, currentKeyGeneration );
			byte sc=sk.getEncryptionAlgorithmType().getMaxCounterSizeInBytesUsedWithBlockMode();
			if (externalCounter==null)
				return new SymmetricEncryptionAlgorithm(random, sk);
			else
				return new SymmetricEncryptionAlgorithm(random, sk, (byte)(Math.min(externalCounter.length, sc)));
		} catch (NoSuchProviderException | NoSuchAlgorithmException e) {
			throw new IOException(e);
		}
	}

	public EncryptionSignatureHashEncoder withPoolExecutor(PoolExecutor poolExecutor)
	{
		if (poolExecutor==null)
			throw new NullPointerException();
		this.poolExecutor=poolExecutor;
		return this;
	}
	public EncryptionSignatureHashEncoder withoutPoolExecutor()
	{
		this.poolExecutor=null;
		return this;
	}

	void reloadCipher() throws IOException {
		if ((cipher!=null && ((cipher.getSecretKey()!=originalSecretKeyForEncryption && originalSecretKeyForEncryption!=null)
						|| (externalCounter==null && cipher.getBlockModeCounterBytes()!=0)
						|| (externalCounter!=null && cipher.getBlockModeCounterBytes()!=externalCounter.length))
						|| currentKeyGeneration!=0) ||
				(cipher==null && originalSecretKeyForEncryption!=null)) {
			cipher = reloadCipher(cipherRandom, originalSecretKeyForEncryption, currentKeyGeneration, externalCounter);
			cleanCache();
			if (decoder!=null) {
				decoder.cipher = reloadCipher(cipher.getSecureRandomForIV(), originalSecretKeyForEncryption, currentKeyGeneration, externalCounter);
				decoder.cleanCache();
			}
		}

	}

	public EncryptionSignatureHashEncoder connectWithDecoder(EncryptionSignatureHashDecoder decoder)
	{
		decoder.encoder=this;
		this.decoder=decoder;
		return this;
	}
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
	public EncryptionSignatureHashEncoder withExternalCounter(byte[] externalCounter) throws IOException {
		if (externalCounter==null)
			throw new NullPointerException();
		if (this.externalCounter!=externalCounter) {
			this.externalCounter = externalCounter;
			reloadCipher();
		}
		return this;
	}
	public EncryptionSignatureHashEncoder withoutExternalCounter() throws IOException {
		if (this.externalCounter!=null) {
			this.externalCounter = null;
			reloadCipher();
		}
		return this;
	}
	public EncryptionSignatureHashEncoder withEncryptionProfileProvider(AbstractSecureRandom random, EncryptionProfileProvider encryptionProfileProvider) throws IOException {
		return withEncryptionProfileProvider(random, encryptionProfileProvider, encryptionProfileProvider.getDefaultKeyID());
	}
	public EncryptionSignatureHashEncoder withEncryptionProfileProvider(AbstractSecureRandom random, EncryptionProfileProvider encryptionProfileProvider, short keyID) throws IOException {
		if (random==null)
			throw new NullPointerException();
		if (encryptionProfileProvider ==null)
			throw new NullPointerException();
		if (useAsContinuousNetworkStream)
			throw new IllegalArgumentException("Cannot use provider and use encoder as network stream");
		this.cipherRandom=random;
		this.originalSecretKeyForEncryption=encryptionProfileProvider.getSecretKeyForEncryption(keyID, false);
		this.cipher=null;
		this.useProvider=true;

		try {
			MessageDigestType t=encryptionProfileProvider.getMessageDigest(keyID, false);
			this.digest=t==null?null:t.getMessageDigestInstance();
			SymmetricSecretKey secretKey=encryptionProfileProvider.getSecretKeyForSignature(keyID, false);
			this.symmetricSigner=secretKey==null?null:new SymmetricAuthenticatedSignerAlgorithm(secretKey);
			IASymmetricPrivateKey privateKey=encryptionProfileProvider.getPrivateKeyForSignature(keyID);
			this.asymmetricSigner=privateKey==null?null:new ASymmetricAuthenticatedSignerAlgorithm(privateKey);

		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		code=null;
		this.currentKeyID=keyID;
		reloadCipher();
		cleanCache();
		return this;
	}

	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption) throws IOException {
		return withSymmetricSecretKeyForEncryption(random, symmetricSecretKeyForEncryption, (byte)0);
	}
	public EncryptionSignatureHashEncoder withSymmetricSecretKeyForEncryption(AbstractSecureRandom random, SymmetricSecretKey symmetricSecretKeyForEncryption, byte externalCounterLength) throws IOException {
		byte sc=symmetricSecretKeyForEncryption.getEncryptionAlgorithmType().getMaxCounterSizeInBytesUsedWithBlockMode();
		if (externalCounterLength<=0) {
			return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption));
		}
		else {
			return withCipher(new SymmetricEncryptionAlgorithm(random, symmetricSecretKeyForEncryption , (byte) Math.min(externalCounterLength, sc)));
		}
	}
	public EncryptionSignatureHashEncoder withCipher(SymmetricEncryptionAlgorithm cipher) throws IOException {
		if (cipher==null)
			throw new NullPointerException();
		this.originalSecretKeyForEncryption=cipher.getSecretKey();
		this.cipher=null;
		this.cipherRandom=cipher.getSecureRandomForIV();
		this.cipherOutputStream=null;
		this.currentKeyID=0;
		this.useProvider=false;
		if (cipher.getMaxExternalCounterLength()==0)
			externalCounter=null;
		reloadCipher();
		cleanCache();

		return this;
	}
	public int getExternalCounterLength()
	{
		return externalCounter==null?0:externalCounter.length;
	}
	public int getAssociatedDataLength()
	{
		return lenAD;
	}
	public EncryptionSignatureHashEncoder withoutAssociatedData()
	{
		if (this.associatedData!=null) {
			this.associatedData = null;
			this.offAD = 0;
			this.lenAD = 0;
			cleanCache();
		}
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
		if (this.associatedData!=associatedData || this.offAD!=offAD || this.lenAD!=lenAD) {
			checkLimits(associatedData, offAD, lenAD);
			this.associatedData=associatedData;
			this.offAD=offAD;
			this.lenAD=lenAD;

			cleanCache();
		}

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
		this.useProvider=false;
		cleanCache();
		return this;
	}
	public EncryptionSignatureHashEncoder withASymmetricSigner(ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner)
	{
		if (asymmetricSigner==null)
			throw new NullPointerException();
		this.asymmetricSigner=asymmetricSigner;
		this.useProvider=false;
		cleanCache();
		return this;
	}

	public IASymmetricPrivateKey getASymmetricPrivateKey()
	{
		return asymmetricSigner==null?null:asymmetricSigner.getPrivateKey();
	}

	public EncryptionSignatureHashEncoder withASymmetricPrivateKeyForSignature(IASymmetricPrivateKey privateKeyForSignature) throws IOException{
		if (privateKeyForSignature==null)
			throw new NullPointerException();
		if (!privateKeyForSignature.useAuthenticatedSignatureAlgorithm())
			throw new IllegalArgumentException();
		try {
			this.asymmetricSigner=new ASymmetricAuthenticatedSignerAlgorithm(privateKeyForSignature);
			this.useProvider=false;
			cleanCache();
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
		this.useProvider=false;
		cleanCache();
		return this;
	}
	public EncryptionSignatureHashEncoder withMessageDigestType(MessageDigestType messageDigestType) throws IOException {
		if (messageDigestType==null)
			throw new NullPointerException();
		try {
			this.digest=messageDigestType.getMessageDigestInstance();
			this.useProvider=false;
			cleanCache();
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
		return this;
	}

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
	public long encode(final RandomOutputStream originalOutputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();
		ROSForEncryption ros=getRandomOutputStream(originalOutputStream, inputStream.length(), false);
		try (ros) {
			inputStream.transferTo(ros);
			if (cipher != null && poolExecutor != null)
				inputStream.flush();
		}
		return ros.bytesWritten;
	}
	public void generatesOnlyHashAndSignatures(final RandomOutputStream originalOutputStream) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();

		try(RandomOutputStream ros=getRandomOutputStreamAndGeneratesOnlyHashAndSignatures(originalOutputStream))
		{
			inputStream.seek(0);
			inputStream.transferTo(ros);
		}
	}
	public int encode(byte[] data, int dataOff, int dataLen, byte[] cipherText, int cipherTextOff, int cipherTextLen) throws IOException {
		init(data, dataOff, dataLen, cipherText, cipherTextOff, cipherTextLen);
		return (int)encode(randomOutputStream);
	}

	private void init(byte[] data, int dataOff, int dataLen, byte[] cipherText, int cipherTextOff, int cipherTextLen) throws IOException {
		checkLimits(data, dataOff, dataLen);
		checkLimits(cipherText, cipherTextOff, cipherTextLen);
		if (dataLen<=0)
			throw new IllegalArgumentException();
		if (cipherTextLen<=0)
			throw new IllegalArgumentException();
		randomByteArrayInputStream.init(data);
		limitedRandomInputStream.init(randomByteArrayInputStream, dataOff, dataLen);
		withRandomInputStream(limitedRandomInputStream);
		randomByteArrayOutputStream.init(cipherText);
		randomOutputStream.init(randomByteArrayOutputStream, cipherTextOff, cipherTextLen);

	}


	public void generatesOnlyHashAndSignatures(byte[] data, int dataOff, int dataLen, byte[] hashSignatures, int hashSignaturesOff, int hashSignaturesLen) throws IOException {
		init(data, dataOff, dataLen, hashSignatures, hashSignaturesOff, hashSignaturesLen);
		generatesOnlyHashAndSignatures(randomOutputStream);
	}

	public int encodeWithSameInputAndOutputStreamSource(byte[] data, int dataOff, int dataLen) throws IOException {
		checkLimits(data, dataOff, dataLen);
		if (dataOff<headSize)
			throw new IllegalArgumentException("dataOff must be greater of equal to "+headSize+" in order to permit head encoding");

		randomByteArrayInputStream.init(data);
		limitedRandomInputStream.init(randomByteArrayInputStream, dataOff, dataLen);
		withRandomInputStream(limitedRandomInputStream);
		randomByteArrayOutputStream.init(data);
		randomOutputStream.init(randomByteArrayOutputStream, dataOff-EncryptionSignatureHashEncoder.headSize, data.length-dataOff+EncryptionSignatureHashEncoder.headSize);
		ROSForEncryption ros=getRandomOutputStream(randomOutputStream, dataLen, true);
		try (ros) {
			inputStream.transferTo(ros);
		}
		return (int)ros.bytesWritten;
	}
	public RandomOutputStream getRandomOutputStream(final RandomOutputStream originalOutputStream) throws IOException {
		return getRandomOutputStream(originalOutputStream, -1, false);
	}
	public AbstractSecureRandom getCipherSecureRandom()
	{
		return cipherRandom;
	}

	@SuppressWarnings("resource")
	public RandomOutputStream getRandomOutputStreamAndGeneratesOnlyHashAndSignatures(final RandomOutputStream originalOutputStream) throws IOException {
		if (EncryptionSignatureHashEncoder.this.cipher!=null)
			throw new IllegalArgumentException("Impossible to generate only signatures when using encryption");
		if (EncryptionSignatureHashEncoder.this.symmetricSigner==null && EncryptionSignatureHashEncoder.this.asymmetricSigner==null && EncryptionSignatureHashEncoder.this.digest==null)
			throw new IllegalArgumentException("You must use at least one symmetric or asymmetric signature, or one hash function !");

		originalOutputStream.ensureLength(headSize);
		AggregatedRandomOutputStreams aout=new AggregatedRandomOutputStreams(
				new RandomOutputStream[]{
						new LimitedRandomOutputStream(originalOutputStream, 0, headSize),
						new NullRandomOutputStream(),
						new LimitedRandomOutputStream(originalOutputStream, headSize)
				},
				new long[]{
						headSize,
						inputStream.length(),
						getMaximumOutputLengthWithOnlyHashAndSignatures()-headSize
				});
		return getRandomOutputStream(aout, inputStream.length(), false);
	}

	private class ROSForEncryption extends RandomOutputStream
	{
		private RandomOutputStream originalOutputStream;
		private long bytesWritten=0;
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
		private boolean sameInputOutputStream;


		private ROSForEncryption(final RandomOutputStream originalOutputStream, final long inputStreamLength, boolean sameInputOutputStream) throws IOException {
			init(originalOutputStream, inputStreamLength, sameInputOutputStream);
		}

		void init(final RandomOutputStream originalOutputStream, final long inputStreamLength, boolean sameInputOutputStream) throws IOException {
			if (originalOutputStream==null)
				throw new NullPointerException();
			if (inputStreamLength<0 && cipher!=null && cipher.getType().isAuthenticatedAlgorithm())
				throw new IllegalArgumentException("Cannot use RandomOutputStream for encryption when using authenticated algorithm");
			if (sameInputOutputStream && cipher!=null)
				throw new IOException("You must use a different input/output stream when using a cipher");
			if (sameInputOutputStream && inputStreamLength<0)
				throw new IllegalAccessError();

			this.sameInputOutputStream=sameInputOutputStream;
			this.originalOutputStream=originalOutputStream;
			this.inputStreamLength=inputStreamLength;
			this.closed=false;
			if (EncryptionSignatureHashEncoder.this.inputStream!=null)
				EncryptionSignatureHashEncoder.this.inputStream.seek(0);
			incrementIVCounter();
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
				if (sameInputOutputStream) {
					nullOutputStream.setLength(0);
					outputStream = nullOutputStream;
				}
				else
					outputStream = originalOutputStream;
				if (digest != null) {
					digest.reset();
					if (hashOut == null || (cipher!=null && poolExecutor!=null)!=hashOut.isMultiThreaded()) {
						if (cipher!=null && poolExecutor!=null)
							hashOut = new HashRandomOutputStream(outputStream, poolExecutor, false, digest);
						else
							hashOut = new HashRandomOutputStream(outputStream, digest);
					}
					else
						hashOut.set(outputStream, digest);
					outputStream = hashOut;
				} else if (symmetricSigner != null) {
					symmetricSigner.init();
					if (signerOut == null || (cipher!=null && poolExecutor!=null)!=signerOut.isMultiThreaded()) {
						if (cipher!=null && poolExecutor!=null) {
							signerOut = new SignerRandomOutputStream(outputStream, poolExecutor, false, symmetricSigner);
						}
						else
							signerOut = new SignerRandomOutputStream(outputStream, symmetricSigner);
					}
					else
						signerOut.set(outputStream, symmetricSigner);
					outputStream = signerOut;
				} else if (asymmetricSigner != null) {
					asymmetricSigner.init();
					if (signerOut == null || (cipher!=null && poolExecutor!=null)!=signerOut.isMultiThreaded())
						if (cipher!=null && poolExecutor!=null) {
							signerOut = new SignerRandomOutputStream(outputStream, poolExecutor, false, asymmetricSigner);
						}
						else
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
						limitedRandomOutputStream.init(outputStream, outputStream.currentPosition(), dataLen);
					else
						limitedRandomOutputStream.init(outputStream, outputStream.currentPosition());

					if (cipher.getType().supportAssociatedData()) {
						lenBuffer = computeAssociatedData(dataLen);
						buffer = bufferRef;
						if (cipherOutputStream == null)
							cipherOutputStream = cipher.getCipherOutputStreamForEncryption(limitedRandomOutputStream, false, buffer, 0, lenBuffer, externalCounter, useAsContinuousNetworkStream);
						else {
							AbstractEncryptionOutputAlgorithm.set(cipherOutputStream, limitedRandomOutputStream, null, externalCounter, buffer, 0, lenBuffer, false, useAsContinuousNetworkStream);
						}
					} else {
						if (cipherOutputStream == null)
							cipherOutputStream = cipher.getCipherOutputStreamForEncryption(limitedRandomOutputStream, false, null, 0, 0, externalCounter, useAsContinuousNetworkStream);
						else
							AbstractEncryptionOutputAlgorithm.set(cipherOutputStream, limitedRandomOutputStream, null, externalCounter, null, 0, 0, false, useAsContinuousNetworkStream);
					}
					dataOutputStream=cipherOutputStream;
				} else {
					originalOutputStream.writeLong(dataLen = inputStreamLength);
					limitedRandomOutputStream.init(outputStream, outputStream.currentPosition());
					dataOutputStream = limitedRandomOutputStream;

				}
				if (sameInputOutputStream)
					originalOutputStream.seek(originalOutputStream.currentPosition()+dataLen);
				bufferToInit=false;
				if (outputStream != originalOutputStream && buffer == null) {
					buffer = bufferRef;
					lenBuffer = headSizeMinusOne;
					Bits.putShort(buffer, 0, currentKeyID);
					if (dataLen>0) {
						Bits.putLong(buffer, 2, dataLen);
					}
					else
						bufferToInit = true;
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
			if (sameInputOutputStream && outputStream==originalOutputStream)
				dataOutputStream.seek(dataOutputStream.currentPosition()+len);
			else
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
			if (closed)
				return;

			if (cipher!=null) {
				dataOutputStream.close();
			}
			else
				dataOutputStream.flush();

			dataOutputStream=null;
			if (inputStreamLength<0)
			{
				dataLen=originalOutputStream.currentPosition()-headSize;
				if (bufferToInit)
					Bits.putLong(buffer, 2, dataLen);
			}




			if (digest!=null) {
				digest.update(code);
				digest.update(buffer, 0, headSizeMinusOne);
				WrappedHashedValue hash = digest.digest();

				if (symmetricSigner != null) {
					symmetricSigner.init();
					if (associatedData!=null)
						symmetricSigner.update(associatedData, offAD, lenAD);
					symmetricSigner.update(hash.getHashArray());
					byte[] signature = symmetricSigner.getSignature();
					digest.reset();
					digest.update(hash.getHashArray());
					digest.update(signature);
					hash=digest.digest();
					assert symmetricSigner.getSecretKey().getAuthenticatedSignatureAlgorithmType().getSignatureSizeInBytes()==signature.length;
					originalOutputStream.write(signature);
				}

				if (asymmetricSigner != null) {
					asymmetricSigner.init();
					asymmetricSigner.update(hash.getHashArray());
					byte[] signature = asymmetricSigner.getSignature();
					digest.reset();
					digest.update(hash.getHashArray());
					digest.update(signature);
					hash=digest.digest();
					originalOutputStream.writeBytesArray(signature, false, ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE);
				}
				originalOutputStream.write(hash.getHashArray());
			} else if (symmetricSigner!=null)
			{
				if (lenBuffer<=headSizeMinusOne)
					symmetricSigner.update(code);
				symmetricSigner.update(buffer, 0, lenBuffer);
				if (lenBuffer<=headSizeMinusOne && associatedData!=null)
					symmetricSigner.update(associatedData, offAD, lenAD);
				byte[] signature = symmetricSigner.getSignature();
				assert symmetricSigner.getSecretKey().getAuthenticatedSignatureAlgorithmType().getSignatureSizeInBytes()==signature.length;
				originalOutputStream.write(signature);
			} else if (asymmetricSigner!=null)
			{
				asymmetricSigner.update(code);
				asymmetricSigner.update(buffer, 0, headSizeMinusOne);
				byte[] signature = asymmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE);
			}
			this.bytesWritten=originalOutputStream.currentPosition();
			if (inputStreamLength<0) {
				originalOutputStream.seek(3);
				originalOutputStream.writeLong(dataLen);
				originalOutputStream.seek(this.bytesWritten);
			}
			if (!sameInputOutputStream && maximumOutputLengthAfterEncoding>0 && this.bytesWritten<maximumOutputLengthAfterEncoding && this.bytesWritten>originalOutputLength) {
				originalOutputStream.setLength(this.bytesWritten);
			}
			originalOutputStream.flush();
			if (cipher!=null && useAsContinuousNetworkStream && originalSecretKeyForEncryption!=null)
			{
				originalSecretKeyForEncryption=cipher.getSecretKey();
			}
			free();
			closed=true;
		}

		@Override
		public void write(int b) throws IOException {
			if (closed)
				throw new IOException("Stream closed");
			if (sameInputOutputStream && outputStream==originalOutputStream)
				dataOutputStream.seek(dataOutputStream.currentPosition()+1);
			else
				dataOutputStream.write(b);
		}
	}

	private ROSForEncryption getRandomOutputStream(final RandomOutputStream originalOutputStream, final long inputStreamLength, boolean sameInputOutputStream) throws IOException {
		if (rosForEncryption==null)
			rosForEncryption=new ROSForEncryption(originalOutputStream, inputStreamLength, sameInputOutputStream);
		else
			rosForEncryption.init(originalOutputStream, inputStreamLength, sameInputOutputStream);
		return rosForEncryption;
	}


	public boolean supportPartialHash()
	{
		return cipher==null || cipher.supportRandomEncryptionAndRandomDecryption();
	}

	public boolean checkPartialHash(SubStreamParameters subStreamParameters, SubStreamHashResult hashResultFromEncryptedStream) throws IOException {
		try {
			AbstractMessageDigest md = subStreamParameters.getMessageDigestType().getMessageDigestInstance();
			md.reset();
			long dataLen=inputStream.length();
			try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream(headSize)) {
				code = getCode();
				out.writeByte(code);
				out.writeShort(currentKeyID);

				if (cipher == null) {
					out.writeLong(dataLen);
					out.flush();
					RandomInputStream in = new AggregatedRandomInputStreams(new RandomByteArrayInputStream(out.getBytes()), inputStream);
					WrappedHashedValue hash = subStreamParameters.partialHash(in, md).digest();
					return hash.equals(hashResultFromEncryptedStream.getHash());
				} else {
					out.writeLong(dataLen = cipher.getOutputSizeAfterEncryption(dataLen));
					out.flush();

					if (cipher.getType().supportAssociatedData()) {
						lenAD = computeAssociatedData(dataLen);
						associatedData = bufferRef;
						offAD = 0;
					}
					return cipher.checkPartialHashWithNonEncryptedStream(out.getBytes(), hashResultFromEncryptedStream, subStreamParameters, inputStream, md);
				}
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
	void cleanCache()
	{
		minimumOutputSize=null;
		code=null;
		cipherOutputStream=null;
		lastInputStreamLength =-1;
	}

	public long getMaximumOutputLength() throws IOException {

		return getMaximumOutputLength(inputStream.length());
	}
	public long getMaximumOutputLengthWithOnlyHashAndSignatures()  {
		return getMinimumOutputSize();
	}
	public long getMaximumOutputLength(long inputStreamLength) throws IOException {
		if (inputStreamLength<=0)
			throw new IllegalArgumentException();
		if (inputStreamLength== lastInputStreamLength)
			return lastMaximumOutputLength;
		lastMaximumOutputLength =getMinimumOutputSize();
		if (cipher!=null) {
			lastMaximumOutputLength += cipher.getOutputSizeAfterEncryption(inputStreamLength);
		}
		else
			lastMaximumOutputLength +=inputStreamLength;
		lastInputStreamLength =inputStreamLength;
		return lastMaximumOutputLength;
	}
	long getMinimumOutputLengthAfterEncoding()
	{
		long res=headSize;

		if (symmetricSigner!=null) {
			res += symmetricSigner.getMacLengthBytes();
		}
		if(asymmetricSigner!=null) {
			res += asymmetricSigner.getMacLengthBytes() + SerializationTools.getSizeCoderSize(ASymmetricAuthenticatedSignatureType.MAX_SIZE_IN_BYTES_OF_ASYMMETRIC_SIGNATURE);
		}
		if (digest!=null || (asymmetricSigner!=null && symmetricSigner!=null))
		{
			if (digest==null) {
				res+=defaultMessageType.getDigestLengthInBits() / 8;
			}
			else {
				res+=digest.getMessageDigestType().getDigestLengthInBits() / 8;
			}

		}
		return res;
	}


	private void free() throws IOException {
		if (signerOut!=null)
			signerOut.set(nullRandomInputStream, symmetricSigner==null?asymmetricSigner:symmetricSigner);
		if (hashOut!=null)
			hashOut.set(nullRandomInputStream, digest==null?defaultMessageDigest:digest);
		limitedRandomOutputStream.init(nullRandomInputStream, 0);

		nullOutputStream.setLength(0);
		randomByteArrayInputStream.init(emptyTab);
		limitedRandomInputStream.init(randomByteArrayInputStream, 0);
		randomByteArrayOutputStream.init(emptyTab);
		randomOutputStream.init(randomByteArrayOutputStream, 0);
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
		originalSecretKeyForEncryption=null;
		cipherRandom=null;
		this.currentKeyID=0;
		cleanCache();
		return this;
	}

	public EncryptionSignatureHashEncoder withoutSymmetricSignature()
	{
		symmetricSigner=null;
		cleanCache();
		return this;
	}
	public EncryptionSignatureHashEncoder withoutASymmetricSignature()
	{
		asymmetricSigner=null;
		cleanCache();
		return this;
	}

	public EncryptionSignatureHashEncoder withoutMessageDigest()
	{
		digest=null;
		cleanCache();
		return this;
	}

}
