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

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.16.0
 */
public class EncryptionTools {
	private static final MessageDigestType defaultMessageType=MessageDigestType.SHA2_256;
	private static void checkLimits(byte[] data, int off, int len)
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


	private static void encryptAndSignImpl(RandomInputStream inputStream, RandomOutputStream originalOutputStream, SymmetricEncryptionAlgorithm cipher,byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);

		try {
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
				digest.update(lenBuffer);
				byte []hash = digest.digest();

				if (symmetricSigner != null) {
					byte[] signature = symmetricSigner.sign(hash);
					originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
				}

				if (asymmetricSigner != null) {
					byte[] signature = asymmetricSigner.sign(hash);
					originalOutputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
				}
			} else if (symmetricSigner!=null)
			{
				symmetricSigner.update(lenBuffer);
				byte[] signature = symmetricSigner.getSignature();
				originalOutputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
			} else if (asymmetricSigner!=null)
			{
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

	private void decryptAndCheckSignature(RandomInputStream originalInputStream, RandomOutputStream outputStream, SymmetricEncryptionAlgorithm cipher, byte[] associatedData, int offAD, int lenAD, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (originalInputStream==null)
			throw new NullPointerException();
		if (originalInputStream.length()<=0)
			throw new IllegalArgumentException();
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);

		try {
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
			if (digest!=null) {
				lenBuffer= new byte[8];
				Bits.putLong(lenBuffer, 0, dataLen);

			}

			if (digest!=null) {
				digest.update(lenBuffer);
				byte[] hash = digest.digest();

				if (symmetricChecker != null) {
					if (!symmetricChecker.verify(hash, inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes())))
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}

				if (asymmetricChecker != null) {
					if (!asymmetricChecker.verify(hash, inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes())))
						throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				}
			}
			else if (symmetricChecker!=null)
			{
				symmetricChecker.update(lenBuffer);
				if (!symmetricChecker.verify())
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			} else if (asymmetricChecker!=null)
			{
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

	private boolean checkheckSignature(final RandomInputStream inputStream, RandomOutputStream outputStream, SymmetricAuthenticatedSignatureCheckerAlgorithm symmetricChecker, ASymmetricAuthenticatedSignatureCheckerAlgorithm asymmetricChecker, AbstractMessageDigest digest) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();

		try {
			if (symmetricChecker==null && asymmetricChecker==null && digest==null)
				return true;
			if (symmetricChecker!=null && asymmetricChecker!=null && digest==null)
				digest=defaultMessageType.getMessageDigestInstance();

			long dataLen=inputStream.readLong();
			long dataPos=inputStream.currentPosition();

			if (digest!=null) {
				digest.reset();
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				digest.update(lis);
				byte[] lenBuffer = new byte[8];
				Bits.putLong(lenBuffer, 0, dataLen);
				digest.update(lenBuffer);


				byte[] hash = digest.digest();

				if (symmetricChecker != null) {
					if (!symmetricChecker.verify(hash, inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes())))
						return false;
				}

				if (asymmetricChecker != null) {
					return asymmetricChecker.verify(hash, inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				}
				return true;
			}
			else if (symmetricChecker!=null)
			{
				inputStream.seek(dataPos+dataLen);
				symmetricChecker.init(inputStream.readBytesArray(false, symmetricChecker.getMacLengthBytes()));
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				symmetricChecker.update(lis);
				return symmetricChecker.verify();

			}
			else
			{
				inputStream.seek(dataPos+dataLen);
				asymmetricChecker.init(inputStream.readBytesArray(false, asymmetricChecker.getMacLengthBytes()));
				LimitedRandomInputStream lis=new LimitedRandomInputStream(inputStream, dataPos, dataLen);
				asymmetricChecker.update(lis);
				return asymmetricChecker.verify();
			}


		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | SignatureException | InvalidParameterSpecException e)
		{
			return false;
		}
	}
}
