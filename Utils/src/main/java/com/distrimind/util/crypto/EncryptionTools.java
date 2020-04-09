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

import com.distrimind.util.io.*;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 4.16.0
 */
public class EncryptionTools {

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

	private static void encryptAndSignImpl(RandomInputStream inputStream, byte[] associatedData, int offAD, int lenAD, RandomOutputStream originalOutputStream, SymmetricEncryptionAlgorithm cipher, SymmetricAuthenticatedSignerAlgorithm symmetricSigner, ASymmetricAuthenticatedSignerAlgorithm asymmetricSigner, AbstractMessageDigest digest) throws IOException {
		if (inputStream==null)
			throw new NullPointerException();
		if (inputStream.length()<=0)
			throw new IllegalArgumentException();
		if (associatedData!=null)
			checkLimits(associatedData, offAD, lenAD);
		try {
			RandomOutputStream outputStream=originalOutputStream;
			long dataLen=-1;
			if (symmetricSigner != null) {
				symmetricSigner.init();
				outputStream=new SignerRandomOutputStream(outputStream, symmetricSigner);
			}
			if (asymmetricSigner != null) {
				asymmetricSigner.init();
				outputStream=new SignerRandomOutputStream(outputStream, asymmetricSigner);
			}
			if (digest != null) {
				digest.reset();
				outputStream=new HashRandomOutputStream(outputStream, digest);
			}
			long dataPos=outputStream.currentPosition();
			if (cipher != null) {

				originalOutputStream.writeLong(-1);
				if (associatedData!=null)
					cipher.encode(inputStream, associatedData, offAD, lenAD, outputStream);
				else
					cipher.encode(inputStream, outputStream);
				long newPos=outputStream.currentPosition();
				dataLen=newPos-dataPos;
			}
			else
			{
				originalOutputStream.writeLong(-1);
				outputStream.write(inputStream);
			}

			outputStream.seek(dataPos);
			outputStream.writeLong(dataLen);


			if (symmetricSigner != null) {
				byte[] signature=symmetricSigner.getSignature();
				outputStream.writeBytesArray(signature, false, symmetricSigner.getMacLengthBytes());
				//noinspection ConstantConditions
				outputStream=((SignerRandomOutputStream)outputStream).getOriginalRandomOutputStream();
			}

			if (asymmetricSigner != null) {
				byte[] signature=asymmetricSigner.getSignature();
				outputStream.writeBytesArray(signature, false, asymmetricSigner.getMacLengthBytes());
				//noinspection ConstantConditions
				outputStream=((SignerRandomOutputStream)outputStream).getOriginalRandomOutputStream();
			}

			if (digest != null) {
				byte[] hash=digest.digest();
				outputStream.writeBytesArray(hash, false, digest.getDigestLength());
			}
		}
		catch(InvalidKeyException | InvalidAlgorithmParameterException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | InvalidKeySpecException | NoSuchProviderException | IOException | SignatureException | ShortBufferException e)
		{
			throw new IOException(e);
		}
	}


}
