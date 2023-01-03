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

import com.distrimind.util.io.*;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since MaDKitLanEdition 5.24.0
 */
public class WrappedIVAndSecretKey extends AbstractWrappedIV<SymmetricEncryptionAlgorithm, WrappedIVsAndSecretKeys, WrappedIVAndSecretKey>
{
	private WrappedEncryptedSymmetricSecretKey encryptedSecretKey;
	private SymmetricSecretKey secretKey;
	@Override
	public String toString() {
		return secretKey.toString();
	}

	@SuppressWarnings("unused")
	protected WrappedIVAndSecretKey()
	{
		super();
		this.encryptedSecretKey=null;
		this.secretKey=null;
	}


	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys) throws IOException {
		super(generateIV(wrappedIVsAndSecretKeys.getIvSizeBytes(), wrappedIVsAndSecretKeys), wrappedIVsAndSecretKeys);

		try {
			this.secretKey=container.getAlgorithm().getSecretKey().getEncryptionAlgorithmType().getKeyGenerator(wrappedIVsAndSecretKeys.getAlgorithm().getSecureRandomForKeyGeneration(), wrappedIVsAndSecretKeys.getAlgorithm().getSecretKey().getKeySizeBits()).generateKey();
			this.encryptedSecretKey=wrappedIVsAndSecretKeys.wrapKey(secretKey);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}


	SymmetricSecretKey getDecryptedSecretKey() throws IOException {
		if (secretKey==null)
			secretKey=container.getKeyWrapperAlgorithm().unwrap(encryptedSecretKey);

		return secretKey;
	}


	@Override
	void readFully(RandomInputStream in) throws IOException {
		super.readFully(in);
		int s=container.getKeyWrapperAlgorithm().getWrappedSymmetricSecretKeySizeInBytes(container.getAlgorithm().getSecretKey());
		encryptedSecretKey=new WrappedEncryptedSymmetricSecretKey(new byte[s]);
		in.readFully(encryptedSecretKey.getBytes());
		secretKey=null;
	}
	@Override
	void write(RandomOutputStream out) throws IOException {
		super.write(out);
		//assert encryptedSecretKey.getBytes().length==wrappedIVsAndSecretKeys.getKeyWrapperAlgorithm().getWrappedSymmetricSecretKeySizeInBytes(wrappedIVsAndSecretKeys.getMainKey());
		out.write(encryptedSecretKey.getBytes(), 0, encryptedSecretKey.getBytes().length);
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		super.writeExternal(out);
		out.writeWrappedData(encryptedSecretKey, false);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		super.readExternal(in);
		encryptedSecretKey=in.readWrappedEncryptedSymmetricSecretKey(false);
	}
	@Override
	public int getInternalSerializedSize() {
		return super.getInternalSerializedSize()+ SerializationTools.getInternalSize(encryptedSecretKey);
	}

}
