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

import com.distrimind.util.io.SecuredObjectInputStream;
import com.distrimind.util.io.SecuredObjectOutputStream;
import com.distrimind.util.io.SerializationTools;

import java.io.IOException;


/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since MaDKitLanEdition 5.24.0
 */

public class WrappedIVsAndSecretKeys extends AbstractWrappedIVs<SymmetricEncryptionAlgorithm, WrappedIVAndSecretKey>{






	private WrappedIVAndSecretKey currentIVAndSecretKey=null;
	private transient KeyWrapperAlgorithm keyWrapperAlgorithm;
	private SymmetricKeyWrapperType symmetricKeyWrapperType;
	private int elementSizeInBytes;
	protected WrappedIVsAndSecretKeys() throws IOException {
		super();
		keyWrapperAlgorithm=null;
		symmetricKeyWrapperType=null;
		elementSizeInBytes=0;
	}
	protected WrappedIVsAndSecretKeys(SymmetricEncryptionAlgorithm algorithm) throws IOException {
		super(algorithm);
	}
	@Override
	public void setAlgorithm(IClientServer algorithm) throws IOException
	{
		if (algorithm instanceof SymmetricEncryptionAlgorithm)
		{
			this.setAlgorithmImpl((SymmetricEncryptionAlgorithm) algorithm);
		}
		else
			throw new IllegalArgumentException();
	}
	@Override
	protected void setAlgorithmImpl(SymmetricEncryptionAlgorithm algorithm) throws IOException {
		super.setAlgorithmImpl(algorithm);
		this.keyWrapperAlgorithm=new KeyWrapperAlgorithm(algorithm.getSymmetricKeyWrapperType(), algorithm.getSecretKey(), true);
		this.symmetricKeyWrapperType=algorithm.getSymmetricKeyWrapperType();
		for (AbstractWrappedIV<?, ?, ?> ea : data.values())
		{
			WrappedIVAndSecretKey e=(WrappedIVAndSecretKey)ea;
			if (algorithm.getSecretKey().getEncryptionAlgorithmType().getIVSizeBytes()!=e.getIv().length)
				throw new IOException();
		}
		elementSizeInBytes =IVSizeBytesWithoutExternalCounter+ keyWrapperAlgorithm.getWrappedSymmetricSecretKeySizeInBytes(algorithm.getSecretKey());
	}



	WrappedEncryptedSymmetricSecretKey wrapKey(SymmetricSecretKey secretKeyToEncrypt) throws IOException {
		return keyWrapperAlgorithm.wrap(getAlgorithm().getSecureRandomForIV(), secretKeyToEncrypt);
	}



	@Override
	WrappedIVAndSecretKey newEmptyWrappedIVInstance() throws IOException {
		return new WrappedIVAndSecretKey(this);
	}

	@Override
	protected WrappedIVAndSecretKey generateElement() throws IOException {
		return new WrappedIVAndSecretKey(this);
	}


	@Override
	protected void setCurrentIV(WrappedIVAndSecretKey res, byte[] externalCounter) throws IOException {
		super.setCurrentIV(res, externalCounter);
		this.currentIVAndSecretKey=res;
	}

	SymmetricSecretKey getCurrentSecretKey() throws IOException {
		return currentIVAndSecretKey==null?null:currentIVAndSecretKey.getDecryptedSecretKey();
	}

	@Override
	int getSerializedElementSizeInBytes()  {
		return elementSizeInBytes;
	}

	@Override
	protected Class<WrappedIVAndSecretKey> getDataClass() {
		return WrappedIVAndSecretKey.class;
	}


	KeyWrapperAlgorithm getKeyWrapperAlgorithm() {
		return keyWrapperAlgorithm;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		super.writeExternal(out);
		out.writeEnum(symmetricKeyWrapperType, false);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		super.readExternal(in);
		symmetricKeyWrapperType=in.readEnum(false);
		currentIVAndSecretKey=null;
	}

	@Override
	public int getInternalSerializedSize() {
		return super.getInternalSerializedSize()+ SerializationTools.getInternalSize(symmetricKeyWrapperType);
	}

	@Override
	public String toString() {
		return data.toString();
	}
}
