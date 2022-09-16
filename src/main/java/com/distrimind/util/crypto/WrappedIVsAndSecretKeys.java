package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

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
 * @version 1.0
 * @since MaDKitLanEdition 5.24.0
 */

class WrappedIVs extends AbstractWrappedIVs<WrappedIV> {
	protected WrappedIVs() throws IOException {
		super();
	}
	WrappedIVs(int ivSizeBytes, int blockModeCounterBytes, AbstractSecureRandom random) {
		super(ivSizeBytes, blockModeCounterBytes,random);
	}
	WrappedIVs(int ivSizeBytes, int blockModeCounterBytes) throws IOException {
		super(ivSizeBytes, blockModeCounterBytes);
	}


	@Override
	WrappedIV pushNewElement(long index, Object... params)
	{
		if (params.length>0)
			throw new IllegalArgumentException();
		checkMaxElementNumbers();
		WrappedIV res=new WrappedIV(WrappedIVs.this.getIvSizeBytes());
		data.put(lastIndex=index, res);
		return res;
	}

	@Override
	WrappedIV newEmptyWrappedIVInstance() {
		return new WrappedIV(getIvSizeBytes());
	}

	@Override
	int getSerializedElementSizeInBytes() {
		return IVSizeBytesWithoutExternalCounter;
	}

	@Override
	protected Class<WrappedIV> getDataClass() {
		return WrappedIV.class;
	}

	protected WrappedIV generateElement()
	{
		return new WrappedIV(WrappedIV.generateIV(getIvSizeBytes(), getSecureRandom()));
	}

}
class WrappedIVAndSecretKey extends WrappedIV
{
	private WrappedEncryptedSymmetricSecretKey encryptedSecretKey;
	private SymmetricSecretKey secretKey;
	private WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys;

	void setWrappedIVsAndSecretKeys(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys) {
		this.wrappedIVsAndSecretKeys = wrappedIVsAndSecretKeys;
	}

	protected WrappedIVAndSecretKey()
	{
		super();
		this.encryptedSecretKey=null;
		this.secretKey=null;
		this.wrappedIVsAndSecretKeys=null;
	}

	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys) throws IOException {
		super(generateIV(wrappedIVsAndSecretKeys.getIvSizeBytes(), wrappedIVsAndSecretKeys.getSecureRandom()));
		try {
			this.wrappedIVsAndSecretKeys=wrappedIVsAndSecretKeys;
			this.secretKey=wrappedIVsAndSecretKeys.getMainKey().getEncryptionAlgorithmType().getKeyGenerator(wrappedIVsAndSecretKeys.getSecureRandom(), wrappedIVsAndSecretKeys.getMainKey().getKeySizeBits()).generateKey();
			this.encryptedSecretKey=wrappedIVsAndSecretKeys.getKeyWrapperAlgorithm().wrap(wrappedIVsAndSecretKeys.getSecureRandom(), secretKey);
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}

	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys, byte[] iv) {
		super(iv);
		if (wrappedIVsAndSecretKeys.getIvSizeBytes()!=iv.length)
			throw new IllegalArgumentException();
		this.encryptedSecretKey=null;
		this.secretKey=null;
		this.wrappedIVsAndSecretKeys=wrappedIVsAndSecretKeys;
	}

	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys, byte[] iv, WrappedEncryptedSymmetricSecretKey encryptedSecretKey) {
		super(iv);
		if (wrappedIVsAndSecretKeys.getIvSizeBytes()!=iv.length)
			throw new IllegalArgumentException();
		if (encryptedSecretKey==null)
			throw new NullPointerException();
		this.encryptedSecretKey = encryptedSecretKey;
		this.secretKey=null;
		this.wrappedIVsAndSecretKeys=wrappedIVsAndSecretKeys;
	}
	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys, byte[] iv, SymmetricSecretKey secretKey) throws IOException {
		super(iv);
		if (wrappedIVsAndSecretKeys.getIvSizeBytes()!=iv.length)
			throw new IllegalArgumentException();
		if (secretKey==null)
			throw new NullPointerException();
		this.secretKey=secretKey;
		this.encryptedSecretKey=wrappedIVsAndSecretKeys.wrapKey(secretKey);
		this.wrappedIVsAndSecretKeys=wrappedIVsAndSecretKeys;
	}
	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys, SymmetricSecretKey secretKey) throws IOException {
		super(wrappedIVsAndSecretKeys.getIvSizeBytes());
		if (secretKey==null)
			throw new NullPointerException();
		this.secretKey=secretKey;
		this.encryptedSecretKey=wrappedIVsAndSecretKeys.wrapKey(secretKey);
		this.wrappedIVsAndSecretKeys=wrappedIVsAndSecretKeys;
	}
	WrappedIVAndSecretKey(WrappedIVsAndSecretKeys wrappedIVsAndSecretKeys, WrappedEncryptedSymmetricSecretKey encryptedSecretKey) {
		super(wrappedIVsAndSecretKeys.getIvSizeBytes());
		if (encryptedSecretKey==null)
			throw new NullPointerException();
		this.encryptedSecretKey = encryptedSecretKey;
		this.secretKey=null;
		this.wrappedIVsAndSecretKeys=wrappedIVsAndSecretKeys;
	}

	SymmetricSecretKey getDecryptedSecretKey() throws IOException {
		if (secretKey==null)
			secretKey=wrappedIVsAndSecretKeys.getKeyWrapperAlgorithm().unwrap(encryptedSecretKey);

		return secretKey;
	}

	WrappedEncryptedSymmetricSecretKey getEncryptedSecretKey() {
		return encryptedSecretKey;
	}

	@Override
	void readFully(RandomInputStream in) throws IOException {
		super.readFully(in);
		int s=wrappedIVsAndSecretKeys.getKeyWrapperAlgorithm().getWrappedSymmetricSecretKeySizeInBytes(wrappedIVsAndSecretKeys.getMainKey().getKeySizeBytes());
		encryptedSecretKey=new WrappedEncryptedSymmetricSecretKey(new byte[s]);
		in.readFully(encryptedSecretKey.getBytes());
	}
	@Override
	void write(RandomOutputStream out) throws IOException {
		super.write(out);
		assert encryptedSecretKey.getBytes().length==wrappedIVsAndSecretKeys.getKeyWrapperAlgorithm().getWrappedSymmetricSecretKeySizeInBytes(wrappedIVsAndSecretKeys.getMainKey().getKeySizeBytes());
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
}
public class WrappedIVsAndSecretKeys extends AbstractWrappedIVs<WrappedIVAndSecretKey>{



	static final SymmetricKeyWrapperType DEFAULT_SYMMETRIC_KEY_WRAPPER_TYPE=SymmetricKeyWrapperType.BC_FIPS_AES_WITH_PADDING;

	private KeyWrapperAlgorithm keyWrapperAlgorithm;

	private SymmetricSecretKey mainKey;
	private WrappedIVAndSecretKey currentIVAndSecretKey=null;
	private SymmetricKeyWrapperType symmetricKeyWrapperType;
	private int elementSizeInBytes =0;
	protected WrappedIVsAndSecretKeys() throws IOException {
		super();

		mainKey=null;
		symmetricKeyWrapperType=null;
	}
	WrappedIVsAndSecretKeys(int ivSizeBytes, int blockModeCounterBytes, SymmetricSecretKey mainKey, AbstractSecureRandom secureRandom, SymmetricKeyWrapperType symmetricKeyWrapperType) {
		super(ivSizeBytes, blockModeCounterBytes, secureRandom);


		try {
			setMainKey(mainKey, symmetricKeyWrapperType);
		} catch (IOException e) {
			throw new IllegalArgumentException(e);
		}
	}

	public void setMainKey(SymmetricSecretKey mainKey, AbstractSecureRandom secureRandom) throws IOException {
		setMainKey(mainKey, symmetricKeyWrapperType);
		setSecureRandom(secureRandom);
	}

	void setMainKey(SymmetricSecretKey mainKey, SymmetricKeyWrapperType symmetricKeyWrapperType) throws IOException {
		if (mainKey==null)
			throw new NullPointerException();
		if (symmetricKeyWrapperType==null)
			throw new NullPointerException();
		this.mainKey=mainKey;
		this.keyWrapperAlgorithm=new KeyWrapperAlgorithm(symmetricKeyWrapperType, mainKey);
		this.symmetricKeyWrapperType=symmetricKeyWrapperType;
		for (WrappedIVAndSecretKey e : data.values())
		{
			if (mainKey.getEncryptionAlgorithmType().getIVSizeBytes()!=e.getIv().length)
				throw new IOException();
		}
		elementSizeInBytes =IVSizeBytesWithoutExternalCounter+ keyWrapperAlgorithm.getWrappedSymmetricSecretKeySizeInBytes(mainKey.getKeySizeBytes());
	}
	WrappedIVsAndSecretKeys(int ivSizeBytes, int blockModeCounterBytes, SymmetricSecretKey mainKey, AbstractSecureRandom secureRandom) {
		this(ivSizeBytes, blockModeCounterBytes, mainKey, secureRandom, DEFAULT_SYMMETRIC_KEY_WRAPPER_TYPE);
	}

	WrappedIVsAndSecretKeys(int ivSizeBytes, int blockModeCounterBytes, SymmetricSecretKey mainKey) throws IOException {
		this(ivSizeBytes, blockModeCounterBytes, mainKey, getDefaultSecureRandom());
	}

	WrappedEncryptedSymmetricSecretKey wrapKey(SymmetricSecretKey secretKeyToEncrypt) throws IOException {
		return keyWrapperAlgorithm.wrap(getSecureRandom(), secretKeyToEncrypt);
	}



	@Override
	WrappedIVAndSecretKey pushNewElement(long index, Object... params) throws IOException {
		checkMaxElementNumbers();
		WrappedIVAndSecretKey res;
		if (params.length==0)
			res=new WrappedIVAndSecretKey();
		else if (params.length==1) {
			if (params[0] instanceof WrappedEncryptedSymmetricSecretKey)
				res = new WrappedIVAndSecretKey(this, (WrappedEncryptedSymmetricSecretKey) params[0]);
			else if (params[0] instanceof SymmetricSecretKey)
				res = new WrappedIVAndSecretKey(this, (SymmetricSecretKey) params[0]);
			else
				throw new IllegalArgumentException();
		}
		else
			throw new IllegalArgumentException();
		data.put(lastIndex=index, res);
		this.currentIVAndSecretKey=res;
		return res;
	}

	@Override
	WrappedIVAndSecretKey newEmptyWrappedIVInstance() {
		return new WrappedIVAndSecretKey();
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
	int getSerializedElementSizeInBytes() throws IOException {
		return elementSizeInBytes;
	}

	@Override
	protected Class<WrappedIVAndSecretKey> getDataClass() {
		return WrappedIVAndSecretKey.class;
	}

	public SymmetricSecretKey getMainKey() {
		return mainKey;
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
		keyWrapperAlgorithm=null;
		mainKey=null;
		currentIVAndSecretKey=null;

		for (WrappedIVAndSecretKey e : data.values())
			e.setWrappedIVsAndSecretKeys(this);
	}

	@Override
	public int getInternalSerializedSize() {
		return super.getInternalSerializedSize()+ SerializationTools.getInternalSize(symmetricKeyWrapperType);
	}


}
