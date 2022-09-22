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
import java.util.HashMap;
import java.util.Map;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.24.0
 */
public abstract class AbstractWrappedIVs<C extends IClientServer, W extends AbstractWrappedIV<C, ? extends AbstractWrappedIVs<C,W>, W>> implements SecureExternalizable {

	private static final int MAX_ELEMENT_NUMBERS=Short.MAX_VALUE;
	protected Map<Long, W> data=new HashMap<>();
	protected long lastIndex=-1;
	private W currentWrappedIV;
	protected int IVSizeBytesWithoutExternalCounter;
	private C algorithm;


	static AbstractSecureRandom getDefaultSecureRandom() throws IOException {
		try {
			return SecureRandomType.DEFAULT_BC_FIPS_APPROVED.getInstance(System.nanoTime());
		} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new IOException(e);
		}
	}
	protected AbstractWrappedIVs() throws IOException {
		currentWrappedIV=null;
		IVSizeBytesWithoutExternalCounter=-1;
	}
	AbstractWrappedIVs(C algorithm) throws IOException {
		setAlgorithm(algorithm);
	}

	void setAlgorithm(C algorithm) throws IOException {
		if (algorithm==null)
			throw new NullPointerException();
		if (algorithm.getIVSizeBytesWithExternalCounter()<0)
			throw new IllegalArgumentException();
		if (algorithm.getBlockModeCounterBytes()<0)
			throw new IllegalArgumentException("The external counter size can't be lower than 0");
		this.algorithm=algorithm;
		if (currentWrappedIV!=null && currentWrappedIV.getIv().length!=algorithm.getIVSizeBytesWithExternalCounter())
		{
			throw new IllegalArgumentException();
		}
		this.IVSizeBytesWithoutExternalCounter=algorithm.getIVSizeBytesWithoutExternalCounter();

	}
	W getElement(long index)
	{
		return data.get(index);
	}

	void setCurrentIV(long index, RandomOutputStream out, byte[] externalCounter) throws IOException {
		setCurrentIV(getElement(index), externalCounter);
		currentWrappedIV.write(out);
	}
	protected void setCurrentIV(W res, byte[] externalCounter) throws IOException {
		res.setExternalCounter(externalCounter);
		this.currentWrappedIV=res;
	}


	abstract W newEmptyWrappedIVInstance() throws IOException;

	protected void checkMaxElementNumbers()  {
		if (data.size()>=MAX_ELEMENT_NUMBERS)
			throw new OutOfMemoryError();
	}
	final void pushNewElementAndSetCurrentIV(long index, RandomInputStream in, byte[] externalCounter) throws IOException {
		checkMaxElementNumbers();
		W res=newEmptyWrappedIVInstance();
		res.readFully(in);
		data.put(lastIndex=index, res);
		setCurrentIV(res, externalCounter);
	}
	protected abstract W generateElement() throws IOException;
	final void generateNewElement(long index, RandomOutputStream os, byte[] externalCounter) throws IOException {
		checkMaxElementNumbers();
		if (data.containsKey(index))
			throw new IllegalArgumentException(""+index);
		W res=generateElement();
		res.write(os);
		data.put(lastIndex=index, res);
		setCurrentIV(res, externalCounter);
	}
	final void pushNewElement(long index, RandomInputStream in) throws IOException {
		checkMaxElementNumbers();
		W res=newEmptyWrappedIVInstance();
		res.readFully(in);
		data.put(lastIndex=index, res);
	}
	int getIvSizeBytes()
	{
		return algorithm.getIVSizeBytesWithExternalCounter();
	}

	W getCurrentIV()
	{
		return currentWrappedIV;
	}

	abstract int getSerializedElementSizeInBytes() ;

	public int size()
	{
		return data.size();
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeMap(data, false, MAX_ELEMENT_NUMBERS);
		out.writeByte(getIvSizeBytes());
		out.writeByte(IVSizeBytesWithoutExternalCounter);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		data=in.readMap(false, MAX_ELEMENT_NUMBERS, Long.class, getDataClass());
		lastIndex=data.keySet().stream().max(Long::compare).orElse(-1L);
		int s=in.readByte();
		if (s<0 || s>WrappedIV.MAX_IV_LENGTH)
			throw new MessageExternalizationException(Integrity.FAIL);
		currentWrappedIV=null;
		IVSizeBytesWithoutExternalCounter=in.readByte();
		if (IVSizeBytesWithoutExternalCounter<=0 || IVSizeBytesWithoutExternalCounter>s)
			throw new MessageExternalizationException(Integrity.FAIL);
		data.values().forEach(v-> v.setContainer(AbstractWrappedIVs.this));

	}

	@Override
	public int getInternalSerializedSize() {
		return SerializationTools.getInternalSize(data, MAX_ELEMENT_NUMBERS)+2;
	}

	protected abstract Class<W> getDataClass();

	public C getAlgorithm() {
		return algorithm;
	}

}
