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
import com.distrimind.util.io.*;

import java.io.IOException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.24.0
 */
abstract class AbstractWrappedIV<C extends IClientServer, T extends AbstractWrappedIVs<C, W>, W extends AbstractWrappedIV<C, T, W>> implements SecureExternalizable
{
	static final int MAX_IV_LENGTH=64;
	private byte[] iv;
	protected transient T container;
	private int ivLengthWithoutExternalCounter;
	private int originalCounter;
	private int counterPos;


	protected AbstractWrappedIV()
	{
		iv=null;
		container=null;
		ivLengthWithoutExternalCounter=0;
	}

	AbstractWrappedIV(T container)
	{
		setContainer(container);

	}
	AbstractWrappedIV(byte[] iv, T  container)
	{
		if (iv==null)
			throw new NullPointerException();
		if (iv.length!=container.getIvSizeBytes())
			throw new IllegalArgumentException();

		this.iv=iv;
		counterPos=iv.length-4;
		setContainer(container);
	}
	static byte[] generateIV(int ivSizeInBytes, AbstractWrappedIVs<?,?>  container)
	{
		byte[] iv=new byte[ivSizeInBytes];
		container.getAlgorithm().getSecureRandomForIV().nextBytes(iv);
		return iv;
	}


	byte[] getIv() {
		return iv;
	}
	void readFully(RandomInputStream in) throws IOException {
		in.readFully(iv, 0, this.ivLengthWithoutExternalCounter=container.getAlgorithm().getIVSizeBytesWithoutExternalCounter());
	}
	void write(RandomOutputStream out) throws IOException {
		out.write(iv, 0, container.getAlgorithm().getIVSizeBytesWithoutExternalCounter());
	}

	@Override
	public int getInternalSerializedSize() {
		return 2+ivLengthWithoutExternalCounter;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeUnsignedInt8Bits(iv.length);
		out.writeUnsignedInt8Bits(ivLengthWithoutExternalCounter);
		out.write(iv, 0, ivLengthWithoutExternalCounter);
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException, ClassNotFoundException {
		int s=in.readUnsignedInt8Bits();
		if (s<=0 || s>MAX_IV_LENGTH)
			throw new MessageExternalizationException(Integrity.FAIL);
		ivLengthWithoutExternalCounter=in.readUnsignedInt8Bits();
		if (ivLengthWithoutExternalCounter<=0 || ivLengthWithoutExternalCounter>s)
			throw new MessageExternalizationException(Integrity.FAIL);
		iv=new byte[s];
		in.readFully(iv, 0, ivLengthWithoutExternalCounter);
	}
	@SuppressWarnings("unchecked")
	<R extends AbstractWrappedIVs<C, W>> void setContainer(R container)
	{
		if (container==null)
			throw new NullPointerException();
		this.ivLengthWithoutExternalCounter=container.getAlgorithm().getIVSizeBytesWithoutExternalCounter();
		if (container.getIvSizeBytes()>MAX_IV_LENGTH)
			throw new IllegalArgumentException();
		if (this.ivLengthWithoutExternalCounter<=0 || this.ivLengthWithoutExternalCounter>container.getIvSizeBytes())
			throw new IllegalArgumentException();
		this.container=(T)container;
		if (iv==null) {
			iv = new byte[container.getIvSizeBytes()];
			counterPos=iv.length-4;
		}
		else if (this.iv.length!=container.getIvSizeBytes())
			throw new IllegalArgumentException();


	}

	void setExternalCounter(byte[] externalCounter) {
		if (externalCounter!=null)
		{
			System.arraycopy(externalCounter, 0, iv, this.ivLengthWithoutExternalCounter, externalCounter.length);
			originalCounter= Bits.getInt(iv, counterPos);
		}
	}
	void setCounter(int counter)
	{
		Bits.putInt(iv, counterPos, originalCounter + counter);
	}
}
public class WrappedIV extends AbstractWrappedIV<IClientServer, WrappedIVs, WrappedIV>
{
	protected WrappedIV() {
	}

	public WrappedIV(WrappedIVs container) {
		super(container);
	}

	public WrappedIV(byte[] iv, WrappedIVs container) {
		super(iv, container);
	}
}