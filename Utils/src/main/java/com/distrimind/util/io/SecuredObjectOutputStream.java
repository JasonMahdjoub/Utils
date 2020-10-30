package com.distrimind.util.io;
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

import java.io.DataOutput;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Map;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.4.0
 */
@SuppressWarnings("NullableProblems")
public abstract class SecuredObjectOutputStream extends OutputStream implements DataOutput {

	private SerializationTools.ObjectResolver objectResolver=new SerializationTools.ObjectResolver();
	@Override
	public final void writeBoolean(boolean v) throws IOException {
		write(v ? 1 : 0);
	}

	@Override
	public final void writeByte(int v) throws IOException {
		write(v);
	}

	@Override
	public final void writeShort(int v) throws IOException {
		write((v >>> 8) & 0xFF);
		write((v) & 0xFF);

	}
	public final void writeUnsignedByte(int v) throws IOException {
		if (v<0)
			throw new IllegalArgumentException();
		write((byte)v);
	}
	public final void writeUnsignedShort(int v) throws IOException {
		if (v<0)
			throw new IllegalArgumentException();
		writeShort(v);
	}

	public final void writeUnsignedShortInt(int v) throws IOException {
		if (v<0)
			throw new IllegalArgumentException();
		write((v >>> 16) & 0xFF);
		write((v >>> 8) & 0xFF);
		write((v) & 0xFF);
	}

	@Override
	public final void writeChar(int v) throws IOException {
		write((v >>> 8) & 0xFF);
		write((v) & 0xFF);
	}

	@Override
	public final void writeInt(int v) throws IOException {
		write((v >>> 24) & 0xFF);
		write((v >>> 16) & 0xFF);
		write((v >>>  8) & 0xFF);
		write((v) & 0xFF);
	}

	private final byte[] writeBuffer = new byte[8];

	@Override
	public final void writeLong(long v) throws IOException {
		writeBuffer[0] = (byte)(v >>> 56);
		writeBuffer[1] = (byte)(v >>> 48);
		writeBuffer[2] = (byte)(v >>> 40);
		writeBuffer[3] = (byte)(v >>> 32);
		writeBuffer[4] = (byte)(v >>> 24);
		writeBuffer[5] = (byte)(v >>> 16);
		writeBuffer[6] = (byte)(v >>>  8);
		writeBuffer[7] = (byte)(v);
		write(writeBuffer, 0, 8);
	}


	@Override
	public final void writeFloat(float v) throws IOException {
		writeInt(Float.floatToIntBits(v));
	}

	@Override
	public final void writeDouble(double v) throws IOException {
		writeLong(Double.doubleToLongBits(v));
	}

	@Override
	public final void writeBytes(String s) throws IOException {
		int len = s.length();
		for (int i = 0 ; i < len ; i++) {
			write((byte)s.charAt(i));
		}
	}

	@Override
	public final void writeChars(String s) throws IOException {
		int len = s.length();
		for (int i = 0 ; i < len ; i++) {
			int v = s.charAt(i);
			write((v >>> 8) & 0xFF);
			write((v) & 0xFF);
		}
	}

	@Deprecated
	@Override
	public final void writeUTF(String str) throws IOException {
		throw new IOException(new IllegalAccessException());
	}

	public void writeCollection(Collection<?> collection, boolean nullAccepted, int maxSize) throws IOException {
		SerializationTools.writeCollection(this, collection, maxSize, nullAccepted);
	}
	public void writeMap(Map<?, ?> map, boolean nullAccepted, int maxSize) throws IOException {
		SerializationTools.writeMap(this, map, maxSize, nullAccepted);
	}

	public void writeString(String s, boolean nullAccepted, int maxSizeInBytes) throws IOException {
		SerializationTools.writeString(this, s, maxSizeInBytes, nullAccepted);
	}
	public void write2DBytesArray(byte[][] array, boolean nullAcceptedForLevel1, boolean nullAcceptedForLevel2, int maxLevel1SizeInByte, int maxLevel2SizeInByte) throws IOException {
		SerializationTools.writeBytes2D(this, array, maxLevel1SizeInByte, maxLevel2SizeInByte, nullAcceptedForLevel1, nullAcceptedForLevel2);
	}
	public void write2DBytesArray(byte[][] array, int offset, int len, boolean nullAcceptedForLevel1, boolean nullAcceptedForLevel2, int maxLevel1SizeInByte, int maxLevel2SizeInByte) throws IOException {
		SerializationTools.writeBytes2D(this, array, offset, len, maxLevel1SizeInByte, maxLevel2SizeInByte, nullAcceptedForLevel1, nullAcceptedForLevel2);
	}

	public void writeBytesArray(byte[] array, int offset, int len, boolean nullAccepted, int maxSizeInBytes) throws IOException {
		SerializationTools.writeBytes(this, array, offset, len, maxSizeInBytes, nullAccepted);
	}
	public void writeBytesArray(byte[] array, boolean nullAccepted, int maxSizeInBytes) throws IOException {
		SerializationTools.writeBytes(this, array, maxSizeInBytes, nullAccepted);
	}


	public void writeObject(Object object, boolean nullAccepted) throws IOException {
		writeObject(object, nullAccepted, -1);
	}
	public void writeObject(Object object, boolean nullAccepted, int maxSizeInBytes) throws IOException {
		SerializationTools.writeObject(this, object, maxSizeInBytes, nullAccepted);
	}
	public void writeClass(Class<?> clazz, boolean nullAccepted) throws IOException {
		writeClass(clazz, nullAccepted, Object.class);
	}
	public <CR> void writeClass(Class<? extends CR> clazz, boolean nullAccepted, Class<CR> rootClass) throws IOException {
		SerializationTools.writeClass(this, clazz, nullAccepted, rootClass);
	}

	public SerializationTools.ObjectResolver getObjectResolver() {
		return objectResolver;
	}

	public void setObjectResolver(SerializationTools.ObjectResolver objectResolver) {
		if (objectResolver==null)
			throw new NullPointerException();
		this.objectResolver = objectResolver;
	}

}
