/*
 * MadKitLanEdition (created by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr)) Copyright (c)
 * 2015 is a fork of MadKit and MadKitGroupExtension. 
 * 
 * Copyright or © or Copr. Jason Mahdjoub, Fabien Michel, Olivier Gutknecht, Jacques Ferber (1997)
 * 
 * jason.mahdjoub@distri-mind.fr
 * fmichel@lirmm.fr
 * olg@no-distance.net
 * ferber@lirmm.fr
 * 
 * This software is a computer program whose purpose is to
 * provide a lightweight Java library for designing and simulating Multi-Agent Systems (MAS).
 * This software is governed by the CeCILL-C license under French law and
 * abiding by the rules of distribution of free software.  You can  use,
 * modify and/ or redistribute the software under the terms of the CeCILL-C
 * license as circulated by CEA, CNRS and INRIA at the following URL
 * "http://www.cecill.info".
 * As a counterpart to the access to the source code and  rights to copy,
 * modify and redistribute granted by the license, users are provided only
 * with a limited warranty  and the software's author,  the holder of the
 * economic rights,  and the successive licensors  have only  limited
 * liability.
 * 
 * In this respect, the user's attention is drawn to the risks associated
 * with loading,  using,  modifying and/or developing or reproducing the
 * software by the user in light of its specific status of free software,
 * that may mean  that it is complicated to manipulate,  and  that  also
 * therefore means  that it is reserved for developers  and  experienced
 * professionals having in-depth computer knowledge. Users are therefore
 * encouraged to load and test the software's suitability as regards their
 * requirements in conditions enabling the security of their systems and/or
 * data to be ensured and,  more generally, to use and operate it in the
 * same conditions as regards security.
 * The fact that you are presently reading this means that you have had
 * knowledge of the CeCILL-C license and that you accept its terms.
 */
package com.distrimind.util.io;

import java.io.DataOutput;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.27.0
 */
public abstract class RandomOutputStream extends OutputStream implements AutoCloseable, DataOutput {
	/*
	 * public int write(byte[] _bytes) throws OutputStreamException; public int
	 * write(byte[] _bytes, int offset, int length) throws OutputStreamException;
	 */
	/**
	 * Returns the length of this stream.
	 *
	 * @return the length of this stream, measured in bytes.
	 * @exception IOException
	 *                if an I/O error occurs.
	 */
	public abstract long length() throws IOException;

	/**
	 * Sets the length of this stream.
	 *
	 * <p>
	 * If the present length of the stream source as returned by the
	 * <code>length</code> method is greater than the <code>newLength</code>
	 * argument then the stream source will be truncated. In this case, if the
	 * stream source offset as returned by the <code>currentPosition</code> method
	 * is greater than <code>newLength</code> then after this method returns the
	 * offset will be equal to <code>newLength</code>.
	 *
	 * <p>
	 * If the present length of the stream source as returned by the
	 * <code>length</code> method is smaller than the <code>newLength</code>
	 * argument then the stream source will be extended. In this case, the contents
	 * of the extended portion of the file are not defined.
	 *
	 * @param newLength
	 *            The desired length of the stream source
	 * @exception IOException
	 *                If an I/O error occurs
	 * @since 1.2
	 */
	public abstract void setLength(long newLength) throws IOException;

	/**
	 * Sets the stream source -pointer offset, measured from the beginning of this
	 * stream, at which the next read or write occurs. The offset may be set beyond
	 * the end of the stream source. Setting the offset beyond the end of the stream
	 * source does not change the stream source length. The stream source length
	 * will change only by writing after the offset has been set beyond the end of
	 * the stream source.
	 *
	 * @param _pos
	 *            the offset position, measured in bytes from the beginning of the
	 *            stream, at which to set the stream source pointer.
	 * @exception IOException
	 *                if <code>pos</code> is less than <code>0</code> or if an I/O
	 *                error occurs.
	 */
	public abstract void seek(long _pos) throws IOException;

	/**
	 * Returns the current position in this stream.
	 *
	 * @return the offset from the beginning of the stream, in bytes, at which the
	 *         next read or write occurs.
	 * @exception IOException
	 *                if an I/O error occurs.
	 */
	public abstract long currentPosition() throws IOException;

	/**
	 * Change the length of the stream source if the current length is lower than
	 * the wanted length.
	 * 
	 * @param length
	 *            the wanted length
	 * @throws IOException
	 *             if a problem occurs
	 */
	public void ensureLength(long length) throws IOException {
		if (length() < length) {
			setLength(length);
		}
	}

	public abstract boolean isClosed();

	private RandomInputStream randomInputStream;

	public final RandomInputStream getRandomInputStream() throws IOException {
		if (isClosed())
			throw new IOException();
		if (randomInputStream==null)
			randomInputStream=getRandomInputStreamImpl();
		return randomInputStream;
	}

	protected abstract RandomInputStream getRandomInputStreamImpl() throws IOException;

	public RandomInputStream getUnbufferedRandomInputStream() throws IOException {
		return getRandomInputStream();
	}

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
		writeUnsignedShort(v);
	}

	public final void writeUnsignedShort(int v) throws IOException {
		if (v<0)
			throw new IllegalArgumentException();
		write((v >>> 8) & 0xFF);
		write((v) & 0xFF);
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

	private byte[] writeBuffer = new byte[8];

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

	@Override
	public final void writeUTF(String str) throws IOException {
		new DataOutputStream(this).writeUTF(str);
	}



}
