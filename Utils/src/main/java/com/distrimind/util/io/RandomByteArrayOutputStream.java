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

import com.distrimind.bouncycastle.util.Arrays;

import java.io.IOException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.27.0
 */
public class RandomByteArrayOutputStream extends RandomOutputStream {
	byte[] bytes;
	private int current_pos;
	int length;
	static final int MAX_ARRAY_SIZE = Integer.MAX_VALUE - 8;

	public RandomByteArrayOutputStream(byte[] _bytes) {
		init(_bytes);
	}

	public void init(byte[] _bytes)
	{
		if (_bytes==null)
			throw new NullPointerException();
		bytes = _bytes;
		current_pos = 0;
		length=_bytes.length;
	}

	public RandomByteArrayOutputStream() {
		bytes = new byte[0];
		current_pos = 0;
		length=0;
	}

	public RandomByteArrayOutputStream(int length) {
		if (length < 0)
			throw new IllegalArgumentException("length must can't be negative");
		bytes = new byte[length];
		current_pos = 0;
		this.length=length;
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public void write(int b) throws IOException {
		if (current_pos == -1)
			throw new IOException("The current RandomByteArrayOutputStream is closed !");
		ensureAdditionalLength(1);
		bytes[current_pos++] = (byte) b;
		length=Math.max(length, current_pos);
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public void write(byte[] _bytes) throws IOException {
		write(_bytes, 0, _bytes.length);
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public void write(byte[] _bytes, int _offset, int _length) throws IOException {
		if (current_pos == -1)
			throw new IOException("The current RandomByteArrayOutputStream is closed !");
		RandomInputStream.checkLimits(_bytes, _offset, _length);
		ensureAdditionalLength(_length);
		System.arraycopy(_bytes, _offset, bytes, current_pos, _length);
		current_pos += _length;
		length=Math.max(length, current_pos);
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public long length() throws IOException {
		if (current_pos == -1)
			throw new IOException("The current RandomByteArrayOutputStream is closed !");
		return length;
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public void setLength(long _length) throws IOException {
		if (current_pos == -1)
			throw new IOException("The current RandomByteArrayOutputStream is closed !");

		if (_length < 0 || _length > MAX_ARRAY_SIZE)
			throw new IllegalArgumentException("invalid length : " + _length);
		int length = (int) _length;
		if (bytes.length<length || bytes.length>_length*3) {
			byte[] prev = bytes;
			bytes = new byte[length];
			if (this.length != 0) {
				System.arraycopy(prev, 0, bytes, 0, Math.min(this.length, length));
			}
		}

		this.length = length;
		if (current_pos>length)
			current_pos=length;
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public void seek(long _pos) throws IOException {
		if (current_pos == -1)
			throw new IOException("The current RandomByteArrayOutputStream is closed !");
		if (_pos<0 || _pos>length())
			throw new IllegalArgumentException(""+_pos+" is not in [0,"+length()+"]");

		current_pos = (int) _pos;
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public long currentPosition() {
		return current_pos;
	}

	@Override
	public boolean isClosed() {
		return current_pos==-1;
	}

	@Override
	protected RandomByteArrayInputStream getRandomInputStreamImpl() {
		return new RandomByteArrayInputStream(this);
	}

	@Override
	public void flush() {

	}

	public byte[] getBytes() {
		return Arrays.copyOf(bytes, length);
	}

	/**
	 * {@inheritDoc}
	 * 
	 */
	@Override
	public void close() {
		current_pos = -1;
	}

	private void ensureAdditionalLength(int l) throws IOException {
		l=this.current_pos+l;
		if (l > MAX_ARRAY_SIZE)
			throw new IOException("invalid length : " + length);

		if (bytes.length<l) {
			int length = (int) Math.min(2L*l, MAX_ARRAY_SIZE);
			byte[] prev = bytes;
			bytes = new byte[length];
			if (this.length != 0) {
				System.arraycopy(prev, 0, bytes, 0, this.length);
			}
		}
	}

}
