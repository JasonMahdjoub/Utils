/*
 * MadKitLanEdition (created by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr)) Copyright (c)
 * 2015 is a fork of MadKit and MadKitGroupExtension. 
 * 
 * Copyright or © or Corp. Jason Mahdjoub, Fabien Michel, Olivier Gutknecht, Jacques Ferber (1997)
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

import com.distrimind.util.Cleanable;

import java.io.*;

import java.nio.file.Path;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.27.0
 */
@SuppressWarnings("NullableProblems")
public class RandomFileInputStream extends RandomInputStream implements Cleanable {
	private final static class Finalizer extends Cleanable.Cleaner
	{
		private final RandomAccessFile raf;
		private boolean closed=false;

		private Finalizer(Cleanable cleanable, RandomAccessFile raf) {
			super(cleanable);
			this.raf = raf;
		}

		@Override
		protected void performCleanup() {
			if (!closed) {
				try {
					close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
		}

		private void close() throws IOException {
			closed=true;
			raf.close();
		}
	}
	private final Finalizer finalizer;

	private long position;
	private final boolean checkPosition;


	public RandomFileInputStream(Path p) throws FileNotFoundException {
		this(p.toFile());
	}

	public RandomFileInputStream(File f) throws FileNotFoundException {
		finalizer=new Finalizer(this, new RandomAccessFile(f, "r"));
		this.position=0;
		this.checkPosition=false;
	}

	RandomFileInputStream(RandomAccessFile raf)
	{
		if (raf==null)
			throw new NullPointerException();
		finalizer=new Finalizer(this, raf);
		this.position=0;
		this.checkPosition=true;
	}

	private void checkPosition() throws IOException {
		if (checkPosition && position!=finalizer.raf.getFilePointer())
			finalizer.raf.seek(position);
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int read() throws IOException {
		checkPosition();
		int res=finalizer.raf.read();
		if (res!=-1)
			++position;
		return res;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int read(byte[] _bytes) throws IOException {
		checkPosition();
		int res= finalizer.raf.read(_bytes);
		position+=res;
		return res;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public int read(byte[] _bytes, int _offset, int _length) throws IOException {

		checkLimits(_bytes, _offset, _length);
		checkPosition();
		int res= finalizer.raf.read(_bytes, _offset, _length);
		position+=res;
		return res;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long length() throws IOException {
		return finalizer.raf.length();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void seek(long _pos) throws IOException {
		if (_pos<0)
			throw new IllegalArgumentException();
		if (_pos > length())
			throw new IOException("The position must be lower that the size of the file");
		position=_pos;
		if (!checkPosition)
			finalizer.raf.seek(_pos);
	}

	private long getFreeSpace() throws IOException {
		return length() - currentPosition();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public long skip(long _nb) throws IOException {
		long skipped = Math.min(getFreeSpace(), _nb);
		position=position + skipped;
		return skipped;
	}



	/**
	 * {@inheritDoc}
	 */
	@Override
	public long currentPosition() throws IOException {
		return position;
	}

	@Override
	public boolean isClosed() {
		return finalizer.closed;
	}

	@Override
	public void readFully(byte[] tab, int off, int len) throws IOException{
		checkLimits(tab, off, len);
		checkPosition();
		finalizer.raf.readFully(tab, off, len);
		position+=len;
	}

	@Override
	public String readLine() throws IOException {
		checkPosition();
		String res=finalizer.raf.readLine();
		position=finalizer.raf.getFilePointer();
		return res;
	}



	/**
	 * {@inheritDoc}
	 */
	@Override
	public void close() throws IOException {
		finalizer.close();
	}


}
