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

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.file.Path;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.27.0
 */
@SuppressWarnings("NullableProblems")
public class RandomFileOutputStream extends RandomOutputStream {
	public enum AccessMode {
		/**
		 * Open for reading and writing. If the file does not already exist then an
		 * attempt will be made to create it.
		 */
		READ_AND_WRITE("rw"),
		/**
		 * Open for reading and writing, as with "rw", and also require that every
		 * update to the file's content be written synchronously to the underlying
		 * storage device.
		 */
		READ_AND_WRITE_WITH_SYNCHRONOUS_CONTENT("rwd"),
		/**
		 * Open for reading and writing, as with "rw", and also require that every
		 * update to the file's content or metadata be written synchronously to the
		 * underlying storage device.
		 */
		READ_AND_WRITE_WITH_SYNCHRONOUS_CONTENT_AND_METADATA("rws");

		private final String mode;

		AccessMode(String mode) {
			this.mode = mode;
		}

		String getMode() {
			return mode;
		}
	}

	private final RandomAccessFile raf;
	private boolean closed=false;
	private long position;
	private boolean checkPosition=false;

	public RandomFileOutputStream(Path p, AccessMode mode) throws FileNotFoundException {
		this(p.toFile(), mode);
	}

	public RandomFileOutputStream(Path p) throws FileNotFoundException {
		this(p.toFile());
	}

	public RandomFileOutputStream(File f, AccessMode mode) throws FileNotFoundException {
		raf = new RandomAccessFile(f, mode.getMode());
	}

	public RandomFileOutputStream(File f) throws FileNotFoundException {
		this(f, AccessMode.READ_AND_WRITE);
		position=0;
	}
	private void checkPosition() throws IOException {
		if (checkPosition && position!=raf.getFilePointer())
			raf.seek(position);
	}

	@Override
	protected RandomFileInputStream getRandomInputStreamImpl()
	{
		checkPosition=true;
		return new RandomFileInputStream(raf);
	}

	@SuppressWarnings("RedundantThrows")
	@Override
	public void flush() throws IOException {
	}

	public RandomAccessFile getRandomAccessFile() {
		return raf;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void write(int b) throws IOException {
		checkPosition();
		raf.write(b);
		position+=1;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void write(byte[] _bytes) throws IOException {
		checkPosition();
		raf.write(_bytes);
		position+=_bytes.length;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void write(byte[] _bytes, int _offset, int _length) throws IOException {
		RandomInputStream.checkLimits(_bytes, _offset, _length);
		checkPosition();
		raf.write(_bytes, _offset, _length);
		position+=_length;
	}


	/**
	 * {@inheritDoc}
	 */
	@Override
	public long length() throws IOException {
		return raf.length();
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void setLength(long _length) throws IOException {
		if (_length<0)
			throw new IllegalArgumentException();
		//long p=raf.getFilePointer();
		raf.setLength(_length);
		position=Math.min(position, _length);

		/*if (p>_length)
			raf.seek(_length);*/
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void seek(long _pos) throws IOException {
		if (_pos<0 || _pos>length())
			throw new IllegalArgumentException();
		position=_pos;
		if (!checkPosition)
			raf.seek(_pos);
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
		return closed;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void close() throws IOException {
		closed=true;
		flush();
		raf.close();
	}

	@SuppressWarnings("deprecation")
	@Override
	public void finalize()
	{
		if (!isClosed()) {
			try {
				close();
			} catch (IOException e) {
				e.printStackTrace();
			}
		}
	}
	
}
