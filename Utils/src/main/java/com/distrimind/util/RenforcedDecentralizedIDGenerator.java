/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

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

package com.distrimind.util;

import com.distrimind.util.data_buffers.WrappedString;

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/**
 * This class represents a unique identifier. Uniqueness is guaranteed over the
 * network. The 'reinforced' class denomination means that uniqueness is also
 * guaranteed between different instances of MadKit into the same computer.
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 1.0
 */
public class RenforcedDecentralizedIDGenerator extends AbstractDecentralizedIDGenerator {
	/**
	 * 
	 */
	private static final long serialVersionUID = 4279383128706805738L;

	static final String ToStringHead = "RenforcedDecentralizedID";
	public static RenforcedDecentralizedIDGenerator valueOf(String value) {
		return valueOf(new WrappedString(value));
	}
	public static RenforcedDecentralizedIDGenerator valueOf(WrappedString value) {
		AbstractDecentralizedID res = AbstractDecentralizedID.valueOf(value);
		if (res instanceof RenforcedDecentralizedIDGenerator) {
			return (RenforcedDecentralizedIDGenerator) res;
		} else
			throw new IllegalArgumentException("Invalid format : " + value);
	}

	public RenforcedDecentralizedIDGenerator() {
		super();
	}
	
	public RenforcedDecentralizedIDGenerator(boolean useShortMacAddressAndRandomNumber, boolean hashAllIdentifier) {
		super(useShortMacAddressAndRandomNumber, hashAllIdentifier);
	}


	RenforcedDecentralizedIDGenerator(long timestamp, long work_id_sequence) {
		super(timestamp, work_id_sequence);
	}

	@Override
	protected short getNewSequence() {
		synchronized (AbstractDecentralizedIDGenerator.class) {
			short tmp ;
			try (RandomAccessFile raf = new RandomAccessFile(
					new File(System.getProperty("java.io.tmpdir"), "RDIDG_UTILS_DISTRIMIND"), "rw");
					final FileChannel channel = raf.getChannel();
					final FileLock lock = channel.lock()) {
				if (!lock.isValid())
					throw new IOException();
				final ByteBuffer b = ByteBuffer.allocate(2);
				if (channel.read(b, 0)<2)
					tmp=0;
				else
					tmp = ((short) (b.getShort(0) + 1));
				
				b.putShort(0, tmp);
				b.rewind();
				channel.write(b, 0);
			} catch (IOException e) {
				e.printStackTrace();
				tmp = (short) System.nanoTime();
			}
			return tmp;
		}
	}

	@Override
	byte getType() {
		return AbstractDecentralizedID.REINFORCED_DECENTRALIZED_ID_GENERATOR_TYPE;
	}

	@Override
	public String toString() {
		return ToStringHead + "[" + getTimeStamp() + ";" + getWorkerID() + ";" + getSequenceID() + "]";
	}

}
