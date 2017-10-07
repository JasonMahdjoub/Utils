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
package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import com.distrimind.util.sizeof.ObjectSizer;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.5.0
 */
public class OutputDataPackagerWithRandomValues {
	public static byte[] encode(byte[] bytes, int max_random_values_size)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		return encode(bytes, max_random_values_size, SecureRandomType.DEFAULT.getInstance(SecureRandomType.nonce));
	}

	public static byte[] encode(byte[] bytes, int max_random_values_size, AbstractSecureRandom rand) {
		if (bytes == null)
			throw new NullPointerException("bytes");
		OutputDataPackagerWithRandomValues o = new OutputDataPackagerWithRandomValues(
				bytes.length + ObjectSizer.INT_FIELD_SIZE, max_random_values_size, rand);
		o.writeInt(bytes.length);
		o.writeData(bytes, 0, bytes.length);
		o.finilizeTab();
		return o.getBytesArray();
	}

	private final AbstractSecureRandom random;
	private final byte[] tab;
	private final int random_values_size;
	private int random_values_size_remaining;
	// private int data_size;
	private int cursor;
	private int nextRandValuePos;
	protected int randamValuesWrited = 0;
	private int dataRemaining;

	private OutputDataPackagerWithRandomValues(int bufferSize, int max_random_values_size, AbstractSecureRandom rand) {
		if (rand == null)
			throw new NullPointerException("rand");
		this.random = rand;
		int min = getMiniRandomValueSize();
		if (max_random_values_size >= min)
			this.random_values_size = min + rand.nextInt(max_random_values_size - min + 1);
		else
			this.random_values_size = min;
		random_values_size_remaining = this.random_values_size;
		tab = new byte[bufferSize + this.random_values_size];
		// data_size=tab.length-this.random_values_size;
		cursor = 0;
		nextRandValuePos = 0;
		this.dataRemaining = bufferSize;

	}

	/*
	 * private int getWritedData() { return cursor-randamValuesWrited; }
	 * 
	 * 
	 * private boolean writeData(byte d) { byte t[]=new byte[1]; t[0]=d; return
	 * writeData(t, 0, 1)==1; }
	 */

	private int writeData(byte[] d, int offset, int size) {
		if (size <= 0)
			return 0;
		int total = 0;
		while (size > 0) {
			int length = Math.min(nextRandValuePos - cursor, size);
			if (length > 0) {
				System.arraycopy(d, offset, tab, cursor, length);
				offset += length;
				cursor += length;
				size -= length;
				total += length;
				dataRemaining -= length;
				writeRandomValues();
			} else if (cursor >= tab.length)
				return total;
			else
				writeRandomValues();
		}
		return total;
	}

	/*
	 * private int writeData(InputStream is, int size) throws IOException { if
	 * (size<=0) return 0; int total=0; while (size>0) { int
	 * length=Math.min(nextRandValuePos-cursor, size);
	 * 
	 * 
	 * if (length>0) { int readLength=is.read(tab, cursor, length);
	 * 
	 * cursor+=readLength; total+=readLength; size-=readLength; if
	 * (readLength!=length) return total; writeRandomValues(); } else if
	 * (cursor>=tab.length) return total; else writeRandomValues(); } return total;
	 * }
	 */

	private void writeRandomValues() {
		if (cursor == nextRandValuePos) {
			random_values_size_remaining = Math.min(tab.length - cursor, random_values_size_remaining);
			if (random_values_size_remaining < getMiniRandomValueSize()) {
				random_values_size_remaining = 0;
				nextRandValuePos = tab.length;
				return;
			}

			int nbrandmax = Math.min(random_values_size_remaining - getMiniRandomValueSize() + 1,
					getMaximumLocalRandomValues() - 1);
			final byte nbrand = (byte) (random.nextInt(nbrandmax) + 1);
			byte tabrand[] = new byte[nbrand];
			random.nextBytes(tabrand);
			byte nextRand = 0;
			if (random_values_size_remaining - nbrand - 2 >= getMiniRandomValueSize()
					&& tab.length - cursor - nbrand - 2 - getMiniRandomValueSize() >= dataRemaining) {
				int v = random_values_size_remaining / (((int) getMaxIntervalOfRandomValues()) / 2);
				if (v == 0)
					v = 1;
				byte maxNextRand = (byte) Math
						.max(Math.min(getMaxIntervalOfRandomValues() - 1, tab.length - cursor) / v, 1);
				nextRand = (byte) (random.nextInt(maxNextRand) + 1);
			}
			tab[cursor++] = encodeLocalNumberRandomVal(nbrand, random);
			for (int i = 0; i < tabrand.length; i++)
				tab[cursor++] = tabrand[i];
			tab[cursor++] = encodeLocalPosNextRandomVal(nextRand, random);
			randamValuesWrited += 2 + nbrand;
			if (nextRand == 0)
				nextRandValuePos = tab.length;
			else
				nextRandValuePos = cursor + nextRand;
			random_values_size_remaining -= (nbrand + 2);
		}
	}

	private void finilizeTab() {
		if (cursor < tab.length) {
			byte rands[] = new byte[tab.length - cursor];

			random.nextBytes(rands);
			System.arraycopy(rands, 0, tab, cursor, rands.length);
			cursor += rands.length;
			nextRandValuePos = tab.length;
			random_values_size_remaining -= rands.length;
			randamValuesWrited += rands.length;
		}
	}

	private byte[] getBytesArray() {
		return tab;
	}

	private boolean writeInt(int _value) {
		byte b[] = new byte[4];
		Bits.putInt(b, 0, _value);
		return writeData(b, 0, 4) == 4;
	}

	/*
	 * private int getRealDataSize() { return data_size; }
	 * 
	 * 
	 * private boolean writeShort(short _value) { byte b[]=new byte[2];
	 * Bits.putShort(b, 0, _value); return writeData(b, 0, 2)==2; }
	 * 
	 * private boolean writeLong(long _value) { byte b[]=new byte[8];
	 * Bits.putLong(b, 0, _value); return writeData(b, 0, 8)==8; }
	 */

	static int getMiniRandomValueSize() {
		return 3;
	}

	static byte getMaximumLocalRandomValues() {
		return 32;
	}

	static byte encodeLocalNumberRandomVal(byte val, AbstractSecureRandom rand) {
		return encodeLocalNumberRandomVal(val, getMaximumLocalRandomValuesBitsNumber(), rand);
	}

	static byte encodeLocalPosNextRandomVal(byte val, AbstractSecureRandom rand) {
		return encodeLocalNumberRandomVal(val, getMaximumIntervalOfRandomValuesBitsNumber(), rand);
	}

	private static byte encodeLocalNumberRandomVal(byte val, byte maxBits, AbstractSecureRandom rand) {
		return (byte) ((rand.nextInt(1 << (8 - maxBits)) << maxBits) | (int) val);
	}

	static byte getMaximumLocalRandomValuesBitsNumber() {
		return 5;
	}

	static byte getMaxIntervalOfRandomValues() {
		return 64;
	}

	static byte getMaximumIntervalOfRandomValuesBitsNumber() {
		return 6;
	}

}
