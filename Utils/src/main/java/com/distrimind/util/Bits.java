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

import com.distrimind.util.sizeof.ObjectSizer;

/**
 * Utility methods for packing/unpacking primitive values in/out of byte arrays
 * using big-endian byte ordering.
 */
public class Bits {

	public static byte[] concateEncodingWithIntSizedTabs(byte part1[], byte[] part2) {
		int sizePart1 = part1.length;
		byte[] res = new byte[part2.length + part1.length + ObjectSizer.sizeOf(sizePart1)];
		Bits.putInt(res, 0, sizePart1);
		System.arraycopy(part1, 0, res, ObjectSizer.sizeOf(sizePart1), sizePart1);
		System.arraycopy(part2, 0, res, ObjectSizer.sizeOf(sizePart1) + sizePart1, part2.length);
		return res;
	}

	public static byte[] concateEncodingWithShortSizedTabs(byte part1[], byte[] part2) {
		if (part1.length>Short.MAX_VALUE)
			throw new IllegalArgumentException();
		short sizePart1 = (short) part1.length;
		byte[] res = new byte[part2.length + part1.length + ObjectSizer.sizeOf(sizePart1)];
		Bits.putShort(res, 0, sizePart1);
		System.arraycopy(part1, 0, res, ObjectSizer.sizeOf(sizePart1), sizePart1);
		System.arraycopy(part2, 0, res, ObjectSizer.sizeOf(sizePart1) + sizePart1, part2.length);
		return res;
	}

	public static boolean getBoolean(byte[] b, int off) {
		return b[off] != 0;
	}

	public static char getChar(byte[] b, int off) {
		return (char) ((b[off + 1] & 0xFF) + (b[off] << 8));
	}

	public static double getDouble(byte[] b, int off) {
		return Double.longBitsToDouble(getLong(b, off));
	}

	public static float getFloat(byte[] b, int off) {
		return Float.intBitsToFloat(getInt(b, off));
	}

	public static int getInt(byte[] b, int off) {
		return ((b[off + 3] & 0xFF)) + ((b[off + 2] & 0xFF) << 8) + ((b[off + 1] & 0xFF) << 16) + ((b[off]) << 24);
	}

	/*
	 * Methods for packing primitive values into byte arrays starting at given
	 * offsets.
	 */

	public static long getLong(byte[] b, int off) {
		return ((b[off + 7] & 0xFFL)) + ((b[off + 6] & 0xFFL) << 8) + ((b[off + 5] & 0xFFL) << 16)
				+ ((b[off + 4] & 0xFFL) << 24) + ((b[off + 3] & 0xFFL) << 32) + ((b[off + 2] & 0xFFL) << 40)
				+ ((b[off + 1] & 0xFFL) << 48) + (((long) b[off]) << 56);
	}

	public static short getShort(byte[] b, int off) {
		return (short) ((b[off + 1] & 0xFF) + (b[off] << 8));
	}

	public static void putBoolean(byte[] b, int off, boolean val) {
		b[off] = (byte) (val ? 1 : 0);
	}

	public static void putChar(byte[] b, int off, char val) {
		b[off + 1] = (byte) (val);
		b[off] = (byte) (val >>> 8);
	}

	public static void putDouble(byte[] b, int off, double val) {
		putLong(b, off, Double.doubleToLongBits(val));
	}

	public static void putFloat(byte[] b, int off, float val) {
		putInt(b, off, Float.floatToIntBits(val));
	}

	public static void putInt(byte[] b, int off, int val) {
		b[off + 3] = (byte) (val);
		b[off + 2] = (byte) (val >>> 8);
		b[off + 1] = (byte) (val >>> 16);
		b[off] = (byte) (val >>> 24);
	}

	public static void putLong(byte[] b, int off, long val) {
		b[off + 7] = (byte) (val);
		b[off + 6] = (byte) (val >>> 8);
		b[off + 5] = (byte) (val >>> 16);
		b[off + 4] = (byte) (val >>> 24);
		b[off + 3] = (byte) (val >>> 32);
		b[off + 2] = (byte) (val >>> 40);
		b[off + 1] = (byte) (val >>> 48);
		b[off] = (byte) (val >>> 56);
	}

	public static void putShort(byte[] b, int off, short val) {
		b[off + 1] = (byte) (val);
		b[off] = (byte) (val >>> 8);
	}

	public static byte[][] separateEncodingsWithIntSizedTabs(byte[] concatedEncodedElement) {
		return separateEncodingsWithIntSizedTabs(concatedEncodedElement, 0, concatedEncodedElement.length);
	}

	public static byte[][] separateEncodingsWithIntSizedTabs(byte[] concatedEncodedElement, int off, int len) {
		int sizePar1 = Bits.getInt(concatedEncodedElement, off);
		byte[] part1 = new byte[sizePar1];
		byte[] part2 = new byte[len - ObjectSizer.sizeOf(sizePar1) - sizePar1];
		System.arraycopy(concatedEncodedElement, off + ObjectSizer.sizeOf(sizePar1), part1, 0, sizePar1);
		System.arraycopy(concatedEncodedElement, off + ObjectSizer.sizeOf(sizePar1) + sizePar1, part2, 0, part2.length);
		byte[][] res = new byte[2][];
		res[0] = part1;
		res[1] = part2;
		return res;
	}

	public static byte[][] separateEncodingsWithShortSizedTabs(byte[] concatedEncodedElement) {
		return separateEncodingsWithShortSizedTabs(concatedEncodedElement, 0, concatedEncodedElement.length);
	}

	public static byte[][] separateEncodingsWithShortSizedTabs(byte[] concatedEncodedElement, int off, int len) {
		short sizePar1 = Bits.getShort(concatedEncodedElement, off);
		byte[] part1 = new byte[sizePar1];
		byte[] part2 = new byte[len - ObjectSizer.sizeOf(sizePar1) - sizePar1];
		System.arraycopy(concatedEncodedElement, off + ObjectSizer.sizeOf(sizePar1), part1, 0, sizePar1);
		System.arraycopy(concatedEncodedElement, off + ObjectSizer.sizeOf(sizePar1) + sizePar1, part2, 0, part2.length);
		byte[][] res = new byte[2][];
		res[0] = part1;
		res[1] = part2;
		return res;
	}
}
