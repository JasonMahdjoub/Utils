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

import java.io.IOException;

import com.distrimind.util.Bits;
import com.distrimind.util.sizeof.ObjectSizer;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.5.0
 */
public class InputDataPackagedWithRandomValues {
	public static byte[] decode(byte[] bytes) throws IOException {
		if (bytes == null)
			throw new NullPointerException("bytes");

		InputDataPackagedWithRandomValues i = new InputDataPackagedWithRandomValues(bytes);
		byte[] res = i.getBytesArray();
		int size = Bits.getInt(res, 0);
		if (size > res.length - ObjectSizer.INT_FIELD_SIZE)
			throw new IOException("Invalid size");
		byte[] res2 = new byte[size];
		System.arraycopy(res, ObjectSizer.INT_FIELD_SIZE, res2, 0, size);
		return res2;

	}

	private final byte[] tab;
	private byte[] tabRes = null;
	// private int realSize=0;

	private InputDataPackagedWithRandomValues(byte[] tab) {
		this.tab = tab;
	}

	private byte[] getBytesArray() throws IOException {
		if (tabRes == null) {
			tabRes = new byte[tab.length];
			int cursor = 0;
			int tabResCursor = 0;
			while (cursor < tab.length) {
				byte nbrand = decodeLocalNumberRandomVal(tab[cursor++]);
				cursor += nbrand;
				if (cursor >= tab.length)
					break;
				byte nextRandVals = decodeLocalPosNextRandomVal(tab[cursor++]);
				int nextRandomValuesPos;
				if (nextRandVals == 0)
					nextRandomValuesPos = tab.length;
				else
					nextRandomValuesPos = cursor + nextRandVals;
				if (cursor >= tab.length)
					break;
				if (nextRandomValuesPos - cursor < 0)
					throw new IOException("Incoherent data !");
				int size = Math.min(nextRandomValuesPos - cursor, tab.length - cursor);
				if (size > 0)
					System.arraycopy(tab, cursor, tabRes, tabResCursor, size);
				cursor += size;
				tabResCursor += size;
			}

			// realSize=tabResCursor;
		}
		return tabRes;
	}

	static byte decodeLocalNumberRandomVal(byte val) {
		return decodeRandomVal(val, OutputDataPackagerWithRandomValues.getMaximumLocalRandomValuesBitsNumber());
	}

	static byte decodeLocalPosNextRandomVal(byte val) {
		return decodeRandomVal(val, OutputDataPackagerWithRandomValues.getMaximumIntervalOfRandomValuesBitsNumber());
	}

	static byte decodeRandomVal(byte val, byte maxBits) {
		return (byte) ((val & 0xFF) & ((1 << maxBits) - 1));
	}
}
