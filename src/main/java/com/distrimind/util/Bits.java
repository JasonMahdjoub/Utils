/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import java.util.Arrays;
import java.util.Base64;

/**
 * Utility methods for packing/unpacking primitive values in/out of byte arrays
 * using big-endian byte ordering.
 */
public class Bits {

	public static byte[] concatenateEncodingWithIntSizedTabs(byte[] part1, byte[] part2) {
		return concatenateEncodingWithSizedTabs(part1, part2, 4);
	}
	public static byte[] concatenateEncodingWithShortIntSizedTabs(byte[] part1, byte[] part2) {
		return concatenateEncodingWithSizedTabs(part1, part2, 3);
	}
	private static byte[] concatenateEncodingWithSizedTabs(byte[] part1, byte[] part2, int sizePrecision) {
		int sizePart1 = part1.length;
		byte[] res = new byte[part2.length + part1.length + sizePrecision];
		Bits.putUnsignedInt(res, 0, sizePart1, sizePrecision);
		System.arraycopy(part1, 0, res, sizePrecision, sizePart1);
		System.arraycopy(part2, 0, res, sizePrecision + sizePart1, part2.length);
		return res;
	}

	public static byte[] concatenateEncodingWithShortSizedTabs(byte[] part1, byte[] part2) {
		return concatenateEncodingWithSizedTabs(part1, part2, 2);
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
		b[off] = (byte) (val >>> 8);
		b[off + 1] = (byte) (val);
	}

	public static void putDouble(byte[] b, int off, double val) {
		putLong(b, off, Double.doubleToLongBits(val));
	}

	public static void putFloat(byte[] b, int off, float val) {
		putInt(b, off, Float.floatToIntBits(val));
	}

	public static void putInt(byte[] b, int off, int val) {



		b[off] = (byte) (val >>> 24);
		b[off + 1] = (byte) (val >>> 16);
		b[off + 2] = (byte) (val >>> 8);
		b[off + 3] = (byte) (val);
	}

	public static void putLong(byte[] b, int off, long val) {
		b[off] = (byte) (val >>> 56);
		b[off + 1] = (byte) (val >>> 48);
		b[off + 2] = (byte) (val >>> 40);
		b[off + 3] = (byte) (val >>> 32);
		b[off + 4] = (byte) (val >>> 24);
		b[off + 5] = (byte) (val >>> 16);
		b[off + 6] = (byte) (val >>> 8);
		b[off + 7] = (byte) (val);
	}

	public static void putShort(byte[] b, int off, short val) {
		b[off + 1] = (byte) (val);
		b[off] = (byte) (val >>> 8);
	}

	public static void putUnsignedInt16Bits(byte[] b, int off, int val) {
		if (val>0xFFFF)
			throw new IllegalArgumentException("val cannot be greater than "+0xFFFF);
		if (val<0)
			throw new IllegalArgumentException("val cannot be negative");
		putShort(b, off, (short)val);
	}
	public static void putUnsignedInt24Bits(byte[] b, int off, int val) {
		if (val>0xFFFFFF)
			throw new IllegalArgumentException("val cannot be greater than "+0xFFFFFF);
		if (val<0)
			throw new IllegalArgumentException("val cannot be negative");


		b[off] = (byte) (val >>> 16);
		b[off + 1] = (byte) (val >>> 8);
		b[off + 2] = (byte) (val);
	}

    public static int getUnsignedInt24Bits(byte[] b, int off) {
        return ((b[off + 2] & 0xFF)) + ((b[off + 1] & 0xFF) << 8) + ((b[off] & 0xFF) << 16);
    }
	public static int getUnsignedInt16Bits(byte[] b, int off) {
		return ((b[off + 1] & 0xFF)) + ((b[off] & 0xFF) << 8);
	}
	public static void putUnsignedInt(byte[] b, int off, long val, int valueSizeInBytes) {
	    if (val<0)
	        throw new IllegalArgumentException();
		if (valueSizeInBytes>8) {
			throw new IllegalArgumentException();
		}
        else if (valueSizeInBytes>=1) {
        	int i=valueSizeInBytes-1;
        	while (i>=0)
			{
				b[off + i--] = (byte) (val);
				val>>>=8;
			}
		}


	}

    public static long getUnsignedInt(byte[] b, int off, int valueSizeInBytes) {
        if (valueSizeInBytes<1)
            return -1;
        else if (valueSizeInBytes<=8) {
        	int i=valueSizeInBytes-1;
        	long res=0;
        	int decal=0;
        	while(i>=0)
			{
				if (decal==0)
					res += (b[off + i--] & 0xFFL);
				else
					res+=(b[off + i--] & 0xFFL) << decal;
				decal+=8;
			}
        	return res;
        }
        else
            throw new IllegalArgumentException();
    }

	public static byte[][] separateEncodingsWithIntSizedTabs(byte[] concatenatedEncodedElement) {
		return separateEncodingsWithIntSizedTabs(concatenatedEncodedElement, 0, concatenatedEncodedElement.length);
	}

	public static byte[][] separateEncodingsWithIntSizedTabs(byte[] concatenatedEncodedElement, int off, int len) {
		return separateEncodingsWithSizedTabs(concatenatedEncodedElement, off, len, 4);
	}

	public static byte[][] separateEncodingsWithShortIntSizedTabs(byte[] concatenatedEncodedElement) {
		return separateEncodingsWithShortIntSizedTabs(concatenatedEncodedElement, 0, concatenatedEncodedElement.length);
	}

	public static byte[][] separateEncodingsWithShortIntSizedTabs(byte[] concatenatedEncodedElement, int off, int len) {
		return separateEncodingsWithSizedTabs(concatenatedEncodedElement, off, len, 3);
	}

	private static byte[][] separateEncodingsWithSizedTabs(byte[] concatenatedEncodedElement, int off, int len, int sizePrecision) {
		int sizePar1 = (int)Bits.getUnsignedInt(concatenatedEncodedElement, off, sizePrecision);
		byte[] part1 = new byte[sizePar1];
		byte[] part2 = new byte[len - sizePrecision - sizePar1];
		System.arraycopy(concatenatedEncodedElement, off + sizePrecision, part1, 0, sizePar1);
		System.arraycopy(concatenatedEncodedElement, off + sizePrecision + sizePar1, part2, 0, part2.length);
		byte[][] res = new byte[2][];
		res[0] = part1;
		res[1] = part2;
		return res;
	}

	public static byte[][] separateEncodingsWithShortSizedTabs(byte[] concatenatedEncodedElement) {
		return separateEncodingsWithShortSizedTabs(concatenatedEncodedElement, 0, concatenatedEncodedElement.length);
	}

	public static byte[][] separateEncodingsWithShortSizedTabs(byte[] concatenatedEncodedElement, int off, int len) {
		return separateEncodingsWithSizedTabs(concatenatedEncodedElement, off, len, 2);
	}

	private static int computeByteParity(byte b)
	{
		int v=b & 0xFF;
		int res=0;
		for (int i=0;i<8;i++)
		{
			if ((v>>i & 1)==1)
				res^=1;
		}
		return res;
	}
	public static StringBuilder toBase64String(byte[] bytes,boolean addChecksum, boolean zeroiseIntermediateArrays)
	{
		byte[] d;
		if (addChecksum)
			d= Bits.getByteArrayWithCheckSum(bytes);
		else
			d=bytes;
		byte[] e=Base64.getUrlEncoder().encode(d);
		StringBuilder res=new StringBuilder(e.length);
		for (byte b : e) res.append((char) (b & 0xff));

		if (zeroiseIntermediateArrays) {
			if (addChecksum)
				Arrays.fill(d, (byte) 0);
			Arrays.fill(e, (byte)0);
		}
		return res;
	}
	private static final String hexValues = "0123456789ABCDEF";
	public static StringBuilder toBase16String(byte[] bytes,boolean addChecksum) {
		return toBase16String(bytes, addChecksum, false);
	}
	public static StringBuilder toBase16String(byte[] bytes,boolean addChecksum, boolean zeroiseIntermediateArrays) {
		byte[] e;
		if (addChecksum)
		{
			e=Bits.getByteArrayWithCheckSum(bytes);
		}
		else
			e=bytes;
		StringBuilder res = new StringBuilder(e.length);
		for (byte b : e) {
			int v = b & 0xFF;
			res.append(hexValues.charAt(v >>> 4));
			res.append(hexValues.charAt(v & 0x0F));
		}
		if (zeroiseIntermediateArrays && addChecksum)
			Arrays.fill(e, (byte)0);
		return res;
	}
	public static byte[] toBytesArrayFromBase16String(CharSequence base16String, boolean containsCheckSum) throws InvalidEncodedValue {
		return toBytesArrayFromBase16String(base16String, containsCheckSum, false);
	}

	public static byte[] toBytesArrayFromBase16String(CharSequence base16String, boolean containsCheckSum, boolean zeroiseIntermediateArrays) throws InvalidEncodedValue {
		if (base16String.length()%2!=0)
			throw new IllegalArgumentException();
		byte[] e=new byte[base16String.length()/2];
		for (int i=0;i<base16String.length();i+=2)
		{
			int v1=hexValues.indexOf(base16String.charAt(i));
			if (v1<0)
				throw new InvalidEncodedValue();
			int v2=hexValues.indexOf(base16String.charAt(i+1));
			if (v2<0)
				throw new InvalidEncodedValue();

			e[i/2]=(byte) ((v1 << 4) + v2);
		}
		if (containsCheckSum) {
			byte[] res = Bits.checkByteArrayAndReturnsItWithoutCheckSum(e);
			if (zeroiseIntermediateArrays) {
				Arrays.fill(e, (byte) 0);
			}
			return res;
		}
		else
			return e;

	}
	public static StringBuilder toBase64String(byte[] bytes, boolean containsCheckSum)
	{
		return toBase64String(bytes, containsCheckSum, false);
	}
	public static byte[] toBytesArrayFromBase64String(String base64String, boolean containsCheckSum) throws InvalidEncodedValue {
		return toBytesArrayFromBase64String(base64String, containsCheckSum, false);
	}
	public static byte[] toBytesArrayFromBase64String(char[] base64String, boolean containsCheckSum) throws InvalidEncodedValue {
		return toBytesArrayFromBase64String(base64String, containsCheckSum, false);
	}

	public static byte[] toBytesArrayFromBase64String(char[] base64String, boolean containsCheckSum, boolean zeroiseIntermediateArrays) throws InvalidEncodedValue {
		try {
			byte[] e=new byte[base64String.length];
			for (int i=0;i<e.length;i++)
				e[i]=(byte)base64String[i];
			byte[] d = Base64.getUrlDecoder().decode(e);

			byte[] res;
			if (containsCheckSum)
				res= Bits.checkByteArrayAndReturnsItWithoutCheckSum(d);
			else
				res=d;
			if (zeroiseIntermediateArrays) {
				if (containsCheckSum)
					Arrays.fill(d, (byte) 0);
				Arrays.fill(e, (byte)0);
			}
			return res;
		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidEncodedValue(e);
		}
	}
	public static byte[] toBytesArrayFromBase64String(String base64String, boolean containsCheckSum, boolean zeroiseIntermediateArrays) throws InvalidEncodedValue {
		try {
			byte[] d = Base64.getUrlDecoder().decode(base64String);
			byte[] res;
			if (containsCheckSum)
				res= Bits.checkByteArrayAndReturnsItWithoutCheckSum(d);
			else
				res=d;
			if (zeroiseIntermediateArrays && containsCheckSum) {
				Arrays.fill(d, (byte) 0);
			}
			return res;
		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidEncodedValue(e);
		}
	}
	public static byte[] toBytesArrayFromBase64String(StringBuilder base64String, boolean containsCheckSum, boolean zeroiseIntermediateArrays) throws InvalidEncodedValue {
		try {
			byte[] e=new byte[base64String.length()];
			for (int i=0;i<e.length;i++)
				e[i]=(byte)base64String.charAt(i);
			byte[] d = Base64.getUrlDecoder().decode(e);
			byte[] res;
			if (containsCheckSum)
				res= Bits.checkByteArrayAndReturnsItWithoutCheckSum(d);
			else
				res=d;
			if (zeroiseIntermediateArrays) {
				if (containsCheckSum)
					Arrays.fill(d, (byte) 0);
				Arrays.fill(e, (byte) 0);
			}
			return res;
		}
		catch (IllegalArgumentException e)
		{
			throw new InvalidEncodedValue(e);
		}
	}
	public static byte[] getByteArrayWithCheckSum(byte[] tab)
	{
		if (tab==null)
			throw new NullPointerException();
		if (tab.length==0)
			return tab;
		byte[] res=new byte[tab.length+1];
		int code=0;
		for (int i=0;i<tab.length;i++)
		{
			byte b=tab[i];
			res[i]=b;
			code^=computeByteParity(b)<<(i%8);

		}
		res[tab.length]=(byte)code;
		return res;
	}

	public static byte[] checkByteArrayAndReturnsItWithoutCheckSum(byte[] tab) throws InvalidEncodedValue {
		if (tab==null)
			throw new NullPointerException();
		if (tab.length==0)
			return tab;
		byte[] res=new byte[tab.length-1];
		int expectedCode=tab[res.length] & 0xFF;
		int code=0;
		for (int i=0;i<res.length;i++)
		{
			byte b=tab[i];
			res[i]=b;
			code^=computeByteParity(b)<<(i%8);
		}
		if (code!=expectedCode)
			throw new InvalidEncodedValue("Invalid check sum");
		return res;
	}


}
