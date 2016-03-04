/*
 * Copyright (c) 2001, 2010, Oracle and/or its affiliates. All rights reserved.
 * ORACLE PROPRIETARY/CONFIDENTIAL. Use is subject to license terms.
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */
package com.distrimind.util;

import com.distrimind.util.sizeof.ObjectSizer;

/**
 * Utility methods for packing/unpacking primitive values in/out of byte arrays
 * using big-endian byte ordering.
 */
public class Bits {

    public static boolean getBoolean(byte[] b, int off) {
        return b[off] != 0;
    }

    public static char getChar(byte[] b, int off) {
        return (char) ((b[off + 1] & 0xFF) +
                       (b[off] << 8));
    }

    public static short getShort(byte[] b, int off) {
        return (short) ((b[off + 1] & 0xFF) +
                        (b[off] << 8));
    }

    public static int getInt(byte[] b, int off) {
        return ((b[off + 3] & 0xFF)      ) +
               ((b[off + 2] & 0xFF) <<  8) +
               ((b[off + 1] & 0xFF) << 16) +
               ((b[off    ]       ) << 24);
    }

    public static float getFloat(byte[] b, int off) {
        return Float.intBitsToFloat(getInt(b, off));
    }

    public static long getLong(byte[] b, int off) {
        return ((b[off + 7] & 0xFFL)      ) +
               ((b[off + 6] & 0xFFL) <<  8) +
               ((b[off + 5] & 0xFFL) << 16) +
               ((b[off + 4] & 0xFFL) << 24) +
               ((b[off + 3] & 0xFFL) << 32) +
               ((b[off + 2] & 0xFFL) << 40) +
               ((b[off + 1] & 0xFFL) << 48) +
               (((long) b[off])      << 56);
    }

    public static double getDouble(byte[] b, int off) {
        return Double.longBitsToDouble(getLong(b, off));
    }

    /*
     * Methods for packing primitive values into byte arrays starting at given
     * offsets.
     */

    public static void putBoolean(byte[] b, int off, boolean val) {
        b[off] = (byte) (val ? 1 : 0);
    }

    public static void putChar(byte[] b, int off, char val) {
        b[off + 1] = (byte) (val      );
        b[off    ] = (byte) (val >>> 8);
    }

    public static void putShort(byte[] b, int off, short val) {
        b[off + 1] = (byte) (val      );
        b[off    ] = (byte) (val >>> 8);
    }

    public static void putInt(byte[] b, int off, int val) {
        b[off + 3] = (byte) (val       );
        b[off + 2] = (byte) (val >>>  8);
        b[off + 1] = (byte) (val >>> 16);
        b[off    ] = (byte) (val >>> 24);
    }

    public static void putFloat(byte[] b, int off, float val) {
        putInt(b, off,  Float.floatToIntBits(val));
    }

    public static void putLong(byte[] b, int off, long val) {
        b[off + 7] = (byte) (val       );
        b[off + 6] = (byte) (val >>>  8);
        b[off + 5] = (byte) (val >>> 16);
        b[off + 4] = (byte) (val >>> 24);
        b[off + 3] = (byte) (val >>> 32);
        b[off + 2] = (byte) (val >>> 40);
        b[off + 1] = (byte) (val >>> 48);
        b[off    ] = (byte) (val >>> 56);
    }

    public static void putDouble(byte[] b, int off, double val) {
        putLong(b, off, Double.doubleToLongBits(val));
    }
    
    public static byte[] concateEncodingWithShortSizedTabs(byte part1[], byte[] part2)
    {
	short sizePart1=(short)part1.length;
	byte[] res=new byte[part2.length+part1.length+ObjectSizer.sizeOf(sizePart1)];
	Bits.putShort(res, 0, sizePart1);
	System.arraycopy(part1, 0, res, ObjectSizer.sizeOf(sizePart1), sizePart1);
	System.arraycopy(part2, 0, res, ObjectSizer.sizeOf(sizePart1)+sizePart1, part2.length);
	return res;
    }
    
    public static byte[][] separateEncodingsWithShortSizedTabs(byte[] concatedEncodedElement)
    {
	return separateEncodingsWithShortSizedTabs(concatedEncodedElement, 0, concatedEncodedElement.length);
    }
    public static byte[][] separateEncodingsWithShortSizedTabs(byte[] concatedEncodedElement, int off, int len)
    {
	short sizePar1=Bits.getShort(concatedEncodedElement, off);
	byte[] part1=new byte[sizePar1];
	byte[] part2=new byte[len-ObjectSizer.sizeOf(sizePar1)-sizePar1];
	System.arraycopy(concatedEncodedElement, off+ObjectSizer.sizeOf(sizePar1), part1, 0, sizePar1);
	System.arraycopy(concatedEncodedElement, off+ObjectSizer.sizeOf(sizePar1)+sizePar1, part2, 0, part2.length);
	byte[][] res=new byte[2][];
	res[0]=part1;
	res[1]=part2;
	return res;
    }
    
    public static byte[] concateEncodingWithIntSizedTabs(byte part1[], byte[] part2)
    {
	int sizePart1=part1.length;
	byte[] res=new byte[part2.length+part1.length+ObjectSizer.sizeOf(sizePart1)];
	Bits.putInt(res, 0, sizePart1);
	System.arraycopy(part1, 0, res, ObjectSizer.sizeOf(sizePart1), sizePart1);
	System.arraycopy(part2, 0, res, ObjectSizer.sizeOf(sizePart1)+sizePart1, part2.length);
	return res;
    }
    
    public static byte[][] separateEncodingsWithIntSizedTabs(byte[] concatedEncodedElement)
    {
	return separateEncodingsWithIntSizedTabs(concatedEncodedElement, 0, concatedEncodedElement.length);
    }
    public static byte[][] separateEncodingsWithIntSizedTabs(byte[] concatedEncodedElement, int off, int len)
    {
	int sizePar1=Bits.getInt(concatedEncodedElement, off);
	byte[] part1=new byte[sizePar1];
	byte[] part2=new byte[len-ObjectSizer.sizeOf(sizePar1)-sizePar1];
	System.arraycopy(concatedEncodedElement, off+ObjectSizer.sizeOf(sizePar1), part1, 0, sizePar1);
	System.arraycopy(concatedEncodedElement, off+ObjectSizer.sizeOf(sizePar1)+sizePar1, part2, 0, part2.length);
	byte[][] res=new byte[2][];
	res[0]=part1;
	res[1]=part2;
	return res;
    }
}
