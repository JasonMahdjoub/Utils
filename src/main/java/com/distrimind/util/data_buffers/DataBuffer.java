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

package com.distrimind.util.data_buffers;

import java.io.Serializable;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.4
 *
 */
public abstract class DataBuffer implements Cloneable, Serializable {
	/**
	 * 
	 */
	private static final long serialVersionUID = 2681999512187525083L;

	/** Tag for unsigned boolean data. */
	public static final int TYPE_BOOL = 0;

	/** Tag for unsigned byte data. */
	public static final int TYPE_BYTE = 1;

	/** Tag for unsigned char data. */
	public static final int TYPE_CHAR = 2;

	/** Tag for signed short data. Placeholder for future use. */
	public static final int TYPE_SHORT = 3;

	/** Tag for int data. */
	public static final int TYPE_INT = 4;

	/** Tag for long data. */
	public static final int TYPE_LONG = 5;

	/** Tag for float data. Placeholder for future use. */
	public static final int TYPE_FLOAT = 6;

	/** Tag for double data. Placeholder for future use. */
	public static final int TYPE_DOUBLE = 7;

	/**
	 * Tag for byte data. Placeholder for future use. Note that unsigned bytes
	 * doesn't exist on java. Only access functions will transform for example a
	 * byte to an int without sign.
	 */
	public static final int TYPE_UNSIGNED_BYTE = 8;

	/**
	 * Tag for short data. Placeholder for future use. Note that unsigned short
	 * doesn't exist on java. Only access functions will transform for example a
	 * short to an int without sign.
	 */
	public static final int TYPE_UNSIGNED_SHORT = 9;

	/** Tag for undefined data. */
	public static final int TYPE_UNDEFINED = 32;

	public static final int FIRST_TYPE = TYPE_BOOL, LAST_TYPE = TYPE_UNSIGNED_SHORT;

	/** Names of the data types indexed by DataType tags defined above */
	public static final String[] TYPES = { "BOOLEAN", "BYTE", "CHAR", "SHORT", "INT", "LONG", "FLOAT", "DOUBLE",
			"UNSIGNED BYTE", "UNSIGNED SHORT" };

	/** Classes of the data types indexed by DataType tags defined above */
	public static final Class<?>[] TYPE_CLASSES = {boolean[].class, byte[].class,
			char[].class, short[].class, int[].class, long[].class,
			float[].class, double[].class, byte[].class,
			short[].class};

	/** Sizes of the data types indexed by DataType tags defined above */
	private static final int[] dataTypeSize = { 1, 8, 16, 16, 32, 64, 32, 64, 8, 16 };

	/** The size type of this DataBuffer. */
	protected int m_size;

	/** The data type of this DataBuffer. */
	protected int m_data_type;

	static protected int getDataType(final Object o) {
		for (int i = FIRST_TYPE; i <= LAST_TYPE; i++)
			if (o.getClass() == TYPE_CLASSES[i])
				return i;
		return TYPE_UNDEFINED;
	}

	public static int getDataTypeSize(int type) {
		if (type < FIRST_TYPE || type > LAST_TYPE) {
			throw new IllegalArgumentException("Unknown data type " + type);
		}
		return dataTypeSize[type];
	}

	protected DataBuffer(int _size, int _data_type) {
		if (_data_type < FIRST_TYPE || _data_type > LAST_TYPE)
			throw new IllegalArgumentException("Unknown data type " + _data_type);
		if (_size < 0)
			throw new IllegalArgumentException("The size must be greater or equal to 0 (" + _size + ")");
		m_size = _size;
		m_data_type = _data_type;
	}

	/*
	 * protected DataBuffer(DataBuffer _d) { m_size=_d.m_size;
	 * m_data_type=_d.m_data_type; setData(_d); }
	 */
	public abstract void setAllToZero();

	public abstract boolean getBoolean(int _i);

	public abstract byte getByte(int _i);

	public abstract char getChar(int _i);

	public abstract short getShort(int _i);

	public abstract int getInt(int _i);

	public abstract long getLong(int _i);

	public abstract float getFloat(int _i);

	public abstract double getDouble(int _i);

	public abstract void setBoolean(int _i, boolean _val);

	public abstract void setByte(int _i, byte _val);

	public abstract void setChar(int _i, char _val);

	public abstract void setShort(int _i, short _val);

	public abstract void setInt(int _i, int _val);

	public abstract void setLong(int _i, long _val);

	public abstract void setFloat(int _i, float _val);

	public abstract void setDouble(int _i, double _val);

	public final void insertBoolean(int _i, boolean _val) {
		insertValue(_i);
		setBoolean(_i, _val);
	}

	public final void insertByte(int _i, byte _val) {
		insertValue(_i);
		setByte(_i, _val);
	}

	public final void insertChar(int _i, char _val) {
		insertValue(_i);
		setChar(_i, _val);
	}

	public final void insertShort(int _i, short _val) {
		insertValue(_i);
		setShort(_i, _val);
	}

	public final void insertInt(int _i, int _val) {
		insertValue(_i);
		setInt(_i, _val);
	}

	public final void insertLong(int _i, long _val) {
		insertValue(_i);
		setLong(_i, _val);
	}

	public final void insertFloat(int _i, float _val) {
		insertValue(_i);
		setFloat(_i, _val);
	}

	public final void insertDouble(int _i, double _val) {
		insertValue(_i);
		setDouble(_i, _val);
	}

	public abstract void insertBooleans(int _i, boolean[] _vals);

	public abstract void insertBytes(int _i, byte[] _vals);

	public abstract void insertChars(int _i, char[] _vals);

	public abstract void insertShorts(int _i, short[] _vals);

	public abstract void insertInts(int _i, int[] _vals);

	public abstract void insertLongs(int _i, long[] _vals);

	public abstract void insertFloats(int _i, float[] _vals);

	public abstract void insertDoubles(int _i, double[] _vals);

	public abstract void insertData(int _i, DataBuffer _d);

	public final void insertValue(int index) {
		insertValues(index, 1);
	}

	public abstract void insertValues(int index, int number);

	public final void removeValue(int index) {
		removeValues(index, 1);
	}

	public abstract void removeValues(int index, int number);

	public abstract Object getData();

	public abstract void setData(final Object _data);

	public final void setData(final DataBuffer _data) {
		setData(_data.getData());
	}

	public final int getSize() {
		return m_size;
	}

	public final int getDataType() {
		return m_data_type;
	}

	public final String getDataTypeString() {
		if (m_data_type == TYPE_UNDEFINED)
			return "UNDEFINED";
		else
			return TYPES[m_data_type];
	}

	@Override
	final public String toString() {
		return super.toString() + " : type=" + getDataTypeString() + "; size=" + m_size;
	}

	@Override
	public abstract DataBuffer clone();

	public final void pushBackData(final DataBuffer _d) {
		insertData(m_size, _d);
	}

	public final void pushFrontData(final DataBuffer _d) {
		insertData(0, _d);
	}

	public final void pushBackData(int number) {
		insertValues(m_size, number);
	}

	public final void pushFrontData(int number) {
		insertValues(0, number);
	}

	/*
	 * public abstract void pushFrontData(int _size_to_add); public abstract void
	 * pushFrontData(final DataBuffer _d); public abstract void pushBackData(int
	 * _size_to_add); public abstract void pushBackData(final DataBuffer _d);
	 * 
	 * public abstract void leftTroncateData(int _size); public abstract void
	 * rightTroncateData(int _size);
	 */

	public abstract void setSize(int _size);

	public abstract java.nio.Buffer getJavaNIOBuffer();

}
