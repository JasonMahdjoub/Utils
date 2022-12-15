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
public final class DataBufferBool extends DataBuffer implements Cloneable, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5210312015395393237L;

	private boolean[] m_buffer = null;

	@Override
	public void setSize(int _size) {
		if (_size != m_size) {

			if (_size < 0)
				throw new IllegalArgumentException("The size must be greater or equal to 0 (" + _size + ")");
			else
				m_buffer = new boolean[_size];

			m_size = _size;
		}
	}

	public DataBufferBool(int _size) {
		super(_size, TYPE_BOOL);
		m_buffer = new boolean[_size];
	}

	/*
	 * public DataBufferBool(DataBuffer _d) { super(_d);
	 * 
	 * }
	 */
	public DataBufferBool(final Object _data) {
		super(0, TYPE_BOOL);
		setData(_data);
	}

	@Override
	public DataBufferBool clone() {
		return new DataBufferBool(m_buffer.clone());
	}

	@Override
	public void setAllToZero() {
		for (int i = 0; i < m_size; i++)
			m_buffer[i] = false;
	}

	@Override
	public Object getData() {
		return m_buffer;
	}

	public boolean[] getDataBoolean() {
		return m_buffer;
	}

	@Override
	public void setData(final Object _data) {
		// Object _data=(_d instanceof DataBuffer)?((DataBuffer)_d).getData():_d;
		if (_data == null) {
			m_buffer = null;
			m_size = 0;
		} else if (_data.getClass() == boolean[].class) {
			m_buffer = (boolean[]) _data;
			m_size = m_buffer.length;
		} else
			throw new IllegalArgumentException(
					"Cannot convert a " + boolean[].class + " to a " + _data.getClass());
	}

	@Override
	public boolean getBoolean(int _i) {
		return m_buffer[_i];
	}

	@Override
	public byte getByte(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	@Override
	public char getChar(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	@Override
	public double getDouble(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	@Override
	public float getFloat(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	@Override
	public int getInt(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	@Override
	public long getLong(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	@Override
	public short getShort(int _i) {
		if (m_buffer[_i])
			return 1;
		else
			return 0;
	}

	/*
	 * @Override public void leftTroncateData(int _size) { if (_size<0) throw new
	 * IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size+")"); else if (_size==0) {
	 * m_size=0; m_buffer=null; } else if (_size<m_size) { boolean [] d=new
	 * boolean[_size]; System.arraycopy(m_buffer, m_size-_size, d, 0, _size);
	 * m_size=_size; m_buffer=d; } }
	 * 
	 * @Override public void rightTroncateData(int _size) { if (_size<0) throw new
	 * IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size+")"); else if (_size==0) {
	 * m_size=0; m_buffer=null; } else if (_size<m_size) { boolean [] d=new
	 * boolean[_size]; System.arraycopy(m_buffer, 0, d, 0, _size); m_size=_size;
	 * m_buffer=d; }
	 * 
	 * }
	 * 
	 * @Override public void pushBackData(int _size_to_add) { if (_size_to_add<0)
	 * throw new IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size_to_add+")"); if
	 * (_size_to_add>0) { boolean [] d=new boolean[m_size+_size_to_add];
	 * System.arraycopy(m_buffer, 0, d, 0, m_size); m_size=m_size+_size_to_add;
	 * m_buffer=d; } }
	 * 
	 * @Override public void pushBackData(final DataBuffer _d) { if (_d.m_size>0) {
	 * if (this.getClass()!=_d.getClass()) throw new
	 * IllegalArgumentException("Cannot convert a "+_d.getClass()
	 * +" to a DataBufferBool"); else { DataBufferBool d=(DataBufferBool)_d; boolean
	 * [] dnew=new boolean[m_size+d.m_size]; System.arraycopy(m_buffer, 0, dnew, 0,
	 * m_size); System.arraycopy(d.m_buffer, 0, dnew, m_size, d.m_size);
	 * m_size=m_size+d.m_size; m_buffer=dnew; } } }
	 * 
	 * @Override public void pushFrontData(int _size_to_add) { if (_size_to_add<0)
	 * throw new IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size_to_add+")"); if
	 * (_size_to_add>0) { boolean [] d=new boolean[m_size+_size_to_add];
	 * System.arraycopy(m_buffer, 0, d, _size_to_add, m_size);
	 * m_size=m_size+_size_to_add; m_buffer=d; } }
	 * 
	 * @Override public void pushFrontData(final DataBuffer _d) { if (_d.m_size>0) {
	 * if (this.getClass()!=_d.getClass()) throw new
	 * IllegalArgumentException("Cannot convert a "+_d.getClass()
	 * +" to a DataBufferBool"); else { DataBufferBool d=(DataBufferBool)_d; boolean
	 * [] dnew=new boolean[m_size+d.m_size]; System.arraycopy(d.m_buffer, 0, dnew,
	 * 0, d.m_size); System.arraycopy(m_buffer, 0, dnew, d.m_size, m_size);
	 * m_size=m_size+d.m_size; m_buffer=dnew; } } }
	 */

	@Override
	public void setBoolean(int _i, boolean _val) {
		m_buffer[_i] = _val;
	}

	@Override
	public void setByte(int _i, byte _val) {
		throw new IllegalAccessError("Cannot convert a byte to a boolean.");
	}

	@Override
	public void setChar(int _i, char _val) {
		throw new IllegalAccessError("Cannot convert a char to a boolean.");
	}

	@Override
	public void setDouble(int _i, double _val) {
		throw new IllegalAccessError("Cannot convert a double to a boolean.");
	}

	@Override
	public void setFloat(int _i, float _val) {
		throw new IllegalAccessError("Cannot convert a float to a boolean.");
	}

	@Override
	public void setInt(int _i, int _val) {
		throw new IllegalAccessError("Cannot convert an int to a boolean.");
	}

	@Override
	public void setLong(int _i, long _val) {
		throw new IllegalAccessError("Cannot convert a long to a boolean.");
	}

	@Override
	public void setShort(int _i, short _val) {
		throw new IllegalAccessError("Cannot convert a short to a boolean.");
	}

	@Override
	public java.nio.Buffer getJavaNIOBuffer() {
		return null;
	}

	@Override
	public void insertBooleans(int _i, boolean[] _vals) {
		insertValues(_i, _vals.length);
		System.arraycopy(_vals, 0, m_buffer, _i, _vals.length);
	}

	@Override
	public void insertBytes(int _i, byte[] _vals) {
		throw new IllegalAccessError("Cannot convert bytes to a booleans.");
	}

	@Override
	public void insertChars(int _i, char[] _vals) {
		throw new IllegalAccessError("Cannot convert chars to a booleans.");
	}

	@Override
	public void insertShorts(int _i, short[] _vals) {
		throw new IllegalAccessError("Cannot convert shorts to a booleans.");
	}

	@Override
	public void insertInts(int _i, int[] _vals) {
		throw new IllegalAccessError("Cannot convert integers to a booleans.");
	}

	@Override
	public void insertLongs(int _i, long[] _vals) {
		throw new IllegalAccessError("Cannot convert longs to a booleans.");
	}

	@Override
	public void insertFloats(int _i, float[] _vals) {
		throw new IllegalAccessError("Cannot convert floats to a booleans.");
	}

	@Override
	public void insertDoubles(int _i, double[] _vals) {
		throw new IllegalAccessError("Cannot convert doubles to a booleans.");
	}

	@Override
	public void insertData(int _i, DataBuffer _d) {
		if (_d.getDataType() == DataBuffer.TYPE_BOOL)
			insertBooleans(_i, ((DataBufferBool) _d).m_buffer);
		else
			throw new IllegalAccessError("Cannot convert " + _d.getDataTypeString() + " to a booleans.");
	}

	@Override
	public void insertValues(int _index, int _number) {
		if (_index < 0 || _index > m_size)
			throw new IllegalArgumentException("the argument _index (" + _index + ") must in [0," + m_size + "]");
		if (_number < 0) {
			removeValues(_index, -_number);
			return;
		}
		if (_number == 0)
			return;
		boolean[] buffer = new boolean[m_size = m_buffer.length + _number];
		System.arraycopy(m_buffer, 0, buffer, 0, _index);
		System.arraycopy(m_buffer, _index, buffer, _index + _number, m_buffer.length - _index);
		m_buffer = buffer;
	}

	@Override
	public void removeValues(int _index, int _number) {
		if (_index < 0 || _index > m_size)
			throw new IllegalArgumentException("the argument _index (" + _index + ") must in [0," + m_size + "]");
		if (_number < 0) {
			insertValues(_index, -_number);
			return;
		}
		if (_number == 0)
			return;
		if (_number + _index > m_size) {
			throw new IllegalArgumentException(
					"Cannot remove " + _number + " at the position " + _index + " on a buffer which size is " + m_size);
		}
		if (_number == m_size) {
			m_buffer = null;
			m_size = 0;
		} else {
			boolean[] buffer = new boolean[m_size = m_buffer.length - _number];
			System.arraycopy(m_buffer, 0, buffer, 0, _index);
			System.arraycopy(m_buffer, _index + _number, buffer, _index, buffer.length - _index);
			m_buffer = buffer;
		}

	}
}
