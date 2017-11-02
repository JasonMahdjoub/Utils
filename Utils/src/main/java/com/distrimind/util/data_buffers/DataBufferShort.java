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

package com.distrimind.util.data_buffers;

import java.io.Serializable;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.4
 *
 */
public final class DataBufferShort extends DataBuffer implements Cloneable, Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 5784938401567196293L;

	private short[] m_buffer = null;

	@Override
	public void setSize(int _size) {
		if (_size != m_size) {
			if (_size < 0)
				throw new IllegalArgumentException("The size must be greater or equal to 0 (" + _size + ")");
			else
				m_buffer = new short[_size];

			m_size = _size;
		}
	}

	public DataBufferShort(int _size) {
		super(_size, TYPE_SHORT);
		m_buffer = new short[_size];
	}

	/*
	 * public DataBufferShort(DataBuffer _d) { super(_d); }
	 */

	public DataBufferShort(final Object _data) {
		super(0, TYPE_SHORT);
		setData(_data);
	}

	@Override
	public DataBufferShort clone() {
		return new DataBufferShort(m_buffer.clone());
	}

	@Override
	public void setAllToZero() {
		for (int i = 0; i < m_size; i++)
			m_buffer[i] = 0;
	}

	@Override
	public Object getData() {
		return m_buffer;
	}

	public short[] getDataShort() {
		return m_buffer;
	}

	@Override
	public void setData(final Object _data) {
		// Object _data=(_d instanceof DataBuffer)?((DataBuffer)_d).getData():_d;
		if (_data == null) {
			m_buffer = null;
			m_size = 0;
		} else if (_data.getClass() == (new short[1]).getClass()) {
			m_buffer = (short[]) _data;
			m_size = m_buffer.length;
		} else {
			int type = DataBuffer.getDataType(_data);
			if (type == TYPE_UNDEFINED)
				throw new IllegalArgumentException(
						"The data must be a tab of numerics or a DataBufferShort (and not a " + _data.getClass() + ")");
			switch (type) {
			case TYPE_BOOL: {
				boolean[] s = (boolean[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					if (s[i])
						b[i] = 1;
					else
						b[i] = 0;
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			case TYPE_CHAR: {
				char[] s = (char[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					b[i] = (short) s[i];
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			case TYPE_BYTE: {
				byte[] s = (byte[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					b[i] = (short) s[i];
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			case TYPE_INT: {
				int[] s = (int[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					b[i] = (short) s[i];
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			case TYPE_LONG: {
				long[] s = (long[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					b[i] = (short) s[i];
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			case TYPE_FLOAT: {
				float[] s = (float[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					b[i] = (short) s[i];
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			case TYPE_DOUBLE: {
				double[] s = (double[]) _data;
				short[] b = new short[s.length];
				for (int i = 0; i < s.length; i++) {
					b[i] = (short) s[i];
				}
				m_buffer = b;
				m_size = s.length;
				break;
			}
			}
		}

	}

	@Override
	public boolean getBoolean(int _i) {
		throw new IllegalAccessError("Cannot convert a short to a boolean");
	}

	@Override
	public byte getByte(int _i) {
		return (byte) m_buffer[_i];
	}

	@Override
	public char getChar(int _i) {
		return (char) m_buffer[_i];
	}

	@Override
	public double getDouble(int _i) {
		return (double) m_buffer[_i];
	}

	@Override
	public float getFloat(int _i) {
		return (float) m_buffer[_i];
	}

	@Override
	public int getInt(int _i) {
		return (int) m_buffer[_i];
	}

	@Override
	public long getLong(int _i) {
		return (long) m_buffer[_i];
	}

	@Override
	public short getShort(int _i) {
		return m_buffer[_i];
	}

	/*
	 * @Override public void leftTroncateData(int _size) { if (_size<0) throw new
	 * IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size+")"); else if (_size==0) {
	 * m_size=0; m_buffer=null; } else if (_size<m_size) { short [] d=new
	 * short[_size]; System.arraycopy(m_buffer, m_size-_size, d, 0, _size);
	 * m_size=_size; m_buffer=d; } }
	 * 
	 * @Override public void rightTroncateData(int _size) { if (_size<0) throw new
	 * IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size+")"); else if (_size==0) {
	 * m_size=0; m_buffer=null; } else if (_size<m_size) { short [] d=new
	 * short[_size]; System.arraycopy(m_buffer, 0, d, 0, _size); m_size=_size;
	 * m_buffer=d; } }
	 * 
	 * @Override public void pushBackData(int _size_to_add) { if (_size_to_add<0)
	 * throw new IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size_to_add+")"); if
	 * (_size_to_add>0) { short [] d=new short[m_size+_size_to_add];
	 * System.arraycopy(m_buffer, 0, d, 0, m_size); m_size=m_size+_size_to_add;
	 * m_buffer=d; } }
	 * 
	 * @Override public void pushBackData(final DataBuffer _d) { if (_d.m_size>0) {
	 * if (this.getClass()!=_d.getClass()) throw new
	 * IllegalArgumentException("Cannot convert a "+_d.getClass()
	 * +" to a DataBufferShort"); else { DataBufferShort d=(DataBufferShort)_d;
	 * short [] dnew=new short[m_size+d.m_size]; System.arraycopy(m_buffer, 0, dnew,
	 * 0, m_size); System.arraycopy(d.m_buffer, 0, dnew, m_size, d.m_size);
	 * m_size=m_size+d.m_size; m_buffer=dnew; } }
	 * 
	 * }
	 * 
	 * @Override public void pushFrontData(int _size_to_add) { if (_size_to_add<0)
	 * throw new IllegalArgumentException
	 * ("The size must be greater or equal to 0 ("+_size_to_add+")"); if
	 * (_size_to_add>0) { short [] d=new short[m_size+_size_to_add];
	 * System.arraycopy(m_buffer, 0, d, _size_to_add, m_size);
	 * m_size=m_size+_size_to_add; m_buffer=d; } }
	 * 
	 * @Override public void pushFrontData(final DataBuffer _d) { if (_d.m_size>0) {
	 * if (this.getClass()!=_d.getClass()) throw new
	 * IllegalArgumentException("Cannot convert a "+_d.getClass()
	 * +" to a DataBufferShort"); else { DataBufferShort d=(DataBufferShort)_d;
	 * short [] dnew=new short[m_size+d.m_size]; System.arraycopy(d.m_buffer, 0,
	 * dnew, 0, d.m_size); System.arraycopy(m_buffer, 0, dnew, d.m_size, m_size);
	 * m_size=m_size+d.m_size; m_buffer=dnew; } }
	 * 
	 * }
	 */

	@Override
	public void setBoolean(int _i, boolean _val) {
		if (_val)
			m_buffer[_i] = 1;
		else
			m_buffer[_i] = 0;
	}

	@Override
	public void setByte(int _i, byte _val) {
		m_buffer[_i] = (short) _val;
	}

	@Override
	public void setChar(int _i, char _val) {
		m_buffer[_i] = (short) _val;
	}

	@Override
	public void setDouble(int _i, double _val) {
		m_buffer[_i] = (short) _val;
	}

	@Override
	public void setFloat(int _i, float _val) {
		m_buffer[_i] = (short) _val;
	}

	@Override
	public void setInt(int _i, int _val) {
		m_buffer[_i] = (short) _val;
	}

	@Override
	public void setLong(int _i, long _val) {
		m_buffer[_i] = (short) _val;
	}

	@Override
	public void setShort(int _i, short _val) {
		m_buffer[_i] = _val;
	}

	@Override
	public java.nio.Buffer getJavaNIOBuffer() {
		return java.nio.ShortBuffer.wrap(m_buffer);
	}

	@Override
	public void insertBooleans(int _i, boolean[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setBoolean(i, _vals[j]);
	}

	@Override
	public void insertBytes(int _i, byte[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setByte(i, _vals[j]);
	}

	@Override
	public void insertChars(int _i, char[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setChar(i, _vals[j]);
	}

	@Override
	public void insertShorts(int _i, short[] _vals) {
		insertValues(_i, _vals.length);
		System.arraycopy(_vals, 0, m_buffer, _i, _vals.length);
	}

	@Override
	public void insertInts(int _i, int[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setInt(i, _vals[j]);
	}

	@Override
	public void insertLongs(int _i, long[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setLong(i, _vals[j]);
	}

	@Override
	public void insertFloats(int _i, float[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setFloat(i, _vals[j]);
	}

	@Override
	public void insertDoubles(int _i, double[] _vals) {
		insertValues(_i, _vals.length);
		for (int i = _i, j = 0; j < _vals.length; ++i, ++j)
			setDouble(i, _vals[j]);
	}

	@Override
	public void insertData(int _i, DataBuffer _d) {
		if (_d.getDataType() == DataBuffer.TYPE_SHORT)
			insertShorts(_i, ((DataBufferShort) _d).m_buffer);
		else {
			insertValues(_i, _d.getSize());
			for (int i = _i, j = 0; j < _d.getSize(); ++i, ++j)
				setShort(i, _d.getShort(j));
		}
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
		short[] buffer = new short[m_size = m_buffer.length + _number];
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
			short[] buffer = new short[m_size = m_buffer.length - _number];
			System.arraycopy(m_buffer, 0, buffer, 0, _index);
			System.arraycopy(m_buffer, _index + _number, buffer, _index, buffer.length - _index);
			m_buffer = buffer;
		}
	}

}
