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


import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Random;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.4
 *
 */
public final class testDataBufferBool extends testDataBuffer {
	protected static int size = 50;
	protected static boolean tab[] = null;

	public static boolean[] getTab(int _size) {
		boolean res[] = new boolean[_size];
		Random r = new Random(System.currentTimeMillis());

		for (int i = _size - 1; i >= 0; i--) {
			int val = r.nextInt() % 2;
			if (val == 0)
				res[i] = false;
			else
				res[i] = true;
		}
		return res;
	}

	@BeforeClass
	public static void init() {
		tab = getTab(size);
	}

	@Override
	protected DataBuffer getNewDataBuffer(int _size) {
		return new DataBufferBool(_size);
	}

	@Override
	protected int getType() {
		return DataBuffer.TYPE_BOOL;
	}

	@Override
	protected String getTypeString() {
		return "BOOLEAN";
	}

	@Override
	@Test
	public void testConstructors() {
		DataBufferBool d = new DataBufferBool(10);
		assertNotNull(d, "DataBufferBool allocation error");
		d = new DataBufferBool(tab);
		assertNotNull(d, "DataBufferBool allocation error");
	}

	@Override
	@Test
	public void testGetsSets() {
		DataBufferBool d = new DataBufferBool(tab.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getBoolean(i));
		}

		d = new DataBufferBool(size);
		for (int i = size - 1; i >= 0; i--) {
			d.setBoolean(i, tab[i]);
		}
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getBoolean(i));
			assertTrue((tab[i] ? (byte) 1 : (byte) 0) == d.getByte(i));
			assertTrue((tab[i] ? (char) 1 : (char) 0) == d.getChar(i));
			assertTrue((tab[i] ? (double) 1 : (double) 0) == d.getDouble(i));
			assertTrue((tab[i] ? (float) 1 : (float) 0) == d.getFloat(i));
			assertTrue((tab[i] ? (int) 1 : (int) 0) == d.getInt(i));
			assertTrue((tab[i] ? (long) 1 : (long) 0) == d.getLong(i));
			assertTrue((tab[i] ? (short) 1 : (short) 0) == d.getShort(i));
		}

		try {
			d.setByte(0, (byte) 0);
			assertTrue(false, "setting a byte on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
		try {
			d.setChar(0, (char) 0);
			assertTrue(false, "setting a char on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
		try {
			d.setDouble(0, (double) 0);
			assertTrue(false, "setting a double on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
		try {
			d.setFloat(0, (float) 0);
			assertTrue(false, "setting a float on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
		try {
			d.setInt(0, (int) 0);
			assertTrue(false, "setting a int on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
		try {
			d.setLong(0, (long) 0);
			assertTrue(false, "setting a long on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
		try {
			d.setShort(0, (short) 0);
			assertTrue(false, "setting a short on a DataBufferBool should be imposible");
		} catch (IllegalAccessError i) {
		}
	}

	@Override
	@Test
	public void testClone() {
		DataBufferBool d = new DataBufferBool(tab);
		DataBufferBool dd = d.clone();
		assertFalse(d == dd, "A cloned object cannot have the same reference");
		for (int i = d.getSize() - 1; i >= 0; i--) {
			assertTrue(d.getBoolean(i) == dd.getBoolean(i));
		}
	}

	@Override
	@Test
	public void getData() {
		DataBufferBool d = new DataBufferBool(tab);
		assertTrue(d.getData() == tab);
	}

	@Override
	@Test
	public void setData() {
		DataBufferBool d = new DataBufferBool(0);
		d.setData(tab);
		DataBufferBool dd = new DataBufferBool(0);
		dd.setData(d.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getBoolean(i));
			assertTrue(tab[i] == dd.getBoolean(i));
		}
		d = new DataBufferBool(0);

		try {
			d.setData(new byte[10]);
			assertTrue(false, "setting a byte buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}
		try {
			d.setData(new short[10]);
			assertTrue(false, "setting a short buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}
		try {
			d.setData(new char[10]);
			assertTrue(false, "setting a char buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}
		try {
			d.setData(new double[10]);
			assertTrue(false, "setting a double buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}
		try {
			d.setData(new float[10]);
			assertTrue(false, "setting a float buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}
		try {
			d.setData(new int[10]);
			assertTrue(false, "setting a int buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}
		try {
			d.setData(new long[10]);
			assertTrue(false, "setting a long buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}

		try {
			d.setData(Double.valueOf(0.0));
			assertTrue(false, "setting a any object other than boolean buffer on a DataBufferBool should be imposible");
		} catch (IllegalArgumentException i) {
		}

	}

	@Override
	@Test
	public void insertData() {
		boolean tab2[] = getTab(size);

		DataBufferBool d = new DataBufferBool(tab);
		DataBufferBool dd = new DataBufferBool(tab2);
		d.insertData(d.getSize(), dd);
		assertTrue(d.getSize() == dd.getSize() * 2);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getBoolean(i));
		}
		for (int i = size * 2 - 1; i >= size; i--) {
			assertTrue(tab2[i - size] == d.getBoolean(i));
		}
		d.insertData(0, dd);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == d.getBoolean(i));
		}

		dd.insertValues(dd.getSize(), 10);
		assertTrue(dd.getSize() == tab.length + 10);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == dd.getBoolean(i));
		}
		dd.insertValues(0, 10);
		assertTrue(dd.getSize() == tab.length + 20);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == dd.getBoolean(i + 10));
		}
	}

	@Override
	@Test
	public void removeValues() {
		DataBufferBool d = new DataBufferBool(tab);
		d.removeValues(0, 10);
		assertTrue(d.getSize() == 40);
		for (int i = 9; i >= 0; i--) {
			assertTrue(tab[i + 10] == d.getBoolean(i));
		}
		d = new DataBufferBool(tab);
		d.removeValues(d.getSize() - 10, 10);
		assertTrue(d.getSize() == 40);
		for (int i = 9; i >= 0; i--) {
			assertTrue(tab[i] == d.getBoolean(i));
		}

		d = new DataBufferBool(tab);
		try {
			d.removeValues(0, size + 10);
			assertTrue(false);
		} catch (Exception e) {
			assertTrue(true);
		}

		d = new DataBufferBool(tab);
		try {
			d.removeValues(-1, size + 10);
			assertTrue(false);
		} catch (Exception e) {
			assertTrue(true);
		}
	}

	@Override
	@Test
	public void serialize() {
		FileOutputStream fOut = null;
		ObjectOutputStream oOut = null;
		FileInputStream fIn = null;
		ObjectInputStream oIn = null;

		DataBufferBool d = new DataBufferBool(tab);
		boolean ok = true;
		try {
			fOut = new FileOutputStream(".test_databufferbool.dat");
			oOut = new ObjectOutputStream(fOut);
			oOut.writeObject(d);
		} catch (IOException e) {
			e.printStackTrace();
			ok = false;
		} finally {
			try {
				oOut.flush();
				oOut.close();
				fOut.close();
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		try {
			fIn = new FileInputStream(".test_databufferbool.dat");
			oIn = new ObjectInputStream(fIn);
			DataBufferBool dd = (DataBufferBool) oIn.readObject();
			assertTrue(dd.getSize() == d.getSize());
			for (int i = d.getSize() - 1; i >= 0; i--) {
				assertTrue(d.getBoolean(i) == dd.getBoolean(i));
			}
		} catch (IOException e) {
			e.printStackTrace();
			ok = false;
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
			ok = false;
		} finally {
			try {
				oIn.close();
				fIn.close();
				java.io.File f = new File(".test_databufferbool.dat");
				assertTrue(f.delete());
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		assertTrue(ok);

	}

}
