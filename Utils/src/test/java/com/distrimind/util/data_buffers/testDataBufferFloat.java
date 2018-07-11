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

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.Random;

import org.testng.annotations.BeforeClass;
import org.testng.annotations.Test;

import static org.testng.Assert.*;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.4
 *
 */
public final class testDataBufferFloat extends testDataBuffer {
	protected static int size = 50;
	protected static float tab[] = null;

	public static float[] getTab(int _size) {
		float res[] = new float[_size];
		Random r = new Random(System.currentTimeMillis());

		for (int i = _size - 1; i >= 0; i--) {
			res[i] = r.nextFloat();
		}
		return res;
	}

	@BeforeClass
	public static void init() {
		tab = getTab(size);
	}

	@Override
	protected DataBuffer getNewDataBuffer(int _size) {
		return new DataBufferFloat(_size);
	}

	@Override
	protected int getType() {
		return DataBuffer.TYPE_FLOAT;
	}

	@Override
	protected String getTypeString() {
		return "FLOAT";
	}

	@Override
	@Test
	public void testConstructors() {
		DataBufferFloat d = new DataBufferFloat(10);
		assertNotNull(d, "DataBufferBool allocation error");
		d = new DataBufferFloat(tab);
		assertNotNull(d, "DataBufferBool allocation error");
	}

	@Override
	@Test
	public void testGetsSets() {
		DataBufferFloat d = new DataBufferFloat(tab.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab[i], d.getFloat(i), 0.0);
		}

		d = new DataBufferFloat(size);
		for (int i = size - 1; i >= 0; i--) {
			d.setFloat(i, tab[i]);
		}
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((byte) tab[i], d.getByte(i));
			assertEquals((char) tab[i], d.getChar(i));
			assertEquals((double) tab[i], d.getDouble(i), 0.0);
			assertEquals(tab[i], d.getFloat(i), 0.0);
			assertEquals((int) tab[i], d.getInt(i));
			assertEquals((long) tab[i], d.getLong(i));
			assertEquals((short) tab[i], d.getShort(i));
		}

		DataBufferFloat dbool = new DataBufferFloat(size);
		DataBufferFloat db = new DataBufferFloat(size);
		DataBufferFloat dc = new DataBufferFloat(size);
		DataBufferFloat dd = new DataBufferFloat(size);
		DataBufferFloat di = new DataBufferFloat(size);
		DataBufferFloat dl = new DataBufferFloat(size);
		DataBufferFloat ds = new DataBufferFloat(size);

		for (int i = size - 1; i >= 0; i--) {

			dbool.setBoolean(i, tab[i] > 0);
			db.setByte(i, (byte) tab[i]);
			dc.setChar(i, (char) tab[i]);
			dd.setDouble(i, (double) tab[i]);
			di.setInt(i, (int) tab[i]);
			dl.setLong(i, (long) tab[i]);
			ds.setShort(i, (short) tab[i]);
		}

		for (int i = size - 1; i >= 0; i--) {
			assertEquals((tab[i] > 0 ? 1 : 0), dbool.getFloat(i), 0.0);
			assertEquals((byte) tab[i], db.getByte(i));
			assertEquals((char) tab[i], dc.getChar(i));
			assertEquals((double) tab[i], dd.getDouble(i), 0.0);
			assertEquals((int) tab[i], di.getInt(i));
			assertEquals((long) tab[i], dl.getLong(i));
			assertEquals((short) tab[i], ds.getShort(i));
		}

		try {
			d.getBoolean(0);
			fail("getting a boolean on a DataBufferFloat should be imposible");
		} catch (IllegalAccessError ignored) {
		}

	}

	@Override
	@Test
	public void testClone() {
		DataBufferFloat d = new DataBufferFloat(tab);
		DataBufferFloat dd = d.clone();
		assertNotSame(d, dd, "A cloned object cannot have the same reference");
		for (int i = d.getSize() - 1; i >= 0; i--) {
			assertEquals(d.getFloat(i), dd.getFloat(i), 0.0);
		}
	}

	@Override
	@Test
	public void getData() {
		DataBufferFloat d = new DataBufferFloat(tab);
		assertSame(d.getData(), tab);
	}

	@Override
	@Test
	public void setData() {
		DataBufferFloat d = new DataBufferFloat(0);
		d.setData(tab);
		DataBufferFloat dd = new DataBufferFloat(0);
		dd.setData(d.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab[i], d.getFloat(i), 0.0);
			assertEquals(tab[i], dd.getFloat(i), 0.0);
		}

		boolean tbool[] = testDataBufferBool.getTab(size);
		d.setData(tbool);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tbool[i] != (((int) d.getFloat(i)) % 2 == 0));
		}

        byte tb[] = testDataBufferByte.getTab(size);
		d.setData(tb);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((float) tb[i], d.getFloat(i), 0.0);
		}

        char tc[] = testDataBufferChar.getTab(size);
		d.setData(tc);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((float) tc[i], d.getFloat(i), 0.0);
		}

        double td[] = testDataBufferDouble.getTab(size);
		d.setData(td);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((float) td[i], d.getFloat(i), 0.0);
		}

        int ti[] = testDataBufferInt.getTab(size);
		d.setData(ti);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((float) ti[i], d.getFloat(i), 0.0);
		}

        long tl[] = testDataBufferLong.getTab(size);
		d.setData(tl);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((float) tl[i], d.getFloat(i), 0.0);
		}

        short ts[] = testDataBufferShort.getTab(size);
		d.setData(ts);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((float) ts[i], d.getFloat(i), 0.0);
		}
        d = new DataBufferFloat(0);

		try {
			d.setData(0.0);
			fail("setting any object other than numeric buffer on a DataBufferFloat should be imposible");
		} catch (IllegalArgumentException ignored) {
		}

	}

	@Override
	@Test
	public void insertData() {
		float tab2[] = getTab(size);

		DataBufferFloat d = new DataBufferFloat(tab);
		DataBufferFloat dd = new DataBufferFloat(tab2);
		d.insertData(d.getSize(), dd);
		assertEquals(d.getSize(), dd.getSize() * 2);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab[i], d.getFloat(i), 0.0);
		}
		for (int i = size * 2 - 1; i >= size; i--) {
			assertEquals(tab2[i - size], d.getFloat(i), 0.0);
		}
		d.insertData(0, dd);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab2[i], d.getFloat(i), 0.0);
		}

		dd.insertValues(dd.getSize(), 10);
		assertEquals(dd.getSize(), tab.length + 10);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab2[i], dd.getFloat(i), 0.0);
		}
		dd.insertValues(0, 10);
		assertEquals(dd.getSize(), tab.length + 20);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab2[i], dd.getFloat(i + 10), 0.0);
		}
	}

	@Override
	@Test
	public void removeValues() {
		DataBufferFloat d = new DataBufferFloat(tab);
		d.removeValues(0, 10);
		assertEquals(40, d.getSize());
		for (int i = 9; i >= 0; i--) {
			assertEquals(tab[i + 10], d.getFloat(i), 0.0);
		}
		d = new DataBufferFloat(tab);
		d.removeValues(d.getSize() - 10, 10);
		assertEquals(40, d.getSize());
		for (int i = 9; i >= 0; i--) {
			assertEquals(tab[i], d.getFloat(i), 0.0);
		}

		d = new DataBufferFloat(tab);
		try {
			d.removeValues(0, size + 10);
			fail();
		} catch (Exception e) {
			assertTrue(true);
		}

		d = new DataBufferFloat(tab);
		try {
			d.removeValues(-1, size + 10);
			fail();
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

		DataBufferFloat d = new DataBufferFloat(tab);
		boolean ok = true;
		try {
			fOut = new FileOutputStream(".test_databufferfloat.dat");
			oOut = new ObjectOutputStream(fOut);
			oOut.writeObject(d);
		} catch (IOException e) {
			e.printStackTrace();
			ok = false;
		} finally {
			try {
				assert oOut != null;
				oOut.flush();
				oOut.close();
				fOut.close();
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		try {
			fIn = new FileInputStream(".test_databufferfloat.dat");
			oIn = new ObjectInputStream(fIn);
			DataBufferFloat dd = (DataBufferFloat) oIn.readObject();
			assertEquals(dd.getSize(), d.getSize());
			for (int i = d.getSize() - 1; i >= 0; i--) {
				assertEquals(d.getFloat(i), dd.getFloat(i), 0.0);
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			ok = false;
		} finally {
			try {
				oIn.close();
				fIn.close();
				java.io.File f = new File(".test_databufferfloat.dat");
				assertTrue(f.delete());
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		assertTrue(ok);

	}

}
