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
public final class testDataBufferChar extends testDataBuffer {
	protected static int size = 50;
	protected static char tab[] = null;

	public static char[] getTab(int _size) {
		char res[] = new char[_size];
		Random r = new Random(System.currentTimeMillis());

		for (int i = _size - 1; i >= 0; i--) {
			res[i] = (char) r.nextInt();
		}
		return res;
	}

	@BeforeClass
	public static void init() {
		tab = getTab(size);
	}

	@Override
	protected DataBuffer getNewDataBuffer(int _size) {
		return new DataBufferChar(_size);
	}

	@Override
	protected int getType() {
		return DataBuffer.TYPE_CHAR;
	}

	@Override
	protected String getTypeString() {
		return "CHAR";
	}

	@Override
	@Test
	public void testConstructors() {
		DataBufferChar d = new DataBufferChar(10);
		assertNotNull(d, "DataBufferBool allocation error");
		d = new DataBufferChar(tab);
		assertNotNull(d, "DataBufferBool allocation error");
	}

	@Override
	@Test
	public void testGetsSets() {
		DataBufferChar d = new DataBufferChar(tab.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab[i], d.getChar(i));
		}

		d = new DataBufferChar(size);
		for (int i = size - 1; i >= 0; i--) {
			d.setChar(i, tab[i]);
		}
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((byte) tab[i], d.getByte(i));
			assertEquals(tab[i], d.getChar(i));
			assertEquals((double) tab[i], d.getDouble(i), 0.0);
			assertEquals((float) tab[i], d.getFloat(i), 0.0);
			assertEquals((int) tab[i], d.getInt(i));
			assertEquals((long) tab[i], d.getLong(i));
			assertEquals((short) tab[i], d.getShort(i));
		}

		DataBufferChar dbool = new DataBufferChar(size);
		DataBufferChar db = new DataBufferChar(size);
		DataBufferChar dd = new DataBufferChar(size);
		DataBufferChar df = new DataBufferChar(size);
		DataBufferChar di = new DataBufferChar(size);
		DataBufferChar dl = new DataBufferChar(size);
		DataBufferChar ds = new DataBufferChar(size);

		for (int i = size - 1; i >= 0; i--) {

			dbool.setBoolean(i, tab[i] > 0);
			db.setByte(i, (byte) tab[i]);
			dd.setDouble(i, (double) tab[i]);
			df.setFloat(i, (float) tab[i]);
			di.setInt(i, (int) tab[i]);
			dl.setLong(i, (long) tab[i]);
			ds.setShort(i, (short) tab[i]);
		}

		for (int i = size - 1; i >= 0; i--) {
			assertEquals((tab[i] > 0 ? 1 : 0), dbool.getChar(i));
			assertEquals((byte) tab[i], db.getByte(i));
			assertEquals((double) tab[i], dd.getDouble(i), 0.0);
			assertEquals((float) tab[i], df.getFloat(i), 0.0);
			assertEquals((int) tab[i], di.getInt(i));
			assertEquals((long) tab[i], dl.getLong(i));
			assertEquals((short) tab[i], ds.getShort(i));
		}

		try {
			d.getBoolean(0);
			fail("getting a boolean on a DataBufferChar should be imposible");
		} catch (IllegalAccessError ignored) {
		}

	}

	@Override
	@Test
	public void testClone() {
		DataBufferChar d = new DataBufferChar(tab);
		DataBufferChar dd = d.clone();
		assertNotSame(d, dd, "A cloned object cannot have the same reference");
		for (int i = d.getSize() - 1; i >= 0; i--) {
			assertEquals(d.getChar(i), dd.getChar(i));
		}
	}

	@Override
	@Test
	public void getData() {
		DataBufferChar d = new DataBufferChar(tab);
		assertSame(d.getData(), tab);
	}

	@Override
	@Test
	public void setData() {
		DataBufferChar d = new DataBufferChar(0);
		d.setData(tab);
		DataBufferChar dd = new DataBufferChar(0);
		dd.setData(d.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab[i], d.getChar(i));
			assertEquals(tab[i], dd.getChar(i));
		}

		boolean tbool[] = testDataBufferBool.getTab(size);
		d.setData(tbool);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tbool[i] != (d.getChar(i) % 2 == 0));
		}

		byte tb[] = testDataBufferByte.getTab(size);
		d.setData(tb);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((char) tb[i], d.getChar(i));
		}

        double td[] = testDataBufferDouble.getTab(size);
		d.setData(td);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((char) td[i], d.getChar(i));
		}

        float tf[] = testDataBufferFloat.getTab(size);
		d.setData(tf);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((char) tf[i], d.getChar(i));
		}

        int ti[] = testDataBufferInt.getTab(size);
		d.setData(ti);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((char) ti[i], d.getChar(i));
		}

        long tl[] = testDataBufferLong.getTab(size);
		d.setData(tl);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((char) tl[i], d.getChar(i));
		}

        short ts[] = testDataBufferShort.getTab(size);
		d.setData(ts);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals((char) ts[i], d.getChar(i));
		}
        d = new DataBufferChar(0);

		try {
			d.setData(0.0);
			fail("setting any object other than numeric buffer on a DataBufferChar should be imposible");
		} catch (IllegalArgumentException ignored) {
		}

	}

	@Override
	@Test
	public void insertData() {
		char tab2[] = getTab(size);

		DataBufferChar d = new DataBufferChar(tab);
		DataBufferChar dd = new DataBufferChar(tab2);
		d.insertData(d.getSize(), dd);
		assertEquals(d.getSize(), dd.getSize() * 2);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab[i], d.getChar(i));
		}
		for (int i = size * 2 - 1; i >= size; i--) {
			assertEquals(tab2[i - size], d.getChar(i));
		}
		d.insertData(0, dd);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab2[i], d.getChar(i));
		}

		dd.insertValues(dd.getSize(), 10);
		assertEquals(dd.getSize(), tab.length + 10);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab2[i], dd.getChar(i));
		}
		dd.insertValues(0, 10);
		assertEquals(dd.getSize(), tab.length + 20);
		for (int i = size - 1; i >= 0; i--) {
			assertEquals(tab2[i], dd.getChar(i + 10));
		}
	}

	@Override
	@Test
	public void removeValues() {
		DataBufferChar d = new DataBufferChar(tab);
		d.removeValues(0, 10);
		assertEquals(40, d.getSize());
		for (int i = 9; i >= 0; i--) {
			assertEquals(tab[i + 10], d.getChar(i));
		}
		d = new DataBufferChar(tab);
		d.removeValues(d.getSize() - 10, 10);
		assertEquals(40, d.getSize());
		for (int i = 9; i >= 0; i--) {
			assertEquals(tab[i], d.getChar(i));
		}

		d = new DataBufferChar(tab);
		try {
			d.removeValues(0, size + 10);
			fail();
		} catch (Exception e) {
			assertTrue(true);
		}

		d = new DataBufferChar(tab);
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

		DataBufferChar d = new DataBufferChar(tab);
		boolean ok = true;
		try {
			fOut = new FileOutputStream(".test_databufferchar.dat");
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
			fIn = new FileInputStream(".test_databufferchar.dat");
			oIn = new ObjectInputStream(fIn);
			DataBufferChar dd = (DataBufferChar) oIn.readObject();
			assertEquals(dd.getSize(), d.getSize());
			for (int i = d.getSize() - 1; i >= 0; i--) {
				assertEquals(d.getChar(i), dd.getChar(i));
			}
		} catch (IOException | ClassNotFoundException e) {
			e.printStackTrace();
			ok = false;
		} finally {
			try {
				oIn.close();
				fIn.close();
				java.io.File f = new File(".test_databufferchar.dat");
				assertTrue(f.delete());
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		assertTrue(ok);

	}

}
