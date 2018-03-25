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
public class testDataBufferUnsignedShort extends testDataBuffer {
	protected static int size = 50;
	protected static short tab[] = null;

	public static short[] getTab(int _size) {
		short res[] = new short[_size];
		Random r = new Random(System.currentTimeMillis());

		for (int i = _size - 1; i >= 0; i--) {
			res[i] = (short) r.nextInt();
		}
		return res;
	}

	@BeforeClass
	public static void init() {
		tab = getTab(size);
	}

	@Override
	protected DataBuffer getNewDataBuffer(int _size) {
		return new DataBufferUnsignedShort(_size);
	}

	@Override
	protected int getType() {
		return DataBuffer.TYPE_UNSIGNED_SHORT;
	}

	@Override
	protected String getTypeString() {
		return "UNSIGNED SHORT";
	}

	@Override
	@Test
	public void testConstructors() {
		DataBufferUnsignedShort d = new DataBufferUnsignedShort(10);
		assertNotNull(d, "DataBufferBool allocation error");
		d = new DataBufferUnsignedShort(tab);
		assertNotNull(d, "DataBufferBool allocation error");
	}

	@Override
	@Test
	public void testGetsSets() {
		DataBufferUnsignedShort d = new DataBufferUnsignedShort(tab.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getShort(i));
		}

		d = new DataBufferUnsignedShort(size);
		for (int i = size - 1; i >= 0; i--) {
			d.setShort(i, tab[i]);
		}
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) tab[i] == d.getByte(i));
			assertTrue((char) (0xFFFF & tab[i]) == d.getChar(i));
			assertTrue((double) (0x0000FFFF & (int) tab[i]) == d.getDouble(i));
			assertTrue((float) (0x0000FFFF & (int) tab[i]) == d.getFloat(i));
			assertTrue((int) (0x0000FFFF & (int) tab[i]) == d.getInt(i));
			assertTrue((long) (0x000000000000FFFF & (long) tab[i]) == d.getLong(i));
			assertTrue(tab[i] == d.getShort(i));
		}

		DataBufferUnsignedShort dbool = new DataBufferUnsignedShort(size);
		DataBufferUnsignedShort db = new DataBufferUnsignedShort(size);
		DataBufferUnsignedShort dc = new DataBufferUnsignedShort(size);
		DataBufferUnsignedShort dd = new DataBufferUnsignedShort(size);
		DataBufferUnsignedShort df = new DataBufferUnsignedShort(size);
		DataBufferUnsignedShort di = new DataBufferUnsignedShort(size);
		DataBufferUnsignedShort dl = new DataBufferUnsignedShort(size);

		for (int i = size - 1; i >= 0; i--) {

			dbool.setBoolean(i, tab[i] > 0);
			db.setByte(i, (byte) tab[i]);
			dc.setChar(i, (char) tab[i]);
			dd.setDouble(i, (double) tab[i]);
			df.setFloat(i, (float) tab[i]);
			di.setInt(i, (int) tab[i]);
			dl.setLong(i, (long) tab[i]);
		}

		for (int i = size - 1; i >= 0; i--) {
			assertTrue((tab[i] > 0 ? 1 : 0) == dbool.getLong(i));
			assertTrue((byte) tab[i] == db.getByte(i));
			assertTrue((char) (0xFFFF & tab[i]) == dc.getChar(i));
			assertTrue((double) (0xFFFF & tab[i]) == dd.getDouble(i));
			assertTrue((float) (0xFFFF & tab[i]) == df.getFloat(i));
			assertTrue((int) (0xFFFF & tab[i]) == di.getInt(i));
			assertTrue((long) (0xFFFF & tab[i]) == dl.getLong(i));
		}

		try {
			d.getBoolean(0);
			assertTrue(false, "getting a boolean on a DataBufferUnsignedShort should be imposible");
		} catch (IllegalAccessError i) {
		}

	}

	@Override
	@Test
	public void testClone() {
		DataBufferUnsignedShort d = new DataBufferUnsignedShort(tab);
		DataBufferUnsignedShort dd = d.clone();
		assertFalse(d == dd, "A cloned object cannot have the same reference");
		for (int i = d.getSize() - 1; i >= 0; i--) {
			assertTrue(d.getShort(i) == dd.getShort(i));
		}
	}

	@Override
	@Test
	public void getData() {
		DataBufferUnsignedShort d = new DataBufferUnsignedShort(tab);
		assertTrue(d.getData() == tab);
	}

	@Override
	@Test
	public void setData() {
		DataBufferUnsignedShort d = new DataBufferUnsignedShort(0);
		d.setData(tab);
		DataBufferUnsignedShort dd = new DataBufferUnsignedShort(0);
		dd.setData(d.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getShort(i));
			assertTrue(tab[i] == dd.getShort(i));
		}

		boolean tbool[] = testDataBufferBool.getTab(size);
		d.setData(tbool);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tbool[i] == (((int) d.getShort(i)) % 2 == 0) ? false : true);
		}
		tbool = null;

		byte tb[] = testDataBufferByte.getTab(size);
		d.setData(tb);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((short) tb[i] == d.getShort(i));
		}
		tb = null;

		char tc[] = testDataBufferChar.getTab(size);
		d.setData(tc);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((short) tc[i] == d.getShort(i));
		}
		tc = null;

		double td[] = testDataBufferDouble.getTab(size);
		d.setData(td);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((short) td[i] == d.getShort(i));
		}
		td = null;

		float tf[] = testDataBufferFloat.getTab(size);
		d.setData(tf);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((short) tf[i] == d.getShort(i));
		}
		tf = null;

		int ti[] = testDataBufferInt.getTab(size);
		d.setData(ti);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((short) ti[i] == d.getShort(i));
		}
		ti = null;

		long tl[] = testDataBufferLong.getTab(size);
		d.setData(tl);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((short) tl[i] == d.getShort(i));
		}
		tl = null;
		d = new DataBufferUnsignedShort(0);

		try {
			d.setData(Double.valueOf(0.0));
			assertTrue(false, "setting any object other than numeric buffer on a DataBufferUnsignedShort should be imposible");
		} catch (IllegalArgumentException i) {
		}

	}

	@Override
	@Test
	public void insertData() {
		short tab2[] = getTab(size);

		DataBufferUnsignedShort d = new DataBufferUnsignedShort(tab);
		DataBufferUnsignedShort dd = new DataBufferUnsignedShort(tab2);
		d.insertData(d.getSize(), dd);
		assertTrue(d.getSize() == dd.getSize() * 2);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getShort(i));
		}
		for (int i = size * 2 - 1; i >= size; i--) {
			assertTrue(tab2[i - size] == d.getShort(i));
		}
		d.insertData(0, dd);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == d.getShort(i));
		}

		dd.insertValues(dd.getSize(), 10);
		assertTrue(dd.getSize() == tab.length + 10);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == dd.getShort(i));
		}
		dd.insertValues(0, 10);
		assertTrue(dd.getSize() == tab.length + 20);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == dd.getShort(i + 10));
		}
	}

	@Override
	@Test
	public void removeValues() {
		DataBufferUnsignedShort d = new DataBufferUnsignedShort(tab);
		d.removeValues(0, 10);
		assertTrue(d.getSize() == 40);
		for (int i = 9; i >= 0; i--) {
			assertTrue(tab[i + 10] == d.getShort(i));
		}
		d = new DataBufferUnsignedShort(tab);
		d.removeValues(d.getSize() - 10, 10);
		assertTrue(d.getSize() == 40);
		for (int i = 9; i >= 0; i--) {
			assertTrue(tab[i] == d.getShort(i));
		}

		d = new DataBufferUnsignedShort(tab);
		try {
			d.removeValues(0, size + 10);
			assertTrue(false);
		} catch (Exception e) {
			assertTrue(true);
		}

		d = new DataBufferUnsignedShort(tab);
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

		DataBufferUnsignedShort d = new DataBufferUnsignedShort(tab);
		boolean ok = true;
		try {
			fOut = new FileOutputStream(".test_databuffershort.dat");
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
			fIn = new FileInputStream(".test_databuffershort.dat");
			oIn = new ObjectInputStream(fIn);
			DataBufferUnsignedShort dd = (DataBufferUnsignedShort) oIn.readObject();
			assertTrue(dd.getSize() == d.getSize());
			for (int i = d.getSize() - 1; i >= 0; i--) {
				assertTrue(d.getShort(i) == dd.getShort(i));
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
				java.io.File f = new File(".test_databuffershort.dat");
				assertTrue(f.delete());
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		assertTrue(ok);

	}

}
