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
public class testDataBufferUnsignedByte extends testDataBuffer {
	protected static int size = 50;
	protected static byte tab[] = null;

	public static byte[] getTab(int _size) {
		byte res[] = new byte[_size];
		Random r = new Random(System.currentTimeMillis());

		for (int i = _size - 1; i >= 0; i--) {
			res[i] = (byte) r.nextInt();
		}
		return res;
	}

	@BeforeClass
	public static void init() {
		tab = getTab(size);
	}

	@Override
	protected DataBuffer getNewDataBuffer(int _size) {
		return new DataBufferUnsignedByte(_size);
	}

	@Override
	protected int getType() {
		return DataBuffer.TYPE_UNSIGNED_BYTE;
	}

	@Override
	protected String getTypeString() {
		return "UNSIGNED BYTE";
	}

	@Override
	@Test
	public void testConstructors() {
		DataBufferUnsignedByte d = new DataBufferUnsignedByte(10);
		assertNotNull(d, "DataBufferBool allocation error");
		d = new DataBufferUnsignedByte(tab);
		assertNotNull(d, "DataBufferBool allocation error");
	}

	@Override
	@Test
	public void testGetsSets() {
		DataBufferUnsignedByte d = new DataBufferUnsignedByte(tab.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getByte(i));
		}

		d = new DataBufferUnsignedByte(size);
		for (int i = size - 1; i >= 0; i--) {
			d.setByte(i, tab[i]);
		}
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getByte(i));
			assertTrue((char) (0xFF & tab[i]) == d.getChar(i));
			assertTrue((double) (0xFF & tab[i]) == d.getDouble(i));
			assertTrue((float) (0xFF & tab[i]) == d.getFloat(i));
			assertTrue((int) (0xFF & tab[i]) == d.getInt(i));
			assertTrue((long) (0xFF & tab[i]) == d.getLong(i));
			assertTrue((short) (0xFF & tab[i]) == d.getShort(i));
		}

		DataBufferUnsignedByte dbool = new DataBufferUnsignedByte(size);
		DataBufferUnsignedByte dc = new DataBufferUnsignedByte(size);
		DataBufferUnsignedByte dd = new DataBufferUnsignedByte(size);
		DataBufferUnsignedByte df = new DataBufferUnsignedByte(size);
		DataBufferUnsignedByte di = new DataBufferUnsignedByte(size);
		DataBufferUnsignedByte dl = new DataBufferUnsignedByte(size);
		DataBufferUnsignedByte ds = new DataBufferUnsignedByte(size);

		for (int i = size - 1; i >= 0; i--) {

			dbool.setBoolean(i, tab[i] > 0);
			dc.setChar(i, (char) tab[i]);
			dd.setDouble(i, (double) tab[i]);
			df.setFloat(i, (float) tab[i]);
			di.setInt(i, (int) tab[i]);
			dl.setLong(i, (long) tab[i]);
			ds.setShort(i, (short) tab[i]);
		}

		for (int i = size - 1; i >= 0; i--) {
			assertTrue((tab[i] > 0 ? 1 : 0) == dbool.getByte(i));
			assertTrue((char) (0xFF & tab[i]) == dc.getChar(i));
			assertTrue((double) (0xFF & tab[i]) == dd.getDouble(i));
			assertTrue((float) (0xFF & tab[i]) == df.getFloat(i));
			assertTrue((int) (0xFF & tab[i]) == di.getInt(i));
			assertTrue((long) (0xFF & tab[i]) == dl.getLong(i));
			assertTrue((short) (0xFF & tab[i]) == ds.getShort(i));
		}

		try {
			d.getBoolean(0);
			assertTrue(false, "getting a boolean on a DataBufferUnsignedByte should be imposible");
		} catch (IllegalAccessError i) {
		}

	}

	@Override
	@Test
	public void testClone() {
		DataBufferUnsignedByte d = new DataBufferUnsignedByte(tab);
		DataBufferUnsignedByte dd = d.clone();
		assertFalse(d == dd, "A cloned object cannot have the same reference");
		for (int i = d.getSize() - 1; i >= 0; i--) {
			assertTrue(d.getByte(i) == dd.getByte(i));
		}
	}

	@Override
	@Test
	public void getData() {
		DataBufferUnsignedByte d = new DataBufferUnsignedByte(tab);
		assertTrue(d.getData() == tab);
	}

	@Override
	@Test
	public void setData() {
		DataBufferUnsignedByte d = new DataBufferUnsignedByte(0);
		d.setData(tab);
		DataBufferUnsignedByte dd = new DataBufferUnsignedByte(0);
		dd.setData(d.clone());
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getByte(i));
			assertTrue(tab[i] == dd.getByte(i));
		}

		boolean tbool[] = testDataBufferBool.getTab(size);
		d.setData(tbool);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tbool[i] == (d.getByte(i) % 2 == 0) ? false : true);
		}
		tbool = null;

		char tc[] = testDataBufferChar.getTab(size);
		d.setData(tc);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) tc[i] == d.getByte(i));
		}
		tc = null;

		double td[] = testDataBufferDouble.getTab(size);
		d.setData(td);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) td[i] == d.getByte(i));
		}
		td = null;

		float tf[] = testDataBufferFloat.getTab(size);
		d.setData(tf);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) tf[i] == d.getByte(i));
		}
		tf = null;

		int ti[] = testDataBufferInt.getTab(size);
		d.setData(ti);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) ti[i] == d.getByte(i));
		}
		ti = null;

		long tl[] = testDataBufferLong.getTab(size);
		d.setData(tl);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) tl[i] == d.getByte(i));
		}
		tl = null;

		short ts[] = testDataBufferShort.getTab(size);
		d.setData(ts);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue((byte) ts[i] == d.getByte(i));
		}
		ts = null;

		d = new DataBufferUnsignedByte(0);
		try {
			d.setData(Double.valueOf(0.0));
			assertTrue(false, "setting any object other than numeric buffer on a DataBufferUnsignedByte should be imposible");
		} catch (IllegalArgumentException i) {
		}

	}

	@Override
	@Test
	public void insertData() {
		byte tab2[] = getTab(size);

		DataBufferUnsignedByte d = new DataBufferUnsignedByte(tab);
		DataBufferUnsignedByte dd = new DataBufferUnsignedByte(tab2);
		d.insertData(d.getSize(), dd);
		assertTrue(d.getSize() == dd.getSize() * 2);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab[i] == d.getByte(i));
		}
		for (int i = size * 2 - 1; i >= size; i--) {
			assertTrue(tab2[i - size] == d.getByte(i));
		}
		d.insertData(0, dd);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == d.getByte(i));
		}

		dd.insertValues(dd.getSize(), 10);
		assertTrue(dd.getSize() == tab.length + 10);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == dd.getByte(i));
		}
		dd.insertValues(0, 10);
		assertTrue(dd.getSize() == tab.length + 20);
		for (int i = size - 1; i >= 0; i--) {
			assertTrue(tab2[i] == dd.getByte(i + 10));
		}
	}

	@Override
	@Test
	public void removeValues() {
		DataBufferUnsignedByte d = new DataBufferUnsignedByte(tab);
		d.removeValues(0, 10);
		assertTrue(d.getSize() == 40);
		for (int i = 9; i >= 0; i--) {
			assertTrue(tab[i + 10] == d.getByte(i));
		}
		d = new DataBufferUnsignedByte(tab);
		d.removeValues(d.getSize() - 10, 10);
		assertTrue(d.getSize() == 40);
		for (int i = 9; i >= 0; i--) {
			assertTrue(tab[i] == d.getByte(i));
		}

		d = new DataBufferUnsignedByte(tab);
		try {
			d.removeValues(0, size + 10);
			assertTrue(false);
		} catch (Exception e) {
			assertTrue(true);
		}

		d = new DataBufferUnsignedByte(tab);
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

		DataBufferUnsignedByte d = new DataBufferUnsignedByte(tab);
		boolean ok = true;

		try {
			fOut = new FileOutputStream(".test_databufferbyte.dat");
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
			fIn = new FileInputStream(".test_databufferbyte.dat");
			oIn = new ObjectInputStream(fIn);
			DataBufferUnsignedByte dd = (DataBufferUnsignedByte) oIn.readObject();
			assertTrue(dd.getSize() == d.getSize());
			for (int i = d.getSize() - 1; i >= 0; i--) {
				assertTrue(d.getByte(i) == dd.getByte(i));
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
				java.io.File f = new File(".test_databufferbyte.dat");
				assertTrue(f.delete());
			} catch (IOException e1) {
				e1.printStackTrace();
				ok = false;
			}
		}
		assertTrue(ok);

	}

}
