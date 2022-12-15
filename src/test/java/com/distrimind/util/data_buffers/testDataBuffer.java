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


import static org.testng.Assert.assertEquals;

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.4
 *
 */
public abstract class testDataBuffer {
	protected abstract DataBuffer getNewDataBuffer(int _size);

	protected abstract int getType();

	protected abstract String getTypeString();

	@Test
	public abstract void testConstructors();

	@Test
	public void getDataType() {
		DataBuffer d = getNewDataBuffer(10);
		assertEquals(d.getDataType(), getType(), "Invalid Data Type (int)");
		d = getNewDataBuffer(0);
		assertEquals(getType(), d.getDataType(), "Invalid Data Type (int)");
	}

	@Test
	public void getDataTypeString() {

		DataBuffer d = getNewDataBuffer(10);
		assertEquals(d.getDataTypeString(), getTypeString(), "Invalid Data Type (String)");
	}

	@Test
	public void setGetSize() {
		try {
			DataBuffer d = getNewDataBuffer(10);
			assertEquals(10, d.getSize(), "Invalid Data Type (String)");
			d.setSize(20);
			assertEquals(20, d.getSize(), "Invalid Data Type (String)");
			d.setSize(5);
			assertEquals(5, d.getSize(), "Invalid Data Type (String)");
			d.setSize(-1);
			Assert.fail();
		} catch (IllegalArgumentException ignored) {

		}
	}

	@Test
	public abstract void testGetsSets();

	@Test
	public abstract void testClone();

	@Test
	public abstract void getData();

	@Test
	public abstract void setData();

	@Test
	public abstract void insertData();

	@Test
	public abstract void removeValues();

	@Test
	public abstract void serialize();

	@Test
	public void testAllToZero() {
		DataBuffer d = getNewDataBuffer(100);
		d.setAllToZero();
		for (int i = d.getSize() - 1; i >= 0; i--) {
			assertEquals(0, d.getInt(i), "Data are not set to zero");
		}
	}

}
