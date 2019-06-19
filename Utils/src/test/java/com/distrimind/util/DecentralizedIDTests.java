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
package com.distrimind.util;

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.EnumSet;

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.MessageDigestType;
import com.distrimind.util.crypto.SecureRandomType;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * 
 */
public class DecentralizedIDTests {
	private static final int numberofTests = 2000;

	@DataProvider(name = "getDEncetralizedIDs", parallel = true)
	public Object[][] getDEncetralizedIDs() throws NoSuchAlgorithmException, NoSuchProviderException {
		Object[][] res = new Object[numberofTests][];
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (int i = 0; i < res.length; i++) {
			switch ((int) (Math.random() * 16)) {
			case 0:
				res[i] = new Object[] { new DecentralizedIDGenerator(true, true) };
				break;
			case 1:
				res[i] = new Object[] { new RenforcedDecentralizedIDGenerator(true, true) };
				break;
			case 2:
				res[i] = new Object[] { new SecuredDecentralizedID(new RenforcedDecentralizedIDGenerator(true, true), rand) };
				break;
			case 3:
				res[i] = new Object[] { new SecuredDecentralizedID(new DecentralizedIDGenerator(true, true), rand) };
				break;
			case 4:
				res[i] = new Object[] { new DecentralizedIDGenerator(false, true) };
				break;
			case 5:
				res[i] = new Object[] { new RenforcedDecentralizedIDGenerator(false, true) };
				break;
			case 6:
				res[i] = new Object[] { new SecuredDecentralizedID(new RenforcedDecentralizedIDGenerator(false, true), rand) };
				break;
			case 7:
				res[i] = new Object[] { new SecuredDecentralizedID(new DecentralizedIDGenerator(false, true), rand) };
				break;
			case 8:
				res[i] = new Object[] { new DecentralizedIDGenerator(true, false) };
				break;
			case 9:
				res[i] = new Object[] { new RenforcedDecentralizedIDGenerator(true, false) };
				break;
			case 10:
				res[i] = new Object[] { new SecuredDecentralizedID(new RenforcedDecentralizedIDGenerator(true, false), rand) };
				break;
			case 11:
				res[i] = new Object[] { new SecuredDecentralizedID(new DecentralizedIDGenerator(true, false), rand) };
				break;
			case 12:
				res[i] = new Object[] { new DecentralizedIDGenerator(false, false) };
				break;
			case 13:
				res[i] = new Object[] { new RenforcedDecentralizedIDGenerator(false, false) };
				break;
			case 14:
				res[i] = new Object[] { new SecuredDecentralizedID(new RenforcedDecentralizedIDGenerator(false, false), rand) };
				break;
			case 15:
				res[i] = new Object[] { new SecuredDecentralizedID(new DecentralizedIDGenerator(false, false), rand) };
				break;
				
			}
		}
		return res;
	}

	@Test
	public void testDecentralizedID() throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (MessageDigestType type : EnumSet.allOf(MessageDigestType.class)) {
			testDecentralizedID(type, rand);
		}
	}

	public void testDecentralizedID(MessageDigestType type, AbstractSecureRandom rand) throws NoSuchAlgorithmException, NoSuchProviderException {
		for (int i = 0; i < numberofTests; i++) {
			testEquals(type, rand, new DecentralizedIDGenerator(), new DecentralizedIDGenerator());

		}
	}

	private void testEquals(MessageDigestType type, AbstractSecureRandom rand, AbstractDecentralizedIDGenerator id1,
			AbstractDecentralizedIDGenerator id2) throws NoSuchAlgorithmException, NoSuchProviderException {
		Assert.assertNotEquals(id1, id2);
		SecuredDecentralizedID sid1 = new SecuredDecentralizedID(type, id1, rand);
		SecuredDecentralizedID sid2 = new SecuredDecentralizedID(type, id2, rand);
		Assert.assertNotEquals(sid1, sid2);
		Assert.assertNotEquals(DecentralizedValue.decode(id1.encode()),
				DecentralizedValue.decode(id2.encode()));
		Assert.assertNotEquals(DecentralizedValue.decode(sid1.encode()),
				DecentralizedValue.decode(sid2.encode()));
	}

	@Test(dataProvider = "getDEncetralizedIDs", dependsOnMethods = "testToBytes")
	public void testNotEquals(AbstractDecentralizedID id) throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		Assert.assertNotEquals(id, new DecentralizedIDGenerator());
		Assert.assertNotEquals(id, new RenforcedDecentralizedIDGenerator());
		Assert.assertNotEquals(id, new SecuredDecentralizedID(new DecentralizedIDGenerator(), rand));
		Assert.assertNotEquals(id, new SecuredDecentralizedID(new RenforcedDecentralizedIDGenerator(), rand));
	}

	@Test
	public void testRenforcedDecentralizedID() throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (MessageDigestType type : EnumSet.allOf(MessageDigestType.class)) {
			testRenforcedDecentralizedID(type, rand);
		}
	}

	public void testRenforcedDecentralizedID(MessageDigestType type, AbstractSecureRandom rand)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		for (int i = 0; i < numberofTests; i++) {
			testEquals(type, rand, new RenforcedDecentralizedIDGenerator(), new RenforcedDecentralizedIDGenerator());
		}
	}

	@Test(dataProvider = "getDEncetralizedIDs")
	public void testToBytes(AbstractDecentralizedID id) {
		byte[] bytes = id.encode();
		AbstractDecentralizedID id2 = (AbstractDecentralizedID)DecentralizedValue.decode(bytes);
		Assert.assertEquals(id, id2);
		Assert.assertEquals(id.hashCode(), id2.hashCode());
		Assert.assertEquals(bytes, id2.encode());
	}

	@Test
	public void testToStringAndValueOf() throws NoSuchAlgorithmException, NoSuchProviderException {
		testToStringAndValueOf(new DecentralizedIDGenerator());
		testToStringAndValueOf(new RenforcedDecentralizedIDGenerator());
		testToStringAndValueOf(
				new SecuredDecentralizedID(new DecentralizedIDGenerator(), SecureRandomType.DEFAULT.getSingleton(null)));
	}

	void testToStringAndValueOf(DecentralizedIDGenerator value) {
		Assert.assertEquals(DecentralizedIDGenerator.valueOf(value.toString()), value);
	}

	void testToStringAndValueOf(RenforcedDecentralizedIDGenerator value) {
		Assert.assertEquals(RenforcedDecentralizedIDGenerator.valueOf(value.toString()), value);
	}

	void testToStringAndValueOf(SecuredDecentralizedID value) {
		Assert.assertEquals(SecuredDecentralizedID.valueOf(value.toString()), value);
	}
}
