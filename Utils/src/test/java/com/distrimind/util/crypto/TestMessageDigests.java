package com.distrimind.util.crypto;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.7.0
 */
public class TestMessageDigests {
	@Test(dataProvider = "provideMessageDigestType")
	public void testMessageDigest(MessageDigestType type) throws NoSuchAlgorithmException, NoSuchProviderException {
		System.out.println("Testing message digest " + type);

		AbstractMessageDigest md = type.getMessageDigestInstance();
		for (byte[] m : VariousTests.messagesToEncrypt) {
			byte[] b1 = md.digest(m);
			md.reset();
			byte[] b2 = md.digest(m);

			Assert.assertEquals(b1, b2);

		}

	}





	@Test(dataProvider = "providePasswordHashTypes")
	public void testPasswordHash(PasswordHashType type) throws IOException {
		SecureRandom random = new SecureRandom();
		PasswordHash ph = new PasswordHash(type, random);
		String password = "password";
		String invalidPassword = "invalid password";
		ph.setCost((byte)7);
		byte[] hashedValue = ph.hash(password);
		Assert.assertTrue(PasswordHash.checkValidHashedPassword(password, hashedValue));
		Assert.assertFalse(PasswordHash.checkValidHashedPassword(invalidPassword, hashedValue));
		Assert.assertEquals(PasswordHashType.getPasswordHashLengthBytes(hashedValue), type.getDefaultHashLengthBytes());
		Assert.assertEquals(PasswordHashType.getSaltSizeBytes(hashedValue), ph.getSaltSizeBytes());
		byte[] staticSalt = new byte[20];
		random.nextBytes(staticSalt);
		hashedValue = ph.hash(password, staticSalt);
		Assert.assertTrue(PasswordHash.checkValidHashedPassword(password, hashedValue, staticSalt));
		Assert.assertFalse(PasswordHash.checkValidHashedPassword(password, hashedValue));
		Assert.assertFalse(PasswordHash.checkValidHashedPassword(invalidPassword, hashedValue, staticSalt));
	}

	@DataProvider(name = "provideMessageDigestType", parallel = true)
	public Object[][] provideMessageDigestType() {
		Object[][] res = new Object[MessageDigestType.values().length][];
		int i = 0;
		for (MessageDigestType v : MessageDigestType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}

	@DataProvider(name = "providePasswordHashTypes", parallel = true)
	public Object[][] providePasswordHashTypes() {
		Object[][] res = new Object[PasswordHashType.values().length][1];
		int index = 0;
		for (PasswordHashType type : PasswordHashType.values()) {
			res[index++][0] = type;
		}
		return res;
	}
}
