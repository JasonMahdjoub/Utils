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
package com.distrimind.util.crypto;

import com.distrimind.util.Bits;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 4.7.0
 */
public class VariousTests {
	static final byte[][] messagesToEncrypt;

	static final byte[] salt;
	static {
		System.out.println("Generatring messages");
		Random rand = new Random(System.currentTimeMillis());
		messagesToEncrypt = new byte[30][];
		for (int i = 0; i < messagesToEncrypt.length; i++) {
			byte[] b = new byte[96 + rand.nextInt(20000)];
			for (int j = 0; j < b.length; j++)
				b[j] = (byte) rand.nextInt();

			messagesToEncrypt[i] = b;
		}
		salt = new byte[rand.nextInt(10) + 30];
		for (int j = 0; j < salt.length; j++)
			salt[j] = (byte) rand.nextInt();

	}

	static final int[] keySizes = { 1024, 2048, 3072, 4096 };
	static byte[] testSignature(AbstractAuthenticatedSignerAlgorithm signer, AbstractAuthenticatedCheckerAlgorithm checker) throws IllegalStateException, IOException
	{
		byte[] m = new byte[100000];
		Random r=new Random(System.currentTimeMillis());
		r.nextBytes(m);

		byte[] signature = signer.sign(m);
		if (signer instanceof SymmetricAuthenticatedSignerAlgorithm)
			Assert.assertEquals(signer.getMacLengthBytes(), signature.length);
		Assert.assertTrue(checker.verify(m, signature));
		Assert.assertTrue(checker.verify(m, signature));
		Assert.assertTrue(checker.verify(m, 0, m.length, signature, 0, signature.length));

		for (int i = 0; i < m.length; i++) {
			m[i] = (byte) ~m[i];
		}

		Assert.assertFalse(checker.verify(m, signature));
		return signature;

	}

	@DataProvider(name = "provideSecureRandomType", parallel = true)
	public Object[][] provideSecureRandomType() {
		Object[][] res = new Object[SecureRandomType.values().length][];
		int i = 0;
		for (SecureRandomType v : SecureRandomType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}


	@Test(invocationCount = 20, threadPoolSize = 16)
	public void testEncodeAndSeparateEncoding() {
		Random rand = new Random(System.currentTimeMillis());
		byte[] t1 = new byte[rand.nextInt(100) + 20];
		byte[] t2 = new byte[rand.nextInt(100) + 20];
		byte[] encoded = Bits.concatenateEncodingWithShortSizedTabs(t1, t2);
		byte[][] decoded = Bits.separateEncodingsWithShortSizedTabs(encoded);
		Assert.assertEquals(t1, decoded[0]);
		Assert.assertEquals(t2, decoded[1]);
		encoded = Bits.concatenateEncodingWithIntSizedTabs(t1, t2);
		decoded = Bits.separateEncodingsWithIntSizedTabs(encoded);
		Assert.assertEquals(t1, decoded[0]);
		Assert.assertEquals(t2, decoded[1]);
	}






	@Test(dataProvider = "provideSecureRandomType")
	public void testSecureRandom(SecureRandomType type) throws NoSuchAlgorithmException, NoSuchProviderException {
		AbstractSecureRandom random;
		System.out.println("Test "+type);
		random = type.getSingleton("nonce".getBytes(), "parameter".getBytes());
		System.out.println(type+" instantiated");
		random.nextBytes(new byte[10]);
		if (type!=SecureRandomType.NativePRNG && type!=SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NATIVE_PRNG && type!=SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG && type!=SecureRandomType.GNU_DEFAULT && type!=SecureRandomType.SHA1PRNG && type.getProvider()!=CodeProvider.BCFIPS)
		{
			
			int nb= 110000;
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
			random.nextBytes(new byte[nb]);
		}
		System.out.println("End test "+type);
	}


	



	
	@Test(invocationCount = 4000, threadPoolSize = 16)
	public void testReadWriteDataPackaged() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		Random rand = new Random(System.currentTimeMillis());
		byte[] originalBytes = new byte[50 + rand.nextInt(10000)];
		rand.nextBytes(originalBytes);
		int randNb = rand.nextInt(10000);
		byte[] encodedBytes = OutputDataPackagerWithRandomValues.encode(originalBytes, randNb);
		// Assert.assertTrue(encodedBytes.length>originalBytes.length);
		Assert.assertTrue(encodedBytes.length >= originalBytes.length, "invalid size : " + encodedBytes.length
				+ " (originalBytes size=" + originalBytes.length + ", randNb=" + randNb + ") ");
		byte[] decodedBytes = InputDataPackagedWithRandomValues.decode(encodedBytes);
		Assert.assertEquals(decodedBytes.length, originalBytes.length);
		for (int i = 0; i < decodedBytes.length; i++)
			Assert.assertEquals(decodedBytes[i], originalBytes[i]);
	}

	



}
