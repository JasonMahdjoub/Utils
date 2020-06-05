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

import com.distrimind.util.DecentralizedValue;
import com.distrimind.util.io.RandomByteArrayInputStream;
import com.distrimind.util.io.RandomInputStream;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.7.0
 */
public class TestsForSymmetricEncryption {
	@Test(dataProvider = "provideDataForSymetricEncryptions")
	public void testSecretKeyEncoding(SymmetricEncryptionType type) throws NoSuchAlgorithmException,
			NoSuchProviderException,
			IllegalArgumentException, IOException {
		System.out.println("Testing " + type);
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey key = type.getKeyGenerator(random).generateKey();
		Assert.assertEquals(DecentralizedValue.decode(key.encode()), key);
		new SymmetricEncryptionAlgorithm(random, key);
		Assert.assertEquals(DecentralizedValue.decode(key.encode()), key);
		Assert.assertEquals(DecentralizedValue.valueOf(key.encodeString()), key);
		SymmetricSecretKeyPair keyPair=key.getDerivedSecretKeyPair(MessageDigestType.BC_FIPS_SHA3_512, SymmetricAuthentifiedSignatureType.HMAC_SHA2_256);
		Assert.assertEquals(DecentralizedValue.decode(keyPair.encode()), keyPair);
		Assert.assertEquals(DecentralizedValue.valueOf(keyPair.encodeString()), keyPair);

	}



	@Test(dataProvider = "provideDataForSymetricEncryptions")
	public void testSymmetricEncryptions(SymmetricEncryptionType type) throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		testSymmetricEncryptionsCompatibility(type, type);

	}

	@Test(dependsOnMethods = {"testSymmetricEncryptions"})
	public void testSymmetricKeyPair() throws NoSuchProviderException, NoSuchAlgorithmException {
		SymmetricAuthentifiedSignatureType sigType=SymmetricAuthentifiedSignatureType.HMAC_SHA2_256;
		SymmetricSecretKey ke=SymmetricEncryptionType.DEFAULT.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), (short)256).generateKey();
		SymmetricSecretKeyPair ske=ke.getDerivedSecretKeyPair(MessageDigestType.BC_FIPS_SHA3_512, sigType);
		Assert.assertEquals(ke.getEncryptionAlgorithmType(), ske.getSecretKeyForEncryption().getEncryptionAlgorithmType());
		Assert.assertEquals(sigType, ske.getSecretKeyForSignature().getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(ske.getSecretKeyForEncryption().getKeySizeBits(), ke.getKeySizeBits());
		Assert.assertEquals(ske.getSecretKeyForSignature().getKeySizeBits(), ke.getKeySizeBits());
		Assert.assertNotEquals(ske.getSecretKeyForEncryption().getKeyBytes(), ke.getKeyBytes());
		System.out.println(ske);
	}

	@Test(dataProvider = "provideDataForTestSymmetricEncryptionCompatibility", dependsOnMethods = "testSymmetricEncryptions")
	public void testSymmetricEncryptionsCompatibility(SymmetricEncryptionType type1, SymmetricEncryptionType type2) throws NoSuchAlgorithmException,
			IOException,
			NoSuchProviderException, IllegalStateException {
		System.out.println("Testing " + type1+", "+type2);
		AbstractSecureRandom random = SecureRandomType.DEFAULT.getSingleton(null);

		SymmetricSecretKey key1 = type1.getKeyGenerator(random).generateKey();
		SymmetricSecretKey key2;

		if (type2.getCodeProviderForEncryption()!=CodeProvider.GNU_CRYPTO && type2.getCodeProviderForEncryption()!=CodeProvider.BC && type2.getCodeProviderForEncryption()==CodeProvider.BCFIPS)
			key2=new SymmetricSecretKey(type2, key1.toJavaNativeKey(), key1.getKeySizeBits());
		else
			key2=new SymmetricSecretKey(type2, key1.getKeyBytes(), key1.getKeySizeBits());

		byte counterSizeBytes=(byte)random.nextInt(key1.getEncryptionAlgorithmType().getMaxCounterSizeInBytesUsedWithBlockMode()+1);
		SymmetricEncryptionAlgorithm algoDistant;
		if (type1.isBlockModeSupportingCounter())
		{
			algoDistant = new SymmetricEncryptionAlgorithm(random, key1, counterSizeBytes, true);
			Assert.assertEquals(algoDistant.getBlockModeCounterBytes(), counterSizeBytes);
			Assert.assertFalse(algoDistant.useExternalCounter());
			/*Assert.assertEquals(algoDistant.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);
			Assert.assertEquals(algoDistant.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);*/
			Assert.assertEquals(algoDistant.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes());
			Assert.assertEquals(algoDistant.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes());
		}


		algoDistant = new SymmetricEncryptionAlgorithm(random, key1, counterSizeBytes, false);
		algoDistant.setMaxPlainTextSizeForEncoding(1024);
		Assert.assertEquals(algoDistant.getBlockModeCounterBytes(), counterSizeBytes);
		Assert.assertEquals(algoDistant.useExternalCounter(), counterSizeBytes>0);
		Assert.assertEquals(algoDistant.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes());
		Assert.assertEquals(algoDistant.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);
		SymmetricEncryptionAlgorithm algoLocal = new SymmetricEncryptionAlgorithm(random, key2, counterSizeBytes, false);
		algoLocal.setMaxPlainTextSizeForEncoding(1024);
		Assert.assertEquals(algoLocal.getBlockModeCounterBytes(), counterSizeBytes);
		Assert.assertEquals(algoLocal.useExternalCounter(), counterSizeBytes>0);
		Assert.assertEquals(algoLocal.getIVSizeBytesWithExternalCounter(), type1.getIVSizeBytes());
		Assert.assertEquals(algoLocal.getIVSizeBytesWithoutExternalCounter(), type1.getIVSizeBytes()-counterSizeBytes);



		byte[] counter=algoDistant.useExternalCounter()?new byte[counterSizeBytes]:null;
		Random rand = new Random(System.currentTimeMillis());

		for (byte[] m : VariousTests.messagesToEncrypt) {
			if (counter!=null)
				rand.nextBytes(counter);
			int mlength=m.length;
			long expectedLength=algoLocal.getOutputSizeAfterEncryption(mlength);
			byte[] encrypted = algoLocal.encode(m, null, counter);


			Assert.assertEquals(encrypted.length, expectedLength, "length=" + m.length);

			Assert.assertTrue(encrypted.length >= m.length);
			byte[] decrypted = algoDistant.decode(encrypted, null, counter);
			Assert.assertEquals(decrypted.length, m.length, "Testing size " + type1+", "+type2);
			Assert.assertEquals(decrypted, m, "Testing " + type1+", "+type2+", useExternalCounter="+algoLocal.useExternalCounter());
			if (algoLocal.supportRandomEncryptionAndRandomDecryption()) {
				RandomInputStream ris = algoDistant.getCipherInputStreamForDecryption(new RandomByteArrayInputStream(encrypted), counter);
				int p = 5 * (type1.getBlockSizeBits() / 8);
				p=Math.min(p, ((m.length-32-algoLocal.getIVSizeBytesWithoutExternalCounter())/algoLocal.getCounterStepInBytes())*algoLocal.getCounterStepInBytes());
				ris.seek(p);
				byte[] b = new byte[32];
				ris.readFully(b);
				for (int i = 0; i < 32; i++)
					Assert.assertEquals(b[i], m[p + i], "pos="+i);
				p = 80 * (type1.getBlockSizeBits() / 8);
				p=Math.min(p, ((m.length-64-algoLocal.getIVSizeBytesWithoutExternalCounter())/algoLocal.getCounterStepInBytes())*algoLocal.getCounterStepInBytes());
				ris.seek(p);
				b = new byte[64];
				ris.readFully(b);
				for (int i = 0; i < 64; i++)
					Assert.assertEquals(b[i], m[p + i], "pos="+i);
			}
			byte[] md = decrypted;
			Assert.assertEquals(md.length, m.length, "Testing size " + type1+", "+type2);
			Assert.assertEquals(md, m, "Testing " + type1+", "+type2);
			mlength=m.length;
			encrypted = algoDistant.encode(m, null, counter);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeAfterEncryption(mlength));
			Assert.assertTrue(encrypted.length >= m.length);
			md = algoLocal.decode(encrypted, null, counter);
			Assert.assertEquals(md.length, m.length, "Testing size " + type1+", "+type2);
			Assert.assertEquals(md, m, "Testing " + type1+", "+type2);

			int off = rand.nextInt(15);
			int size = m.length;
			size -= rand.nextInt(15) + off;

			byte[] associatedData = new byte[random.nextInt(128) + 127];
			if (type1.supportAssociatedData())
				encrypted = algoLocal.encode(m, off, size, associatedData, 0, associatedData.length, counter);
			else
				encrypted = algoLocal.encode(m, off, size, null, 0, 0, counter);

			Assert.assertEquals(encrypted.length, algoLocal.getOutputSizeAfterEncryption(size));
			Assert.assertTrue(encrypted.length >= size);
			if (type1.supportAssociatedData())
				decrypted = algoDistant.decode(encrypted, associatedData, counter);
			else
				decrypted = algoDistant.decode(encrypted, null, counter);
			Assert.assertEquals(decrypted.length, size, "Testing size " + type1+", "+type2);
			Assert.assertTrue(algoDistant.getOutputSizeAfterDecryption(encrypted.length)>=size, "Testing size " + type1+", "+type2);
			for (int i = 0; i < decrypted.length; i++)
				Assert.assertEquals(decrypted[i], m[i + off]);
			if (type1.supportAssociatedData())
				md = algoDistant.decode(encrypted, associatedData, counter);
			else
				md = algoDistant.decode(encrypted, null, counter);

			Assert.assertEquals(md.length, size, "Testing size " + type1+", "+type2);
			Assert.assertTrue(algoDistant.getOutputSizeAfterDecryption(encrypted.length)>=size, "Testing size " + type1+", "+type2);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

			encrypted = algoDistant.encode(m, off, size, null, 0, 0, counter);
			Assert.assertEquals(encrypted.length, algoDistant.getOutputSizeAfterEncryption(size));
			Assert.assertTrue(encrypted.length >= size);

			md = algoLocal.decode(encrypted, null, counter);
			Assert.assertEquals(md.length, size, "Testing size " + type1+", "+type2);
			Assert.assertTrue(algoDistant.getOutputSizeAfterDecryption(encrypted.length)>=size, "Testing size " + type1+", "+type2);
			for (int i = 0; i < md.length; i++)
				Assert.assertEquals(md[i], m[i + off]);

		}

	}



	@Test(dataProvider = "provideDataForSymetricEncryptions")
	public void testBase64(SymmetricEncryptionType encryptionType) throws NoSuchProviderException, NoSuchAlgorithmException {

		SymmetricSecretKey key1=encryptionType.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), encryptionType.getDefaultKeySizeBits()).generateKey();

		Assert.assertEquals(key1.getKeySizeBits(), encryptionType.getDefaultKeySizeBits());
		System.out.println("Key encryption : \n\t"+ Base64.encodeBase64URLSafeString(key1.getKeyBytes()));
		System.out.println("Key encryption (complete): \n\t"+ Base64.encodeBase64URLSafeString(key1.encode()));
		Assert.assertEquals(key1.getKeyBytes().length, encryptionType.getDefaultKeySizeBytes());
	}

	@Test(dataProvider = "getSymmetricSecretKeysToTestForSecretKeyWrappingWithPassword")
	public void testSymmetricSecretKeyWrappingWithPassword(SymmetricKeyWrapperType keyWrapperType, SymmetricSecretKey secretKey) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		String password="MyPassword";
		PasswordHashType passwordHashType=PasswordHashType.BC_SCRYPT_FOR_DATAENCRYPTION;
		byte[] encryptedSecretKey=keyWrapperType.wrapKey(passwordHashType, password, secretKey, SecureRandomType.DEFAULT.getSingleton(null));
		System.out.println("Bytes tab length : "+encryptedSecretKey.length);
		System.out.println(Hex.encodeHexString(encryptedSecretKey));
		SymmetricSecretKey decodedSecretKey=keyWrapperType.unwrapKey(passwordHashType, password, encryptedSecretKey);
		Assert.assertEquals(decodedSecretKey, secretKey);


		String encryptedSecretKeyString=keyWrapperType.wrapKeyString(passwordHashType, password, secretKey, SecureRandomType.DEFAULT.getSingleton(null));
		System.out.println("String length : "+encryptedSecretKeyString.length());
		System.out.println(encryptedSecretKeyString);
		decodedSecretKey=keyWrapperType.unwrapKey(passwordHashType, password, encryptedSecretKeyString);
		Assert.assertEquals(decodedSecretKey, secretKey);

	}

	@DataProvider(name = "getSymmetricSecretKeysToTestForSecretKeyWrappingWithPassword")
	public Object[][] getSymmetricSecretKeysToTestForSecretKeyEncryptionWithPassword() throws NoSuchProviderException, NoSuchAlgorithmException {
		Object[][]res=new Object[4*SymmetricKeyWrapperType.values().length][2];
		int index=0;
		for (boolean encryption : new boolean[]{true, false}) {
			for (short keySize : new short[]{128, 256}) {
				for (SymmetricKeyWrapperType t : SymmetricKeyWrapperType.values()) {
					res[index][0]=t;
					if (encryption) {
						res[index++][1] = SymmetricEncryptionType.AES_CBC_PKCS5Padding.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), keySize).generateKey();
					} else {
						res[index++][1] = SymmetricAuthentifiedSignatureType.HMAC_SHA2_256.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), keySize).generateKey();
					}
				}
			}
		}
		return res;
	}
	@DataProvider(name="provideDataSymmetricKeyWrapperForEncryption")
	public Object[][] provideDataSymmetricKeyWrapperForEncryption()
	{
		Object [][] res=new Object[SymmetricKeyWrapperType.values().length*SymmetricEncryptionType.values().length*SymmetricEncryptionType.values().length][];
		int index=0;
		for (SymmetricKeyWrapperType akpw : SymmetricKeyWrapperType.values())
		{
			for (SymmetricEncryptionType aet : SymmetricEncryptionType.values())
			{
				for (SymmetricEncryptionType set : SymmetricEncryptionType.values())
				{
					if ((akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(aet.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO) && (akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(set.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO)
							&& akpw.getAlgorithmName().startsWith(aet.getAlgorithmName()))
					{
						Object[] params = new Object[3];
						params[0]=akpw;
						params[1]=aet;
						params[2]=set;
						res[index++]=params;
					}
				}
			}
		}
		Object[][] res2 = new Object[index][];
		System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}
	@Test(dataProvider="provideDataSymmetricKeyWrapperForEncryption")
	public void testSymmetricKeyWrapperForEncryption(SymmetricKeyWrapperType typeWrapper, SymmetricEncryptionType asetype, SymmetricEncryptionType setype) throws NoSuchAlgorithmException, IllegalStateException, NoSuchProviderException, IOException {
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey kp=asetype.getKeyGenerator(rand, asetype.getDefaultKeySizeBits()).generateKey();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, setype.getDefaultKeySizeBits()).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(kp, sk, rand);
		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp, wrappedKey);
		Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
		Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());
		Assert.assertEquals(sk.getKeyBytes(), sk2.getKeyBytes());
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
		Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());
	}
	@DataProvider(name="providePasswordKeyDerivationTypesForSymmetricEncryptions", parallel=true)
	public Object[][] providePasswordKeyDerivationTypesForSymmetricEncryptions()
	{
		Object[][] res=new Object[PasswordBasedKeyGenerationType.values().length*SymmetricEncryptionType.values().length][];
		int index=0;
		for (PasswordBasedKeyGenerationType p : PasswordBasedKeyGenerationType.values())
		{
			for (SymmetricEncryptionType s : SymmetricEncryptionType.values())
			{
				if ((p.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(s.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO))
				{
					Object[] params = new Object[2];
					params[0]=p;
					params[1]=s;
					res[index++]=params;
				}
			}
		}
		Object[][] res2 = new Object[index][];
		System.arraycopy(res, 0, res2, 0, index);
		return res2;
	}
	@Test(dataProvider = "providePasswordKeyDerivationTypesForSymmetricEncryptions")
	public void testPasswordKeyDerivation(PasswordBasedKeyGenerationType derivationType, SymmetricEncryptionType encryptionType) throws IOException {
		String password = "password";
		String invalidPassword = "invalid password";
		Random r=new Random(System.currentTimeMillis());
		byte[] salt=new byte[32];
		r.nextBytes(salt);
		SymmetricSecretKey key1=derivationType.derivateKey(password.toCharArray(), salt, (byte)7, encryptionType);
		Assert.assertEquals(key1.getKeySizeBits(), encryptionType.getDefaultKeySizeBits());
		Assert.assertEquals(key1.getEncryptionAlgorithmType(), encryptionType);
		Assert.assertEquals(key1.encode(), derivationType.derivateKey(password.toCharArray(), salt, (byte)7, encryptionType).encode());
		Assert.assertNotEquals(key1.encode(), derivationType.derivateKey(invalidPassword.toCharArray(), salt,(byte) 7, encryptionType).encode());
	}
	@DataProvider(name = "provideDataForTestSymmetricEncryptionCompatibility", parallel = true)
	public Object[][] provideDataForTestSymmetricEncryptionCompatibility() {
		Object[][] res = new Object[][] {
				{SymmetricEncryptionType.AES_CBC_PKCS5Padding, SymmetricEncryptionType.BC_FIPS_AES_CBC_PKCS7Padding},
				{SymmetricEncryptionType.AES_GCM, SymmetricEncryptionType.BC_FIPS_AES_GCM},
				{SymmetricEncryptionType.GNU_AES_CBC_PKCS5Padding, SymmetricEncryptionType.BC_FIPS_AES_CBC_PKCS7Padding},
				{SymmetricEncryptionType.GNU_TWOFISH_CBC_PKCS5Padding, SymmetricEncryptionType.BC_TWOFISH_CBC_PKCS7Padding},
				{SymmetricEncryptionType.GNU_SERPENT_CBC_PKCS5Padding, SymmetricEncryptionType.BC_SERPENT_CBC_PKCS7Padding},
				{SymmetricEncryptionType.GNU_AES_CBC_PKCS5Padding, SymmetricEncryptionType.AES_CBC_PKCS5Padding},
				{SymmetricEncryptionType.CHACHA20_NO_RANDOM_ACCESS, SymmetricEncryptionType.BC_CHACHA20_NO_RANDOM_ACCESS},
				{SymmetricEncryptionType.CHACHA20_POLY1305, SymmetricEncryptionType.BC_CHACHA20_POLY1305}
		};
		Object[][] res2 = new Object[res.length*2][2];
		int j=0;
		for (Object[] re : res) {
			res2[j][0] = re[0];
			res2[j++][1] = re[1];
			res2[j][0] = re[1];
			res2[j++][1] = re[0];
		}
		return res2;
	}
	@DataProvider(name = "provideDataForSymetricEncryptions", parallel = true)
	public Object[][] provideDataForSymetricEncryptions() {
		Object[][] res = new Object[SymmetricEncryptionType.values().length][];
		int i = 0;
		for (SymmetricEncryptionType v : SymmetricEncryptionType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}
}
