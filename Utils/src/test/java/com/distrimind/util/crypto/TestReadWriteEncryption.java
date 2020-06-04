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

import com.distrimind.util.io.*;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.16.0
 */
public class TestReadWriteEncryption {

	@DataProvider(name = "provideParameters", parallel = false)
	public Object[][] provideParameters() throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
		Random rand=new Random(System.currentTimeMillis());
		Object[][] res=new Object[32][5];
		int i=0;
		for (SymmetricSecretKey ske : new SymmetricSecretKey[]{
				SymmetricEncryptionType.AES_CTR.getKeyGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKey(),
				null
		})
		{
			for (byte[] associatedData : new byte[][]{
					null,
					new byte[100]
			})
			{
				if (associatedData!=null) {
					rand.nextBytes(associatedData);
					if (ske!=null)
						ske = SymmetricEncryptionType.AES_GCM.getKeyGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKey();
				}
				for (SymmetricSecretKey sks : new SymmetricSecretKey[]{
						SymmetricAuthentifiedSignatureType.DEFAULT.getKeyGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKey(),
						null
				})
				{
					for (ASymmetricKeyPair kp : new ASymmetricKeyPair[]{
							ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed25519.getKeyPairGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKeyPair(),
							null
					})
					{
						for (MessageDigestType md : new MessageDigestType[]{
								MessageDigestType.DEFAULT,
								null
						})
						{
							res[i][0]=ske;
							res[i][1]=associatedData;
							res[i][2]=(ske!=null && ske.getEncryptionAlgorithmType().isAuthenticatedAlgorithm())?null:sks;
							res[i][3]=kp;
							res[i][4]=md;
							++i;
						}
					}
				}
			}
		}
		return res;
	}

	@Test(dataProvider = "provideParameters")
	public void testEncryption(SymmetricSecretKey secretKeyForEncryption, byte[] associatedData, SymmetricSecretKey secretKeyForSignature, ASymmetricKeyPair keyPairForSignature, MessageDigestType messageDigestType) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
		System.out.println("Encryption type : "+(secretKeyForEncryption==null?"null":secretKeyForEncryption.getEncryptionAlgorithmType()));
		Random r=new Random(System.currentTimeMillis());
		byte[] in=new byte[10000*r.nextInt(1000)];
		r.nextBytes(in);
		RandomByteArrayInputStream bais=new RandomByteArrayInputStream(in.clone());
		RandomByteArrayOutputStream baos=new RandomByteArrayOutputStream();
		EncryptionSignatureHashEncoder writer=new EncryptionSignatureHashEncoder();
		writer.withRandomInputStream(bais);
		if (secretKeyForEncryption!=null) {
			writer.withSymmetricSecretKeyForEncryption(SecureRandomType.DEFAULT.getInstance(null), secretKeyForEncryption);
			if (associatedData!=null)
				writer.withAssociatedData(associatedData);
		}
		if (secretKeyForSignature!=null)
			writer.withSymmetricSecretKeyForSignature(secretKeyForSignature);
		if (keyPairForSignature!=null)
			writer.withASymmetricPrivateKeyForSignature(keyPairForSignature.getASymmetricPrivateKey());
		if (messageDigestType!=null)
			writer.withMessageDigestType(messageDigestType);
		long expectedLength=writer.getMaximumOutputLength();
		writer.encode(baos);
		byte[] res=baos.getBytes();
		Assert.assertTrue(expectedLength>=res.length, "expectedLength="+expectedLength+", actual="+res.length);
		bais=new RandomByteArrayInputStream(res.clone());
		baos=new RandomByteArrayOutputStream();
		EncryptionSignatureHashDecoder reader=getReader(bais, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		expectedLength=reader.getMaximumOutputLength(bais.length());
		reader.decodeAndCheckHashAndSignaturesIfNecessary(baos);
		Assert.assertEquals(baos.getBytes(), in);
		Assert.assertTrue(expectedLength>=in.length);
		Assert.assertEquals(reader.checkHashAndSignature(), Integrity.OK);
		Assert.assertEquals(reader.checkHashAndPublicSignature(), Integrity.OK);
		long s;
		SubStreamParameters ssp=null;
		SubStreamHashResult sshr;
		if (secretKeyForEncryption==null || secretKeyForEncryption.getEncryptionAlgorithmType().supportRandomReadWrite()) {
			ssp = new SubStreamParameters(MessageDigestType.DEFAULT, Arrays.asList(
					new SubStreamParameter(s = r.nextInt(8), s + 12 + r.nextInt(10)),
					new SubStreamParameter(s = r.nextInt(100) + 200, s + 10 + r.nextInt(10)),
					new SubStreamParameter(s = r.nextInt(100) + 1000, s + 10 + r.nextInt(10)),
					new SubStreamParameter(s = r.nextInt(100) + 2000, s + 10 + r.nextInt(10))
			));
			sshr = reader.computePartialHash(ssp);
			Assert.assertTrue(writer.checkPartialHash(ssp, sshr));
		}
		sshr=testFail(res, 8, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, ssp);
		if (ssp!=null) {
			Assert.assertFalse(writer.checkPartialHash(ssp, sshr));
		}
		testFail(res, 65, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, null);
		testFail(res, res.length-10, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, null);
		testFail(res, res.length-40, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, null);
		testFail(res, res.length-70, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, null);
		testFail(res, res.length-100, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, null);

		if (secretKeyForEncryption!=null) {
			testBadParameters(res, null, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType, false, false, false);
			if (associatedData!=null) {
				testBadParameters(res, secretKeyForEncryption, null, secretKeyForSignature, keyPairForSignature, messageDigestType, false, secretKeyForSignature!=null, false);
				byte code=EncryptionSignatureHashEncoder.getCode(null, secretKeyForSignature, keyPairForSignature, messageDigestType);
				testTruncateCode(code,res, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
			}

		}
		if (secretKeyForSignature!=null) {
			testBadParameters(res, secretKeyForEncryption, associatedData, null, keyPairForSignature, messageDigestType, false, true, false);
			byte code = EncryptionSignatureHashEncoder.getCode(associatedData, null, keyPairForSignature, messageDigestType);
			testTruncateCode(code, res, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		}
		if (keyPairForSignature!=null) {
			testBadParameters(res, secretKeyForEncryption, associatedData, secretKeyForSignature, null, messageDigestType, false, false, true);
			byte code = EncryptionSignatureHashEncoder.getCode(associatedData, secretKeyForSignature, null, messageDigestType);
			testTruncateCode(code, res, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		}
		if (messageDigestType!=null) {
			testBadParameters(res, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, null, true, false, false);
			byte code = EncryptionSignatureHashEncoder.getCode(associatedData, secretKeyForSignature, keyPairForSignature, null);
			testTruncateCode(code, res, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		}

	}

	private EncryptionSignatureHashDecoder getReader(RandomByteArrayInputStream bais, SymmetricSecretKey secretKeyForEncryption, byte[] associatedData, SymmetricSecretKey secretKeyForSignature, ASymmetricKeyPair keyPairForSignature, MessageDigestType messageDigestType) throws IOException, NoSuchProviderException, NoSuchAlgorithmException {
		EncryptionSignatureHashDecoder reader=new EncryptionSignatureHashDecoder();
		reader.withRandomInputStream(bais);
		if (secretKeyForEncryption!=null) {
			reader.withSymmetricSecretKeyForEncryption(SecureRandomType.DEFAULT.getInstance(null), secretKeyForEncryption);
			if (associatedData!=null)
				reader.withAssociatedData(associatedData);
		}
		if (secretKeyForSignature!=null)
			reader.withSymmetricSecretKeyForSignature(secretKeyForSignature);
		if (keyPairForSignature!=null)
			reader.withASymmetricPublicKeyForSignature(keyPairForSignature.getASymmetricPublicKey());
		if (messageDigestType!=null)
			reader.withMessageDigestType(messageDigestType);
		return reader;
	}

	private SubStreamHashResult testFail(byte[] res, int indexModif, SymmetricSecretKey secretKeyForEncryption, byte[] associatedData, SymmetricSecretKey secretKeyForSignature, ASymmetricKeyPair keyPairForSignature, MessageDigestType messageDigestType, SubStreamParameters ssp) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		byte[] ed=res.clone();
		ed[indexModif]=(byte)(~ed[indexModif]);
		RandomByteArrayInputStream bais=new RandomByteArrayInputStream(ed);
		RandomByteArrayOutputStream baos=new RandomByteArrayOutputStream();
		EncryptionSignatureHashDecoder reader=getReader(bais, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		try {
			reader.decodeAndCheckHashAndSignaturesIfNecessary(baos);
			if (messageDigestType!=null || keyPairForSignature!=null || secretKeyForSignature!=null)
				Assert.fail();
		}
		catch(IOException ignored)
		{
		}
		if (messageDigestType!=null || keyPairForSignature!=null || secretKeyForSignature!=null) {
			Assert.assertNotEquals(reader.checkHashAndSignature(), Integrity.OK);
		}
		if (messageDigestType!=null || keyPairForSignature!=null) {
			Assert.assertNotEquals(reader.checkHashAndPublicSignature(), Integrity.OK, "");
		}
		if (ssp!=null)
			return reader.computePartialHash(ssp);
		else
			return null;
	}

	private void testBadParameters(byte[] res, SymmetricSecretKey secretKeyForEncryption, byte[] associatedData, SymmetricSecretKey secretKeyForSignature, ASymmetricKeyPair keyPairForSignature, MessageDigestType messageDigestType, boolean changeHash, boolean changeSymSig, boolean changeASymSig) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		byte[] ed=res.clone();
		RandomByteArrayInputStream bais=new RandomByteArrayInputStream(ed);
		RandomByteArrayOutputStream baos=new RandomByteArrayOutputStream();
		EncryptionSignatureHashDecoder reader=getReader(bais, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		boolean symError=false;
		try {
			reader.decodeAndCheckHashAndSignaturesIfNecessary(baos);
			Assert.fail(""+Arrays.toString(associatedData)+" ; "+ed[0]);
		}
		catch(NullPointerException e)
		{
			symError=e.getMessage().equals("symmetricChecker");
		}

		if (messageDigestType!=null || keyPairForSignature!=null || secretKeyForSignature!=null) {
			if (changeHash || changeSymSig || changeASymSig)
				Assert.assertNotEquals(reader.checkHashAndSignature(), Integrity.OK);
			else
				Assert.assertEquals(reader.checkHashAndSignature(), Integrity.OK);
		}
		if (!symError && (messageDigestType!=null || keyPairForSignature!=null)) {
			if (changeHash || changeASymSig)
				Assert.assertNotEquals(reader.checkHashAndPublicSignature(), Integrity.OK, "");
			else
				Assert.assertEquals(reader.checkHashAndPublicSignature(), Integrity.OK, "");
		}
	}
	private void testTruncateCode(byte code, byte[] res, SymmetricSecretKey secretKeyForEncryption, byte[] associatedData, SymmetricSecretKey secretKeyForSignature, ASymmetricKeyPair keyPairForSignature, MessageDigestType messageDigestType) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		byte[] ed=res.clone();
		ed[0]=code;
		RandomByteArrayInputStream bais=new RandomByteArrayInputStream(ed);
		RandomByteArrayOutputStream baos=new RandomByteArrayOutputStream();
		EncryptionSignatureHashDecoder reader=getReader(bais, secretKeyForEncryption, associatedData, secretKeyForSignature, keyPairForSignature, messageDigestType);
		boolean symError=false;
		try {
			reader.decodeAndCheckHashAndSignaturesIfNecessary(baos);
			Assert.fail();
		}
		catch(MessageExternalizationException e)
		{
			symError=e.getMessage().equals("symmetricChecker");
		}
		if (messageDigestType!=null || keyPairForSignature!=null || secretKeyForSignature!=null) {
			Assert.assertNotEquals(reader.checkHashAndSignature(), Integrity.OK);
		}
		if (!symError && (messageDigestType!=null || keyPairForSignature!=null)) {
			Assert.assertNotEquals(reader.checkHashAndPublicSignature(), Integrity.OK, "");
		}
	}
}
