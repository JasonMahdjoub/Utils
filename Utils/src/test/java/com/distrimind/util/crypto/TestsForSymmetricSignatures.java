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

import org.apache.commons.codec.binary.Base64;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.7.0
 */
public class TestsForSymmetricSignatures {
	@Test(dataProvider = "provideDataForSymmetricSignatureTest")
	public void testSymmetricSignatures(SymmetricAuthentifiedSignatureType type, SymmetricSecretKey secretKey)
			throws NoSuchAlgorithmException, InvalidKeyException, SignatureException, InvalidKeySpecException,
			NoSuchProviderException, IllegalStateException, InvalidAlgorithmParameterException, InvalidParameterSpecException, IOException {
		System.out.println("Testing symmetric signature : " + secretKey.getAuthenticatedSignatureAlgorithmType());
		SymmetricAuthenticatedSignerAlgorithm signer = new SymmetricAuthenticatedSignerAlgorithm(secretKey);
		SymmetricAuthenticatedSignatureCheckerAlgorithm checker = new SymmetricAuthenticatedSignatureCheckerAlgorithm(secretKey);
		byte[] signature=VariousTests.testSignature(signer, checker);
		Assert.assertEquals(signature.length*8, secretKey.getAuthenticatedSignatureAlgorithmType().getSignatureSizeInBits());
	}

	@Test(dataProvider = "symmetricSignatures")
	public void testBase64(SymmetricAuthentifiedSignatureType signatureType) throws NoSuchProviderException, NoSuchAlgorithmException {

		SymmetricSecretKey key1=signatureType.getKeyGenerator(SecureRandomType.DEFAULT.getSingleton(null), signatureType.getDefaultKeySizeBits()).generateKey();

		Assert.assertEquals(key1.getKeySizeBits(), signatureType.getDefaultKeySizeBits());
		System.out.println("Key encryption : \n\t"+ Base64.encodeBase64URLSafeString(key1.getKeyBytes()));
		System.out.println("Key encryption (complete): \n\t"+ Base64.encodeBase64URLSafeString(key1.encode()));
		Assert.assertEquals(key1.getKeyBytes().length, signatureType.getDefaultKeySizeBytes());
	}

	@DataProvider(name="provideDataSymmetricKeyWrapperForSignature", parallel=true)
	public Object[][] provideDataSymmetricKeyWrapperForSignature()
	{
		Object [][] res=new Object[SymmetricKeyWrapperType.values().length*SymmetricEncryptionType.values().length*SymmetricAuthentifiedSignatureType.values().length][];
		int index=0;
		for (SymmetricKeyWrapperType akpw : SymmetricKeyWrapperType.values())
		{
			for (SymmetricEncryptionType aet : SymmetricEncryptionType.values())
			{
				for (SymmetricAuthentifiedSignatureType set : SymmetricAuthentifiedSignatureType.values())
				{
					if ((akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(aet.getCodeProviderForEncryption()==CodeProvider.GNU_CRYPTO) && (akpw.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(set.getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO)
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
	@Test(dataProvider="provideDataSymmetricKeyWrapperForSignature")
	public void testSymmetricKeyWrapperForSignature(SymmetricKeyWrapperType typeWrapper, SymmetricEncryptionType asetype, SymmetricAuthentifiedSignatureType setype) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchPaddingException, IllegalStateException, IllegalBlockSizeException, NoSuchProviderException
	{
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		SymmetricSecretKey kp=asetype.getKeyGenerator(rand, (short)128).generateKey();
		SymmetricSecretKey sk= setype.getKeyGenerator(rand, (short)128).generateKey();
		byte[] wrappedKey=typeWrapper.wrapKey(kp, sk, rand);

		SymmetricSecretKey sk2=typeWrapper.unwrapKey(kp, wrappedKey);
		Assert.assertEquals(sk.getKeySizeBits(), sk2.getKeySizeBits());
		Assert.assertEquals(sk.getAuthenticatedSignatureAlgorithmType(), sk2.getAuthenticatedSignatureAlgorithmType());
		Assert.assertEquals(sk.getEncryptionAlgorithmType(), sk2.getEncryptionAlgorithmType());

		Assert.assertEquals(sk.getKeyBytes(), sk2.getKeyBytes(), sk+" , "+sk2+" , "+Base64.encodeBase64URLSafeString(wrappedKey));
		Assert.assertEquals(sk.toJavaNativeKey().getEncoded(), sk2.toJavaNativeKey().getEncoded());
		Assert.assertEquals(sk.toBouncyCastleKey().getKeyBytes(), sk2.toBouncyCastleKey().getKeyBytes());
	}
	@DataProvider(name="providePasswordKeyDerivationTypesForSymmetricSignatures", parallel=true)
	public Object[][] providePasswordKeyDerivationTypesForSymmetricSignatures()
	{
		Object[][] res=new Object[PasswordBasedKeyGenerationType.values().length*SymmetricAuthentifiedSignatureType.values().length][];
		int index=0;
		for (PasswordBasedKeyGenerationType p : PasswordBasedKeyGenerationType.values())
		{
			for (SymmetricAuthentifiedSignatureType s : SymmetricAuthentifiedSignatureType.values())
			{
				if ((p.getCodeProvider()==CodeProvider.GNU_CRYPTO)==(s.getCodeProviderForSignature()==CodeProvider.GNU_CRYPTO))
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
	@Test(dataProvider = "providePasswordKeyDerivationTypesForSymmetricSignatures")
	public void testPasswordKeyDerivation(PasswordBasedKeyGenerationType derivationType, SymmetricAuthentifiedSignatureType signatureType) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException {
		String password = "password";
		String invalidPassword = "invalid password";
		Random r=new Random(System.currentTimeMillis());
		byte[] salt=new byte[32];
		r.nextBytes(salt);
		SymmetricSecretKey key1=derivationType.derivateKey(password.toCharArray(), salt, (byte)7, signatureType);
		Assert.assertEquals(key1.getKeySizeBits(), signatureType.getDefaultKeySizeBits());
		Assert.assertEquals(key1.getAuthenticatedSignatureAlgorithmType(), signatureType);
		Assert.assertEquals(key1.encode(), derivationType.derivateKey(password.toCharArray(), salt, (byte)7, signatureType).encode());
		Assert.assertNotEquals(key1.encode(), derivationType.derivateKey(invalidPassword.toCharArray(), salt, (byte)7, signatureType).encode());
	}

	@DataProvider(name = "symmetricSignatures", parallel = true)
	public Object[][] provideDataForSymetricSignatures() {
		Object[][] res = new Object[SymmetricAuthentifiedSignatureType.values().length][];
		int i = 0;
		for (SymmetricAuthentifiedSignatureType v : SymmetricAuthentifiedSignatureType.values()) {
			Object[] o = new Object[1];
			o[0] = v;
			res[i++] = o;
		}
		return res;
	}
	@DataProvider(name = "provideDataForSymmetricSignatureTest", parallel = true)
	public Object[][] provideDataForSymmetricSignatureTest() throws NoSuchAlgorithmException, NoSuchProviderException {
		Object[][] res = new Object[SymmetricAuthentifiedSignatureType.values().length*2][];
		int i = 0;
		AbstractSecureRandom rand = SecureRandomType.DEFAULT.getSingleton(null);
		for (SymmetricAuthentifiedSignatureType ast : SymmetricAuthentifiedSignatureType.values()) {
			Object[] o = new Object[2];
			o[0] = ast;

			o[1] = ast.getKeyGenerator(rand, (short)256).generateKey();
			res[i++] = o;
		}
		for (SymmetricAuthentifiedSignatureType ast : SymmetricAuthentifiedSignatureType.values()) {
			Object[] o = new Object[2];
			o[0] = ast;

			o[1] = ast.getKeyGenerator(rand, (short)128).generateKey();
			res[i++] = o;
		}
		return res;
	}
}
