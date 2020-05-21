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

import com.distrimind.util.OS;
import com.distrimind.util.Timer;
import com.distrimind.util.io.LimitedRandomInputStream;
import com.distrimind.util.io.RandomByteArrayInputStream;
import com.distrimind.util.io.RandomByteArrayOutputStream;
import org.testng.annotations.DataProvider;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.ArrayList;
import java.util.Random;


/**
 * Set of functions giving information about the current running OS
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 3.11.1
 *
 */
public class CryptoBench {
	@org.testng.annotations.Test(dataProvider="provideDataForTestEncryptionAndSignatureSpeed")
	public void testEncryptionAndSignatureSpeed(SymmetricEncryptionType type) throws NoSuchAlgorithmException,NoSuchProviderException, IllegalStateException, IOException
	{
		System.out.println("JRE Version : "+OS.getCurrentJREVersionDouble());
		byte[] toEncrypt = new byte[1024 * 1024 * 400];
		int shift=64*1024;
		Random random=new Random(System.currentTimeMillis());
		random.nextBytes(toEncrypt);


		SymmetricSecretKey secretKeyForEncryption=type.getKeyGenerator(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS.getInstance(null), (type.getDefaultKeySizeBits()==128 && !type.equals(SymmetricEncryptionType.GNU_SQUARE_CBC__PKCS5Padding))?256:type.getDefaultKeySizeBits()).generateKey();
		EncryptionSignatureHashEncoder encoder=new EncryptionSignatureHashEncoder()
				.withSymmetricSecretKeyForEncryption(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED.getInstance(null), secretKeyForEncryption);
		SymmetricSecretKey secretKeyForSignature=null;
		SymmetricAuthentifiedSignatureType sigType=type.getDefaultSignatureAlgorithm();
		if (!type.isAuthenticatedAlgorithm()) {
			secretKeyForSignature=sigType.getKeyGenerator(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS.getInstance(null), type.getDefaultKeySizeBits() >= 128 ? 256 : type.getDefaultKeySizeBits()).generateKey();
			encoder.withSymmetricSecretKeyForSignature(secretKeyForSignature);
		}
		EncryptionSignatureHashDecoder decoder=new EncryptionSignatureHashDecoder()
				.withSymmetricSecretKeyForEncryption(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED.getInstance(null), secretKeyForEncryption);
		if (secretKeyForSignature!=null)
			decoder.withSymmetricSecretKeyForSignature(secretKeyForSignature);

		Timer timer=new Timer(true);

		ArrayList<byte[]> messages=new ArrayList<>(toEncrypt.length/shift+1);
		for (int index=0;index<toEncrypt.length;index+=shift) {
			int l=Math.min(toEncrypt.length-index, shift);
			try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream()) {
				encoder.withRandomInputStream(new LimitedRandomInputStream(new RandomByteArrayInputStream(toEncrypt), index, l))
						.encode(out);
				byte[] message=out.getBytes();
				messages.add(message);
			}
		}
		double ms=timer.getMilid();
		double speedEncoding=(toEncrypt.length/(ms/1000.0)/1024.0/1024.0);
		System.out.println(type+" - Encryption speed  : "+speedEncoding+" MiO/s");

		timer.reset();

		for (byte[] message : messages) {
			try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream()) {
				decoder.withRandomInputStream(new RandomByteArrayInputStream(message))
						.decodeAndCheckHashAndSignaturesIfNecessary(out);
			}
		}
		double ms2=timer.getMilid();

		double speedDecoding=(toEncrypt.length/(ms2/1000.0)/1024.0/1024.0);
		double averageSpeedEncodingAndDecoding=(speedDecoding+speedEncoding)/2.0;
		System.out.println(type+"Decryption speed  : "+speedDecoding+" MiO/s");
		System.out.println(type+"Average encryption and decryption speed  : "+averageSpeedEncodingAndDecoding+" MiO/s");
	}

	@DataProvider( name="provideDataForTestEncryptionAndSignatureSpeed")
	public Object[][] provideDataForTestEncryptionAndSignatureSpeed()
	{
		Object[][] res = new Object[SymmetricEncryptionType.values().length][1];
		int index=0;
		for (SymmetricEncryptionType t : SymmetricEncryptionType.values())
		{
			res[index++][0]=t;
		}
		return res;
	}



}
