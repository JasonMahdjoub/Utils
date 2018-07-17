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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;

import java.io.IOException;


import org.testng.Assert;
import org.testng.annotations.DataProvider;

import com.distrimind.util.OS;
import com.distrimind.util.Timer;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnu.security.spec.InvalidParameterSpecException;
import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import gnu.vm.jgnux.crypto.ShortBufferException;

/**
 * Set of functions giving information about the current running OS
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.11.1
 *
 */
public class CryptoBench {
	@SuppressWarnings("ResultOfMethodCallIgnored")
	@org.testng.annotations.Test(dataProvider="provideDataForTestEncryptionAndSignatureSpeed")
	public void testEncryptionAndSignatureSpeed(SymmetricEncryptionType type) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchProviderException, InvalidKeySpecException, IllegalStateException, IllegalBlockSizeException, BadPaddingException, IOException, SignatureException, ShortBufferException, InvalidParameterSpecException
	{
		System.out.println("JRE Version : "+OS.getCurrentJREVersionDouble());
		byte toEncrypt[]=new byte[1024*1024*400];
		int shift=32*1024;
		SymmetricEncryptionAlgorithm cipher=new SymmetricEncryptionAlgorithm(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED.getInstance(null), type.getKeyGenerator(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS.getInstance(null), type.getDefaultKeySizeBits()).generateKey());
		SymmetricAuthentifiedSignatureType sigType;
		SymmetricSecretKey sks;
		SymmetricAuthentifiedSignerAlgorithm signer=null;
		SymmetricAuthentifiedSignatureCheckerAlgorithm checker=null;
		sigType=type.getDefaultSignatureAlgorithm();
		if (!type.isAuthenticatedAlgorithm())
		{
			
			sks=sigType.getKeyGenerator(SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS.getInstance(null), (short)128).generateKey();
			signer=new SymmetricAuthentifiedSignerAlgorithm(sks);
			checker=new SymmetricAuthentifiedSignatureCheckerAlgorithm(sks);
		}
		double nb=0;

		
		
		
		int signatureSize=sigType.getSignatureSizeInBits()/8;
		byte[] signatures=new byte[signatureSize*(toEncrypt.length/shift)];
		int indexSignature=0;
		Timer t=new Timer(true);
		int sizeEncoded=cipher.getOutputSizeForEncryption(shift);
		ByteArrayOutputStream os=new ByteArrayOutputStream(toEncrypt.length/shift*sizeEncoded);
		ByteArrayInputStream is=new ByteArrayInputStream(toEncrypt);
		
		while (is.available()>=shift)
		{
			byte tmp[]=new byte[shift];
			int i=is.read(tmp);
			if (i==shift)
			{
				byte[] encoded=cipher.encode(tmp);
				if (!type.isAuthenticatedAlgorithm())
				{
					assert signer != null;
					signer.sign(encoded, 0, encoded.length, signatures, indexSignature, signatureSize);
					indexSignature+=signatureSize;
				}
				os.write(encoded);
				nb+=shift;
			}
		}
		double ms=t.getMilid();
		double speedEncoding=(nb/(ms/1000.0)/1024.0/1024.0);
		System.out.println(type+" - Encryption speed  : "+speedEncoding+" MiO/s");
		is.close();
		
		
		is=new ByteArrayInputStream(os.toByteArray());
		os.close();
		os=new ByteArrayOutputStream(toEncrypt.length/shift*sizeEncoded);
		Timer t2=new Timer(true);
		indexSignature=0;
		while (is.available()>0)
		{
			byte tmp[]=new byte[sizeEncoded];
			is.read(tmp);
			
			os.write(cipher.decode(tmp));
			if (!type.isAuthenticatedAlgorithm())
			{
				//signer.sign(tmp);
				assert checker != null;
				Assert.assertTrue(checker.verify(tmp, 0, tmp.length, signatures, indexSignature, signatureSize));
				indexSignature+=signatureSize;
			}
			
			
		}
		double ms2=t2.getMilid();
		double speedEncodingAndDecoding=(nb/((ms2+ms)/1000.0)/1024.0/1024.0);
		double speedDecoding=(nb/(ms2/1000.0)/1024.0/1024.0);
		
		
		System.out.println(type+"Decryption speed  : "+speedDecoding+" MiO/s");
		System.out.println(type+"Encryption and decryption speed  : "+speedEncodingAndDecoding+" MiO/s");
		is.close();
		os.close();
	}

	@DataProvider( name="provideDataForTestEncryptionAndSignatureSpeed")
	public Object[][] provideDataForTestEncryptionAndSignatureSpeed()
	{
		Object res[][]=new Object[SymmetricEncryptionType.values().length][1];
		int index=0;
		for (SymmetricEncryptionType t : SymmetricEncryptionType.values())
		{
			res[index++][0]=t;
		}
		return res;
	}

}
