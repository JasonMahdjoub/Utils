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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm
{
    private final SymmetricSecretKey key;
    private final SymmetricEncryptionType type;
    private final SecureRandom random;
    
    public SymmetricEncryptionAlgorithm(SymmetricSecretKey key, SecureRandomType randomType, byte[] randomSeed) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	super(key.getAlgorithmType().getCipherInstance());
	this.type=key.getAlgorithmType();
	this.key=key;
	this.random=randomType.getInstance();
	if (randomSeed!=null)
	    this.random.setSeed(randomSeed);
	this.cipher.init(Cipher.ENCRYPT_MODE, this.key.getSecretKey(), generateIV());
    }
    
    
    private IvParameterSpec generateIV()
    {
	byte[] iv=new byte[cipher.getBlockSize()];
	random.nextBytes(iv);
	return new IvParameterSpec(iv);
    }

    public static SymmetricEncryptionAlgorithm getInstance(SecureRandomType randomType, byte[] seed, byte[] cryptedKey, P2PASymmetricEncryptionAlgorithm asalgo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	byte[] key=asalgo.decode(cryptedKey);
	return getInstance(randomType, seed, key);
    }

    private static SymmetricEncryptionAlgorithm getInstance(SecureRandomType randomType, byte[] seed, byte[] decryptedKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	return new SymmetricEncryptionAlgorithm(SymmetricSecretKey.decode(decryptedKey), randomType, seed);
    }
    
    public static SymmetricEncryptionAlgorithm getInstance(SecureRandomType randomType, byte[] seed, byte[] cryptedKey, ServerASymmetricEncryptionAlgorithm asalgo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	byte[] key=asalgo.decode(cryptedKey);
	return getInstance(randomType, seed, key);
    }

    @Override 
    public void initCipherForEncrypt(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey(), generateIV());
    }
    @Override 
    public void initCipherForEncryptAndNotChangeIV(Cipher cipher) throws InvalidKeyException
    {
	cipher.init(Cipher.ENCRYPT_MODE, key.getSecretKey());
    }
    
    @Override 
    public void initCipherForDecrypt(Cipher cipher, byte[]iv) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	if (iv!=null)
	    cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey(), new IvParameterSpec(iv));
	else
	    cipher.init(Cipher.DECRYPT_MODE, key.getSecretKey());
    }
    
    @Override
    protected Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return type.getCipherInstance();
    }
    
    public SymmetricEncryptionType getType()
    {
	return type;
    }
    
    public SymmetricSecretKey getSecretKey()
    {
	return key;
    }
    
    public byte[] encodeKey(P2PASymmetricEncryptionAlgorithm asalgo) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	return asalgo.encode(key.encode());
	
    }
    
    
    public byte[] encodeKey(ClientASymmetricEncryptionAlgorithm asalgo) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	return asalgo.encode(key.encode());
	
    }

    @Override
    public int getMaxBlockSizeForEncoding()
    {
	return key.getMaxBlockSize();
    }
    @Override
    public int getMaxBlockSizeForDecoding()
    {
	return key.getMaxBlockSize();
    }



    @Override
    protected boolean includeIV()
    {
	return true;
    }
    
    public int getBlockSize()
    {
	return cipher.getBlockSize();
    }
}
