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

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionIOAlgorithm
{
    private final SecretKey key;
    private final IvParameterSpec ivParameter;
    private final SymmetricEncryptionType type;
    
    public SymmetricEncryptionAlgorithm(SymmetricEncryptionType type, SecretKey key, SecureRandom random) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	this(type, key, random, null);
    }

    public SymmetricEncryptionAlgorithm(SymmetricEncryptionType type, SecretKey key, SecureRandom random, IvParameterSpec ivParameter) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	super(type.getCipherInstance());
	this.type=type;
	this.key=key;
	
	if (ivParameter==null)
	{
	    this.cipher.init(Cipher.ENCRYPT_MODE, this.key, random);
	    this.ivParameter=new IvParameterSpec(this.cipher.getIV());
	}
	else
	{
	    this.cipher.init(Cipher.ENCRYPT_MODE, this.key, ivParameter, random);
	    this.ivParameter=ivParameter;
	}
    }

    public static SymmetricEncryptionAlgorithm getInstance(SymmetricEncryptionType type, SecureRandom random, byte[] cryptedKeyAndIV, ASymmetricEncryptionAlgorithm asalgo) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	byte[] keyAndIV=asalgo.decode(cryptedKeyAndIV);
	byte[][] parts=Bits.separateEncodingsWithShortSizedTabs(keyAndIV);
	SecretKey k = SymmetricEncryptionType.decodeSecretKey(parts[0]);
	IvParameterSpec iv=new IvParameterSpec(parts[1]);
	return new SymmetricEncryptionAlgorithm(type, k, random, iv);
    }
    
    @Override 
    public void initCipherForEncrypt(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	cipher.init(Cipher.ENCRYPT_MODE, key, ivParameter);
    }
    @Override 
    public void initCipherForDecrypt(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	cipher.init(Cipher.DECRYPT_MODE, key, new IvParameterSpec(cipher.getIV()));
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
    
    public SecretKey getSecretKey()
    {
	return key;
    }
    
    public IvParameterSpec getIV()
    {
	return ivParameter;
    }
    
    public byte[] encodeKeyAndIvParameter(ASymmetricEncryptionAlgorithm asalgo) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	byte[] k=SymmetricEncryptionType.encodeSecretKey(key);
	byte[]iv=ivParameter.getIV();
	return asalgo.encode(Bits.concateEncodingWithShortSizedTabs(k, iv));
	
    }
    
}
