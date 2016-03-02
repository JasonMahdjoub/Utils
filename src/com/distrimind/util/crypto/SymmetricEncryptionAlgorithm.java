/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */
package com.distrimind.util.crypto;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.4
 */
public class SymmetricEncryptionAlgorithm extends AbstractEncryptionAlgorithm
{
    private final Key key;
    private final IvParameterSpec ivParameter;
    private final SymmetricEncryptionType type;
    
    public SymmetricEncryptionAlgorithm(SymmetricEncryptionType type, Key key, SecureRandom random) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	this(type, key, random, null);
    }

    public SymmetricEncryptionAlgorithm(SymmetricEncryptionType type, Key key, SecureRandom random, IvParameterSpec ivParameter) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
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
	Key k = new SecretKeySpec(keyAndIV, 0, type.getKeySizeBytes(), type.getAlgorithmName());
	IvParameterSpec iv=new IvParameterSpec(keyAndIV, type.getKeySizeBytes(), keyAndIV.length-(type.getKeySizeBytes()));
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
    
    public Key getKey()
    {
	return key;
    }
    
    public IvParameterSpec getIV()
    {
	return ivParameter;
    }
    
    public byte[] encodeKeyAndIvParameter(ASymmetricEncryptionAlgorithm asalgo) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	byte[] k=key.getEncoded();
	byte[]iv=ivParameter.getIV();
	byte[] toEncode=new byte[k.length+iv.length];
	System.arraycopy(k, 0, toEncode, 0, k.length);
	System.arraycopy(iv, 0, toEncode, k.length, iv.length);
	return asalgo.encode(toEncode);
	
    }
}
