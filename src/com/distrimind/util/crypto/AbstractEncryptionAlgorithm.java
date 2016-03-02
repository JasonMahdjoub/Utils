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

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.4
 */
public abstract class AbstractEncryptionAlgorithm
{
    protected final Cipher cipher;
    
    protected AbstractEncryptionAlgorithm(Cipher cipher)
    {
	if (cipher==null)
	    throw new NullPointerException("cipher");
	this.cipher=cipher;
    }
    
    public int getOutputSize(int inputLen)
    {
	return cipher.getOutputSize(inputLen);
    }

    
    
    public abstract void initCipherForEncrypt(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException;
    public abstract void initCipherForDecrypt(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException;
    
    protected abstract Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException;
    
    public void encode(InputStream is, OutputStream os) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException
    {
	initCipherForEncrypt(cipher);
	try(CipherOutputStream cos=new CipherOutputStream(os, cipher))
	{
	    int read=-1;
	    do
	    {
		read=is.read();
		if (read!=-1)
		    cos.write(read);
		
	    } while (read!=-1);
	}
    }

    public void encode(byte[] bytes, int off, int len, OutputStream os) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException
    {
	initCipherForEncrypt(cipher);
	try(CipherOutputStream cos=new CipherOutputStream(os, cipher))
	{
	    cos.write(bytes, off, len);
	}
	
    }

    public byte[] encode(byte[] bytes) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException
    {
	return encode(bytes, 0, bytes.length);
    }
    public byte[] encode(byte[] bytes, int off, int len) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException
    {
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream(getOutputSize(len)))
	{
	    encode(bytes, off, len, baos);
	    return baos.toByteArray();
	}
    }
    public byte[] decode(byte[] bytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	return decode(bytes, 0, bytes.length);
    }
    public byte[] decode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	try(ByteArrayInputStream bais=new ByteArrayInputStream(bytes, off, len))
	{
	    return decode(bais);
	}
    }
    
    public byte[] decode(InputStream is) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream())
	{
	    this.decode(is, baos);
	    return baos.toByteArray();
	}
    }
    
    public void decode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	initCipherForDecrypt(cipher);
	
	try(CipherInputStream cis=new CipherInputStream(is, cipher))
	{
	    int read=-1;
	    do
	    {
		read=cis.read();
		if (read!=-1)
		    os.write(read);
	    }while (read!=-1);
	}
    }
    
    public CipherInputStream getCipherInputStream(InputStream is) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException
    {
	Cipher c=getCipherInstance();
	initCipherForDecrypt(c);
	return new CipherInputStream(is, c);
    }
    
    public CipherOutputStream getCipherOutputStream(OutputStream os) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
	Cipher c=getCipherInstance();
	initCipherForEncrypt(c);
	return new CipherOutputStream(os, c);
    }
    

}
