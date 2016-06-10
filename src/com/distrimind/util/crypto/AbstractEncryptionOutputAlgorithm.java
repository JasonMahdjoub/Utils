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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionOutputAlgorithm
{
    protected final Cipher cipher;
    
    protected AbstractEncryptionOutputAlgorithm(Cipher cipher)
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
    
    public CipherOutputStream getCipherOutputStream(OutputStream os) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidAlgorithmParameterException
    {
	Cipher c=getCipherInstance();
	initCipherForEncrypt(c);
	return new CipherOutputStream(os, c);
    }
    

}
