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

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionOutputAlgorithm
{
    final static int BUFFER_SIZE=1024; 
    
    protected final Cipher cipher;
    
    protected AbstractEncryptionOutputAlgorithm(Cipher cipher)
    {
	if (cipher==null)
	    throw new NullPointerException("cipher");
	this.cipher=cipher;
    }
    
    public int getOutputSizeForEncryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	
	initCipherForEncrypt(cipher);
	int maxBlockSize=getMaxBlockSizeForEncoding();
	if (maxBlockSize==Integer.MAX_VALUE)
	    return cipher.getOutputSize(inputLen);
	int div=inputLen/maxBlockSize;
	int mod=inputLen%maxBlockSize;
	int res=0;
	if (div>0)
	    res+=cipher.getOutputSize(maxBlockSize)*div;
	if (mod>0)
	    res+=cipher.getOutputSize(mod);
	return res;
    }

    
    
    public abstract void initCipherForEncrypt(Cipher cipher) throws InvalidKeyException, InvalidAlgorithmParameterException;
    
    protected abstract Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException;
    
    public void encode(InputStream is, OutputStream os) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
	initCipherForEncrypt(cipher);
	
	int maxBlockSize=getMaxBlockSizeForEncoding();
	
	byte[] buffer=new byte[BUFFER_SIZE];
	boolean finish=false;
	while (!finish)
	{
	    
	    int blockACC=0;
	    do
	    {
		int nb=Math.min(BUFFER_SIZE, maxBlockSize-blockACC);
		int size=is.read(buffer, 0, nb);
		if (size>0)
		{
		    os.write(cipher.update(buffer, 0, size));
		    blockACC+=size;
		}
		if (nb!=size || size<=0)
		    finish=true;
	    } while ((blockACC<maxBlockSize || maxBlockSize==Integer.MAX_VALUE) && !finish);
	    if (blockACC!=0)
		os.write(cipher.doFinal());
	}
	
	os.flush();
	
	
	/*try(CipherOutputStream cos=new CipherOutputStream(os, cipher))
	{
	    int read=-1;
	    do
	    {
		read=is.read();
		if (read!=-1)
		    cos.write(read);
		
	    } while (read!=-1);
	}*/
    }
    
    public abstract int getMaxBlockSizeForEncoding();

    public void encode(byte[] bytes, int off, int len, OutputStream os) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
	if (len<0 || off<0)
	    throw new IllegalArgumentException("bytes.length="+bytes.length+", off="+off+", len="+len);
	if (off>bytes.length)
	    throw new IllegalArgumentException("bytes.length="+bytes.length+", off="+off+", len="+len);
	if (off+len>bytes.length)
	    throw new IllegalArgumentException("bytes.length="+bytes.length+", off="+off+", len="+len);
	initCipherForEncrypt(cipher);
	
	int maxBlockSize=getMaxBlockSizeForEncoding();
	
	while (len>0)
	{
	    int size=0;
	    if (maxBlockSize==Integer.MAX_VALUE)
		size=len;
	    else
		size=Math.min(len, maxBlockSize);
	    
	    os.write(cipher.doFinal(bytes, off, size));
	    off+=size;
	    len-=size;
	}
	
	os.flush();

	/*try(CipherOutputStream cos=new CipherOutputStream(os, cipher))
	{
	    cos.write(bytes, off, len);
	}*/
	
    }

    public byte[] encode(byte[] bytes) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
	return encode(bytes, 0, bytes.length);
    }
    public byte[] encode(byte[] bytes, int off, int len) throws InvalidKeyException, IOException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException
    {
	
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream(getOutputSizeForEncryption(len)))
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
