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
import java.io.InputStream;
import java.io.OutputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.5
 */
public abstract class AbstractEncryptionIOAlgorithm extends AbstractEncryptionOutputAlgorithm
{
    private final byte nullIV[];
    protected AbstractEncryptionIOAlgorithm(Cipher cipher)
    {
	super(cipher);
	nullIV=new byte[cipher.getBlockSize()];
    }
    
    public int getOutputSizeForDecryption(int inputLen) throws InvalidKeyException, InvalidAlgorithmParameterException
    {
	initCipherForDecrypt(cipher, nullIV);
	if (includeIV())
	    inputLen-=cipher.getIV().length;

	int maxBlockSize=getMaxBlockSizeForDecoding();
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
    
    public abstract void initCipherForDecrypt(Cipher cipher, byte[] iv) throws InvalidKeyException, InvalidAlgorithmParameterException;
    
    public byte[] decode(byte[] bytes) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	return decode(bytes, 0, bytes.length);
    }
    public byte[] decode(byte[] bytes, int off, int len) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	if (len<0 || off<0)
	    throw new IllegalArgumentException("bytes.length="+bytes.length+", off="+off+", len="+len);
	if (off>bytes.length)
	    throw new IllegalArgumentException("bytes.length="+bytes.length+", off="+off+", len="+len);
	if (off+len>bytes.length)
	    throw new IllegalArgumentException("bytes.length="+bytes.length+", off="+off+", len="+len);
	
	try(ByteArrayInputStream bais=new ByteArrayInputStream(bytes, off, len))
	{
	    return decode(bais);
	}
    }
    
    public byte[] decode(InputStream is) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	try(ByteArrayOutputStream baos=new ByteArrayOutputStream())
	{
	    this.decode(is, baos);
	    return baos.toByteArray();
	}
    }

    public abstract int getMaxBlockSizeForDecoding();
    
    public void decode(InputStream is, OutputStream os) throws InvalidKeyException, InvalidAlgorithmParameterException, IOException, IllegalBlockSizeException, BadPaddingException
    {
	byte[] iv=null;
	if (includeIV())
	{
	    iv=new byte[cipher.getBlockSize()];
	    if (is.read(iv)!=iv.length)
		throw new IOException();
	}
	
	initCipherForDecrypt(cipher, iv);
	
	int maxBlockSize=getMaxBlockSizeForDecoding();
	int blockACC=0;
	byte[] buffer=new byte[BUFFER_SIZE];
	boolean finish=false;
	while (!finish)
	{
	    blockACC=0;
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
	
	
	/*try(CipherInputStream cis=new CipherInputStream(is, cipher))
	{
	    int read=-1;
	    do
	    {
		read=cis.read();
		if (read!=-1)
		    os.write(read);
	    }while (read!=-1);
	}*/
    }
    
    public CipherInputStream getCipherInputStream(InputStream is) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException
    {
	Cipher c=getCipherInstance();
	byte[] iv=null;
	if (includeIV())
	{
	    iv=new byte[c.getBlockSize()];
	    if (is.read(iv)!=iv.length)
		throw new IOException();
	}
	
	initCipherForDecrypt(c, iv);
	return new CipherInputStream(is, c);
    }

}
