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

import java.io.Serializable;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import org.apache.commons.net.util.Base64;

import com.distrimind.util.Bits;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.7.1
 */
public class ASymmetricPublicKey implements Serializable
{
    /**
     * 
     */
    private static final long serialVersionUID = 1279365581082538490L;
    
    private final PublicKey publicKey;
    private final short keySize;
    private final ASymmetricEncryptionType type;
    
    ASymmetricPublicKey(ASymmetricEncryptionType type, PublicKey publicKey, short keySize)
    {
	if (type==null)
	    throw new NullPointerException("type");
	if (publicKey==null)
	    throw new NullPointerException("publicKey");
	if (keySize<1024)
	    throw new IllegalArgumentException("keySize");
	this.publicKey=publicKey;
	this.keySize=keySize;
	this.type=type;
    }
    
    @Override
    public String toString()
    {
	return Base64.encodeBase64String(encode());
    }
    
    public static ASymmetricPublicKey valueOf(String key) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	return decode(Base64.decodeBase64(key));
    }
    
    
    
    @Override
    public boolean equals(Object o)
    {
	if (o==null)
	    return false;
	if (o==this)
	    return true;
	if (o instanceof ASymmetricPublicKey)
	{
	    ASymmetricPublicKey other=(ASymmetricPublicKey)o;
	    return publicKey.equals(other.publicKey) && keySize==other.keySize && type==other.type;
	}
	return false;
    }
    @Override
    public int hashCode()
    {
	return publicKey.hashCode();
    }
    
    public ASymmetricEncryptionType getAlgorithmType()
    {
	return type;
    }
    public int getMaxBlockSize()
    {
	return type.getMaxBlockSize(keySize);
    }
    
    public PublicKey getPublicKey()
    {
	return publicKey;
    }
    
    public short getKeySize()
    {
	return keySize;
    }
    public byte[] encode()
    {
	byte[] tab=new byte[6];
	Bits.putShort(tab, 0, keySize);
	Bits.putInt(tab, 2, type.ordinal());
	return Bits.concateEncodingWithShortSizedTabs(tab, ASymmetricEncryptionType.encodePublicKey(publicKey));
    }
    
    public static ASymmetricPublicKey decode(byte[] b) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	byte[][] res=Bits.separateEncodingsWithShortSizedTabs(b);
	return new ASymmetricPublicKey(ASymmetricEncryptionType.valueOf(Bits.getInt(res[0], 2)), ASymmetricEncryptionType.decodePublicKey(res[1]), Bits.getShort(res[0], 0));
    }
    
}
