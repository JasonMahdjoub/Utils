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

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.distrimind.util.Bits;

/**
 * List of symmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 1.4
 */
public enum SymmetricEncryptionType
{
    
    AES("AES", "CBC","PKCS5Padding", (short)128),//TODO see for OCB and/or GCM mode (limit to 64Gb for the same couple key/iv)
    @Deprecated
    DES("DES","CBC", "PKCS5Padding", (short)56, (short)8),
    @Deprecated
    DESede("DESede","CBC", "PKCS5Padding", (short)168, (short)24),
    @Deprecated
    Blowfish("Blowfish","CBC", "PKCS5Padding", (short)128),
   //GNU_TwoFish
    
    DEFAULT(AES);
    //TODO voir si ajout de GNU crypto ou de Twofish
    //TODO revoir la regenération de l'IV
    private final String algorithmName;
    private final String blockMode;
    private final String padding;
    private final short keySizeBits;
    private final short keySizeBytes;

    
    private SymmetricEncryptionType(SymmetricEncryptionType type)
    {
	this(type.algorithmName, type.blockMode, type.padding, type.keySizeBits, type.keySizeBytes);
    }
    
    private SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits, short keySizeBytes)
    {
	this.algorithmName=algorithmName;
	this.blockMode=blockMode;
	this.padding=padding;
	this.keySizeBits=keySizeBits;
	this.keySizeBytes=keySizeBytes;
    }
    private SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits)
    {
	this(algorithmName, blockMode, padding, keySizeBits, (short)(keySizeBits/8));
    }
    
    public String getAlgorithmName()
    {
	return algorithmName;
    }
    
    public String getBlockMode()
    {
	return blockMode;
    }
    
    public String getPadding()
    {
	return padding;
    }
    
    public short getKeySizeBits()
    {
	return keySizeBits;
    }
    
    public short getKeySizeBytes()
    {
	return keySizeBytes;
    }

    public Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return Cipher.getInstance(algorithmName+"/"+blockMode+"/"+padding);
    }
    
    public KeyGenerator getKeyGenerator(SecureRandom random) throws NoSuchAlgorithmException
    {
	KeyGenerator kg=KeyGenerator.getInstance(algorithmName);
	kg.init(keySizeBits, random);
	return kg;
    }
 
    
    static byte[] encodeSecretKey(SecretKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
    }
    
    static SecretKey decodeSecretKey(byte[] encodedSecretKey)
    {
	return decodeSecretKey(encodedSecretKey, 0, encodedSecretKey.length);
    }
    static SecretKey decodeSecretKey(byte[] encodedSecretKey, int off, int len)
    {
	byte[][] parts=Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
	return new SecretKeySpec(parts[1], new String(parts[0]));
    }

    static SymmetricEncryptionType valueOf(int ordinal) throws IllegalArgumentException
    {
	for(SymmetricEncryptionType a : values())
	{
	    if (a.ordinal()==ordinal)
		return a;
	}
	throw new IllegalArgumentException();
    }
    
}
