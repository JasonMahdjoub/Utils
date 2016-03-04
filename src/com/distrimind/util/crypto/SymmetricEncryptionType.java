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
 * @version 1.1
 * @since Utils 1.4
 */
public enum SymmetricEncryptionType
{
    
    AES("AES", "CBC","PKCS5Padding", (short)128),
    DES("DES","CBC", "PKCS5Padding", (short)56, (short)8),
    DESede("DESede","CBC", "PKCS5Padding", (short)168, (short)24),
    Blowfish("Blowfish","CBC", "PKCS5Padding", (short)128),
    DEFAULT(AES);
    
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
    
    public static byte[] encodeSecretKey(SecretKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
    }
    
    public static SecretKey decodeSecretKey(byte[] encodedSecretKey)
    {
	return decodeSecretKey(encodedSecretKey, 0, encodedSecretKey.length);
    }
    public static SecretKey decodeSecretKey(byte[] encodedSecretKey, int off, int len)
    {
	byte[][] parts=Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
	return new SecretKeySpec(parts[1], new String(parts[0]));
    }
}
