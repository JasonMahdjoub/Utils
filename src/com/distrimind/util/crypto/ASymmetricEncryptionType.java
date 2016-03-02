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

import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * List of asymmetric encryption algorithms
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.4
 */
public enum ASymmetricEncryptionType
{
    RSA("RSA", "ECB","OAEPWithSHA-256AndMGF1Padding", SignatureType.SHA256withRSA, (short)4096),
    DEFAULT(RSA);    
    
    private final String algorithmName;
    private final String blockMode;
    private final String padding;
    private final SignatureType signature;
    private final short keySize;
    
    private ASymmetricEncryptionType(ASymmetricEncryptionType type)
    {
	this(type.algorithmName, type.blockMode, type.padding, type.signature, type.keySize);
    }
    
    
    private ASymmetricEncryptionType(String algorithmName, String blockMode, String padding, SignatureType signature, short keySize)
    {
	this.algorithmName=algorithmName;
	this.blockMode=blockMode;
	this.padding=padding;
	this.signature=signature;
	this.keySize=keySize;
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
    
    public Cipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	return Cipher.getInstance(algorithmName+"/"+blockMode+"/"+padding);
    }
    
    public KeyPairGenerator getKeyPairGenerator(SecureRandom random) throws NoSuchAlgorithmException
    {
	return getKeyPairGenerator(random, keySize);
    }
    public KeyPairGenerator getKeyPairGenerator(SecureRandom random, int keySize) throws NoSuchAlgorithmException
    {
	KeyPairGenerator kgp=KeyPairGenerator.getInstance(algorithmName);
	kgp.initialize(keySize, random);
	return kgp;
    }
    
    public SignatureType getDefaultSignatureAlgorithm()
    {
	return signature;
    }
    
    public short getDefaultKeySize()
    {
	return keySize;
    }
    
    
    
    
    
    

}
