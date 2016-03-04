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

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import com.distrimind.util.Bits;

/**
 * List of asymmetric encryption algorithms
 * @author Jason Mahdjoub
 * @version 1.1
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
    
    
    public static byte[] encodePublicKey(PublicKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	/*X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(key.getEncoded());
	return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), pubKeySpec.getEncoded());*/
    }
    
    static public PublicKey decodePublicKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	byte[][] parts=Bits.separateEncodingsWithShortSizedTabs(encodedKey);
	X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(parts[1]);
	KeyFactory kf=KeyFactory.getInstance(new String(parts[0]));
	return kf.generatePublic(pubKeySpec);
    }
    
    static public byte[] encodePrivateKey(PrivateKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	/*PKCS8EncodedKeySpec pkcsKeySpec=new PKCS8EncodedKeySpec(key.getEncoded());
	return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), pkcsKeySpec.getEncoded());*/
    }
    
    public static PrivateKey decodePrivateKey(byte[] encodedKey) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	byte[][] parts=Bits.separateEncodingsWithShortSizedTabs(encodedKey);
	PKCS8EncodedKeySpec pkcsKeySpec=new PKCS8EncodedKeySpec(parts[1]);
	KeyFactory kf=KeyFactory.getInstance(new String(parts[0]));
	return kf.generatePrivate(pkcsKeySpec);
    }
    
    public static byte[] encodeKeyPair(KeyPair keyPair)
    {
	return Bits.concateEncodingWithShortSizedTabs(encodePublicKey(keyPair.getPublic()), encodePrivateKey(keyPair.getPrivate()));
    }
    
    public static KeyPair decodeKeyPair(byte[] encodedKeyPair) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	return decodeKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
    }
    public static KeyPair decodeKeyPair(byte[] encodedKeyPair, int off, int len) throws NoSuchAlgorithmException, InvalidKeySpecException
    {
	byte[][] parts=Bits.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
	return new KeyPair(decodePublicKey(parts[0]), decodePrivateKey(parts[1]));
    }
    

}
