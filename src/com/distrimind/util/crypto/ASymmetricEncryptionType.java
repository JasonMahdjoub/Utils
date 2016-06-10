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
