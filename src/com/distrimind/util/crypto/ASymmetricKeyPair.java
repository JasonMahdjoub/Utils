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

import java.io.IOException;
import java.io.Serializable;
import java.security.KeyPair;

import com.distrimind.util.Bits;

import gnu.java.util.Base64;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.7.1
 */
public class ASymmetricKeyPair implements Serializable
{
    /**
     * 
     */
    private static final long serialVersionUID = -8249147431069134363L;

    public static ASymmetricKeyPair decode(byte[] b) throws IllegalArgumentException
    {
	byte[][] res1 = Bits.separateEncodingsWithIntSizedTabs(b);
	byte[][] res2 = Bits.separateEncodingsWithShortSizedTabs(res1[0]);
	ASymmetricEncryptionType type = ASymmetricEncryptionType
		.valueOf(Bits.getInt(res2[0], 2));
	short keySize = Bits.getShort(res2[0], 0);
	return new ASymmetricKeyPair(type,
		new ASymmetricPrivateKey(type, res1[1], keySize),
		new ASymmetricPublicKey(type, res2[1], keySize), keySize);
    }

    public static ASymmetricKeyPair valueOf(String key) throws IllegalArgumentException, IOException
    {
	return decode(Base64.decode(key));
    }

    private final ASymmetricPrivateKey privateKey;

    private final ASymmetricPublicKey publicKey;

    private final short keySize;

    private final ASymmetricEncryptionType type;

    private final int hashCode;

    private transient volatile KeyPair nativeKeyPair;

    private transient volatile gnu.vm.java.security.KeyPair gnuKeyPair;

    ASymmetricKeyPair(ASymmetricEncryptionType type, ASymmetricPrivateKey privateKey, ASymmetricPublicKey publicKey, short keySize)
    {
	if (type == null)
	    throw new NullPointerException("type");
	if (privateKey == null)
	    throw new NullPointerException("privateKey");
	if (publicKey == null)
	    throw new NullPointerException("publicKey");
	if (keySize < 1024)
	    throw new IllegalArgumentException("keySize");
	this.privateKey = privateKey;
	this.publicKey = publicKey;
	this.keySize = keySize;
	this.type = type;
	hashCode = privateKey.hashCode() + publicKey.hashCode();
    }

    ASymmetricKeyPair(ASymmetricEncryptionType type, gnu.vm.java.security.KeyPair keyPair, short keySize)
    {
	if (type == null)
	    throw new NullPointerException("type");
	if (keyPair == null)
	    throw new NullPointerException("keyPair");
	if (keySize < 1024)
	    throw new IllegalArgumentException("keySize");
	privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(),
		keySize);
	publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize);
	this.keySize = keySize;
	this.type = type;
	hashCode = privateKey.hashCode() + publicKey.hashCode();
    }

    ASymmetricKeyPair(ASymmetricEncryptionType type, KeyPair keyPair, short keySize)
    {
	if (type == null)
	    throw new NullPointerException("type");
	if (keyPair == null)
	    throw new NullPointerException("keyPair");
	if (keySize < 1024)
	    throw new IllegalArgumentException("keySize");
	privateKey = new ASymmetricPrivateKey(type, keyPair.getPrivate(),
		keySize);
	publicKey = new ASymmetricPublicKey(type, keyPair.getPublic(), keySize);
	this.keySize = keySize;
	this.type = type;
	hashCode = privateKey.hashCode() + publicKey.hashCode();
    }

    public byte[] encode()
    {
	byte[] tab = new byte[6];
	Bits.putShort(tab, 0, keySize);
	Bits.putInt(tab, 2, type.ordinal());
	return Bits.concateEncodingWithIntSizedTabs(
		Bits.concateEncodingWithShortSizedTabs(tab,
			publicKey.getBytesPublicKey()),
		privateKey.getBytesPrivateKey());
	// return Bits.concateEncodingWithShortSizedTabs(tab,
	// ASymmetricEncryptionType.encodeKeyPair(toGnuKeyPair()));
    }

    @Override
    public boolean equals(Object o)
    {
	if (o == null)
	    return false;
	if (o == this)
	    return true;
	if (o instanceof ASymmetricKeyPair)
	{
	    ASymmetricKeyPair other = ((ASymmetricKeyPair) o);
	    return privateKey.equals(other.privateKey)
		    && publicKey.equals(other.publicKey)
		    && keySize == other.keySize && type == other.type;
	}
	return false;
    }

    public ASymmetricEncryptionType getAlgorithmType()
    {
	return type;
    }

    public ASymmetricPrivateKey getASymmetricPrivateKey()
    {
	return privateKey;
    }

    public ASymmetricPublicKey getASymmetricPublicKey()
    {
	return publicKey;
    }

    public short getKeySize()
    {
	return keySize;
    }

    public int getMaxBlockSize()
    {
	return type.getMaxBlockSize(keySize);
    }

    @Override
    public int hashCode()
    {
	return hashCode;
    }

    public gnu.vm.java.security.KeyPair toGnuKeyPair() throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	if (gnuKeyPair == null)
	    gnuKeyPair = new gnu.vm.java.security.KeyPair(publicKey.toGnuKey(),
		    privateKey.toGnuKey());

	return gnuKeyPair;
    }

    /*
     * public static ASymmetricKeyPair generate(SecureRandom random) throws
     * NoSuchAlgorithmException { return generate(random,
     * ASymmetricEncryptionType.DEFAULT,
     * ASymmetricEncryptionType.DEFAULT.getDefaultKeySize()); }
     * 
     * public static ASymmetricKeyPair generate(SecureRandom random,
     * ASymmetricEncryptionType type) throws NoSuchAlgorithmException { return
     * generate(random, type, type.getDefaultKeySize()); }
     * 
     * public static ASymmetricKeyPair generate(SecureRandom random,
     * ASymmetricEncryptionType type, short keySize) throws
     * NoSuchAlgorithmException { return new ASymmetricKeyPair(type,
     * type.getKeyPairGenerator(random, keySize).generateKeyPair(), keySize); }
     */

    public KeyPair toJavaNativeKeyPair() throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	if (nativeKeyPair == null)
	    nativeKeyPair = new KeyPair(publicKey.toJavaNativeKey(),
		    privateKey.toJavaNativeKey());

	return nativeKeyPair;
    }

    @Override
    public String toString()
    {
	try
	{
	    return Base64.encode(encode());
	}
	catch (Exception e)
	{
	    return e.toString();
	}
    }

}
