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

import gnu.vm.java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import gnu.vm.javax.crypto.KeyGenerator;
import gnu.vm.javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.distrimind.util.Bits;

/**
 * List of symmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.4
 */
public enum SymmetricEncryptionType
{

    AES("AES", "CBC", "PKCS5Padding", (short) 128, false), // TODO see for OCB
							   // and/or GCM mode
							   // (limit to 64Gb for
							   // the same couple
							   // key/iv)
    @Deprecated
    DES("DES", "CBC", "PKCS5Padding", (short) 56, (short) 8, false), @Deprecated
    DESede("DESede", "CBC", "PKCS5Padding", (short) 168, (short) 24, false), @Deprecated
    Blowfish("Blowfish", "CBC", "PKCS5Padding", (short) 128, false), GNU_AES("AES", "CBC", "PKCS5Padding", (short) 128, true), GNU_TWOFISH("TWOFISH", "CBC", "PKCS5Padding", (short) 128, true), GNU_SERPENT("Serpent", "CBC", "PKCS5Padding", (short) 128, true), GNU_ANUBIS("Anubis", "CBC", "PKCS5Padding", (short) 128, true), GNU_QUARE("Square", "CBC", "PKCS5Padding", (short) 128, true),

    DEFAULT(AES);
    static gnu.vm.javax.crypto.SecretKey decodeGnuSecretKey(byte[] encodedSecretKey)
    {
	return decodeGnuSecretKey(encodedSecretKey, 0, encodedSecretKey.length);
    }

    static gnu.vm.javax.crypto.SecretKey decodeGnuSecretKey(byte[] encodedSecretKey, int off, int len)
    {
	byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(
		encodedSecretKey, off, len);
	return new gnu.vm.javax.crypto.spec.SecretKeySpec(parts[1],
		new String(parts[0]));
    }

    static SecretKey decodeNativeSecretKey(byte[] encodedSecretKey)
    {
	return decodeNativeSecretKey(encodedSecretKey, 0,
		encodedSecretKey.length);
    }

    static SecretKey decodeNativeSecretKey(byte[] encodedSecretKey, int off, int len)
    {
	byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(
		encodedSecretKey, off, len);
	return new SecretKeySpec(parts[1], new String(parts[0]));
    }

    static byte[] encodeSecretKey(gnu.vm.javax.crypto.SecretKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		key.getAlgorithm().getBytes(), key.getEncoded());
    }

    static byte[] encodeSecretKey(SecretKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		key.getAlgorithm().getBytes(), key.getEncoded());
    }

    static SymmetricEncryptionType valueOf(int ordinal) throws IllegalArgumentException
    {
	for (SymmetricEncryptionType a : values())
	{
	    if (a.ordinal() == ordinal)
		return a;
	}
	throw new IllegalArgumentException();
    }

    // TODO voir si ajout de GNU crypto ou de Twofish
    // TODO revoir la regenération de l'IV
    private final String algorithmName;

    private final String blockMode;

    private final String padding;

    private final short keySizeBits;

    private final short keySizeBytes;

    private final boolean gnuVersion;

    private SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits, boolean gnuVersion)
    {
	this(algorithmName, blockMode, padding, keySizeBits,
		(short) (keySizeBits / 8), gnuVersion);
    }

    private SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits, short keySizeBytes, boolean gnuVersion)
    {
	this.algorithmName = algorithmName;
	this.blockMode = blockMode;
	this.padding = padding;
	this.keySizeBits = keySizeBits;
	this.keySizeBytes = keySizeBytes;
	this.gnuVersion = gnuVersion;
    }

    private SymmetricEncryptionType(SymmetricEncryptionType type)
    {
	this(type.algorithmName, type.blockMode, type.padding, type.keySizeBits,
		type.keySizeBytes, type.gnuVersion);
    }

    public String getAlgorithmName()
    {
	return algorithmName;
    }

    public String getBlockMode()
    {
	return blockMode;
    }

    public AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException
    {
	if (gnuVersion)
	{
	    return new GnuCipher(gnu.vm.javax.crypto.Cipher.getInstance(
		    algorithmName + "/" + blockMode + "/" + padding));
	}
	else
	{
	    try
	    {
		return new JavaNativeCipher(Cipher.getInstance(
			algorithmName + "/" + blockMode + "/" + padding));
	    }
	    catch (java.security.NoSuchAlgorithmException e)
	    {
		throw new NoSuchAlgorithmException(e);
	    }
	    catch (javax.crypto.NoSuchPaddingException e)
	    {
		throw new NoSuchPaddingException(e.getMessage());
	    }
	}

    }

    public short getDefaultKeySizeBits()
    {
	return keySizeBits;
    }

    public short getDefaultKeySizeBytes()
    {
	return keySizeBytes;
    }

    public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random) throws NoSuchAlgorithmException
    {
	return getKeyGenerator(random, keySizeBits);
    }

    public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random, short keySizeBits) throws NoSuchAlgorithmException
    {
	AbstractKeyGenerator res = null;
	if (gnuVersion)
	{
	    res = new GnuKeyGenerator(this,
		    KeyGenerator.getInstance(algorithmName));
	}
	else
	{
	    try
	    {
		res = new JavaNativeKeyGenerator(this,
			javax.crypto.KeyGenerator.getInstance(algorithmName));
	    }
	    catch (java.security.NoSuchAlgorithmException e)
	    {
		throw new NoSuchAlgorithmException(e);
	    }
	}
	res.init(keySizeBits, random);
	return res;

    }

    public String getPadding()
    {
	return padding;
    }

    public boolean isGNUVersion()
    {
	return gnuVersion;
    }

}
