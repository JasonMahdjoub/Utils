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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

import com.distrimind.util.Bits;

/**
 * List of asymmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.4
 */
public enum ASymmetricEncryptionType
{
    RSA_OAEPWithSHA256AndMGF1Padding("RSA", "", "OAEPWithSHA-256AndMGF1Padding",SignatureType.SHA256withRSA, (short) 4096, (short) 66, false), 
    RSA_PKCS1Padding("RSA", "", "PKCS1Padding", SignatureType.SHA256withRSA, (short) 4096, (short) 11,false),
    //GNU_RSA_PKCS1Padding("RSA", "","PKCS1Padding",SignatureType.SHA256withRSA, (short)4096, (short)11, true),
    DEFAULT(RSA_OAEPWithSHA256AndMGF1Padding);

    static gnu.vm.java.security.KeyPair decodeGnuKeyPair(byte[] encodedKeyPair) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	return decodeGnuKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
    }

    static gnu.vm.java.security.KeyPair decodeGnuKeyPair(byte[] encodedKeyPair, int off, int len) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	byte[][] parts = Bits
		.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
	return new gnu.vm.java.security.KeyPair(decodeGnuPublicKey(parts[0]),
		decodeGnuPrivateKey(parts[1]));
    }

    static gnu.vm.java.security.PrivateKey decodeGnuPrivateKey(byte[] encodedKey) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
	gnu.vm.java.security.spec.PKCS8EncodedKeySpec pkcsKeySpec = new gnu.vm.java.security.spec.PKCS8EncodedKeySpec(
		parts[1]);
	gnu.vm.java.security.KeyFactory kf = gnu.vm.java.security.KeyFactory
		.getInstance(new String(parts[0]));
	return kf.generatePrivate(pkcsKeySpec);
    }

    static gnu.vm.java.security.PublicKey decodeGnuPublicKey(byte[] encodedKey) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedKey);
	gnu.vm.java.security.spec.X509EncodedKeySpec pubKeySpec = new gnu.vm.java.security.spec.X509EncodedKeySpec(
		parts[1]);
	gnu.vm.java.security.KeyFactory kf = gnu.vm.java.security.KeyFactory
		.getInstance(new String(parts[0]));
	return kf.generatePublic(pubKeySpec);
    }

    static KeyPair decodeNativeKeyPair(byte[] encodedKeyPair) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	return decodeNativeKeyPair(encodedKeyPair, 0, encodedKeyPair.length);
    }

    static KeyPair decodeNativeKeyPair(byte[] encodedKeyPair, int off, int len) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	byte[][] parts = Bits
		.separateEncodingsWithShortSizedTabs(encodedKeyPair, off, len);
	return new KeyPair(decodeNativePublicKey(parts[0]),
		decodeNativePrivateKey(parts[1]));
    }

    static PrivateKey decodeNativePrivateKey(byte[] encodedKey) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	try
	{
	    byte[][] parts = Bits
		    .separateEncodingsWithShortSizedTabs(encodedKey);
	    PKCS8EncodedKeySpec pkcsKeySpec = new PKCS8EncodedKeySpec(parts[1]);
	    KeyFactory kf = KeyFactory.getInstance(new String(parts[0]));
	    return kf.generatePrivate(pkcsKeySpec);
	}
	catch (NoSuchAlgorithmException e)
	{
	    throw new gnu.vm.java.security.NoSuchAlgorithmException(e);
	}
	catch (InvalidKeySpecException e)
	{
	    throw new gnu.vm.java.security.spec.InvalidKeySpecException(e);
	}
    }

    static PublicKey decodeNativePublicKey(byte[] encodedKey) throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.java.security.spec.InvalidKeySpecException
    {
	try
	{
	    byte[][] parts = Bits
		    .separateEncodingsWithShortSizedTabs(encodedKey);
	    X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(parts[1]);
	    KeyFactory kf = KeyFactory.getInstance(new String(parts[0]));
	    return kf.generatePublic(pubKeySpec);
	}
	catch (NoSuchAlgorithmException e)
	{
	    throw new gnu.vm.java.security.NoSuchAlgorithmException(e);
	}
	catch (InvalidKeySpecException e)
	{
	    throw new gnu.vm.java.security.spec.InvalidKeySpecException(e);
	}

    }

    static byte[] encodeKeyPair(gnu.vm.java.security.KeyPair keyPair)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		encodePublicKey(keyPair.getPublic()),
		encodePrivateKey(keyPair.getPrivate()));
    }

    static byte[] encodeKeyPair(KeyPair keyPair)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		encodePublicKey(keyPair.getPublic()),
		encodePrivateKey(keyPair.getPrivate()));
    }

    static byte[] encodePrivateKey(gnu.vm.java.security.PrivateKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		key.getAlgorithm().getBytes(), key.getEncoded());
    }

    static byte[] encodePrivateKey(PrivateKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		key.getAlgorithm().getBytes(), key.getEncoded());
    }

    static byte[] encodePublicKey(gnu.vm.java.security.PublicKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		key.getAlgorithm().getBytes(), key.getEncoded());
	/*
	 * X509EncodedKeySpec pubKeySpec = new
	 * X509EncodedKeySpec(key.getEncoded()); return
	 * Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(),
	 * pubKeySpec.getEncoded());
	 */
    }

    static byte[] encodePublicKey(PublicKey key)
    {
	return Bits.concateEncodingWithShortSizedTabs(
		key.getAlgorithm().getBytes(), key.getEncoded());
	/*
	 * X509EncodedKeySpec pubKeySpec = new
	 * X509EncodedKeySpec(key.getEncoded()); return
	 * Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(),
	 * pubKeySpec.getEncoded());
	 */
    }

    static ASymmetricEncryptionType valueOf(int ordinal) throws IllegalArgumentException
    {
	for (ASymmetricEncryptionType a : values())
	{
	    if (a.ordinal() == ordinal)
		return a;
	}
	throw new IllegalArgumentException();
    }

    private final String algorithmName;

    private final String blockMode;

    private final String padding;

    private final SignatureType signature;

    private final short keySize;

    private final short blockSizeDecrement;

    private final boolean gnuVersion;

    private ASymmetricEncryptionType(ASymmetricEncryptionType type)
    {
	this(type.algorithmName, type.blockMode, type.padding, type.signature,
		type.keySize, type.blockSizeDecrement, type.gnuVersion);
    }

    private ASymmetricEncryptionType(String algorithmName, String blockMode, String padding, SignatureType signature, short keySize, short blockSizeDecrement, boolean gnuVersion)
    {
	this.algorithmName = algorithmName;
	this.blockMode = blockMode;
	this.padding = padding;
	this.signature = signature;
	this.keySize = keySize;
	this.blockSizeDecrement = blockSizeDecrement;
	this.gnuVersion = gnuVersion;
    }

    public String getAlgorithmName()
    {
	return algorithmName;
    }

    public String getBlockMode()
    {
	return blockMode;
    }

    public AbstractCipher getCipherInstance() throws gnu.vm.java.security.NoSuchAlgorithmException, gnu.vm.javax.crypto.NoSuchPaddingException
    {
	if (gnuVersion)
	{
	    String name = algorithmName;
	    if ((blockMode != null && !blockMode.equals(""))
		    && (padding != null && !padding.equals("")))
		name += "/" + blockMode + "/" + padding;
	    return new GnuCipher(gnu.vm.javax.crypto.Cipher.getInstance(name));
	}
	else
	{
	    try
	    {
		String name = algorithmName;
		if ((blockMode != null && !blockMode.equals(""))
			&& (padding != null && !padding.equals("")))
		    name += "/" + blockMode + "/" + padding;
		return new JavaNativeCipher(Cipher.getInstance(name));
	    }
	    catch (NoSuchAlgorithmException e)
	    {
		throw new gnu.vm.java.security.NoSuchAlgorithmException(e);
	    }
	    catch (NoSuchPaddingException e)
	    {
		throw new gnu.vm.javax.crypto.NoSuchPaddingException(
			e.getMessage());
	    }
	}
    }

    public short getDefaultKeySize()
    {
	return keySize;
    }

    public int getDefaultMaxBlockSize()
    {
	return keySize / 8 - blockSizeDecrement;
    }

    public SignatureType getDefaultSignatureAlgorithm()
    {
	return signature;
    }

    public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random) throws gnu.vm.java.security.NoSuchAlgorithmException
    {
	return getKeyPairGenerator(random, keySize);
    }

    public AbstractKeyPairGenerator getKeyPairGenerator(AbstractSecureRandom random, short keySize) throws gnu.vm.java.security.NoSuchAlgorithmException
    {
	if (gnuVersion)
	{
	    gnu.vm.java.security.KeyPairGenerator kgp = gnu.vm.java.security.KeyPairGenerator
		    .getInstance(algorithmName);
	    GnuKeyPairGenerator res = new GnuKeyPairGenerator(this, kgp);
	    res.initialize(keySize, random);

	    return res;
	}
	else
	{
	    try
	    {
		KeyPairGenerator kgp = KeyPairGenerator
			.getInstance(algorithmName);
		JavaNativeKeyPairGenerator res = new JavaNativeKeyPairGenerator(
			this, kgp);
		res.initialize(keySize, random);

		return res;
	    }
	    catch (NoSuchAlgorithmException e)
	    {
		throw new gnu.vm.java.security.NoSuchAlgorithmException(e);
	    }

	}

    }

    public int getMaxBlockSize(int keySize)
    {
	return keySize / 8 - blockSizeDecrement;
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
