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
import java.util.Arrays;
import javax.crypto.SecretKey;
import com.distrimind.util.Bits;
import gnu.java.util.Base64;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.7.1
 */
public class SymmetricSecretKey implements UtilKey
{

    /**
     * 
     */
    private static final long serialVersionUID = -1811177031909192919L;

    public static SymmetricSecretKey decode(byte[] b) throws IllegalArgumentException
    {
	byte[][] res = Bits.separateEncodingsWithShortSizedTabs(b);
	return new SymmetricSecretKey(
		SymmetricEncryptionType.valueOf(Bits.getInt(res[0], 0)), res[1],
		Bits.getShort(res[0], 4));
    }

    public static SymmetricSecretKey valueOf(String key) throws IllegalArgumentException, IOException
    {
	return decode(Base64.decode(key));
    }

    private final byte[] secretKey;

    private final short keySize;

    private final SymmetricEncryptionType type;

    private final int hashCode;

    private transient SecretKey javaNativeSecretKey = null;

    private transient gnu.vm.javax.crypto.SecretKey gnuSecretKey = null;

    SymmetricSecretKey(SymmetricEncryptionType type, byte secretKey[], short keySize)
    {
	if (type == null)
	    throw new NullPointerException("type");
	if (secretKey == null)
	    throw new NullPointerException("secretKey");
	this.secretKey = secretKey;
	this.keySize = keySize;
	this.type = type;
	hashCode = Arrays.hashCode(this.secretKey);
    }

    SymmetricSecretKey(SymmetricEncryptionType type, gnu.vm.javax.crypto.SecretKey secretKey, short keySize)
    {
	if (type == null)
	    throw new NullPointerException("type");
	if (secretKey == null)
	    throw new NullPointerException("secretKey");
	if (!type.isGNUVersion())
	    throw new IllegalAccessError();
	this.secretKey = SymmetricEncryptionType.encodeSecretKey(secretKey);
	this.keySize = keySize;
	this.type = type;
	hashCode = Arrays.hashCode(this.secretKey);
    }

    SymmetricSecretKey(SymmetricEncryptionType type, SecretKey secretKey, short keySize)
    {
	if (type == null)
	    throw new NullPointerException("type");
	if (secretKey == null)
	    throw new NullPointerException("secretKey");
	if (type.isGNUVersion())
	    throw new IllegalAccessError();
	this.secretKey = SymmetricEncryptionType.encodeSecretKey(secretKey);
	this.keySize = keySize;
	this.type = type;
	hashCode = Arrays.hashCode(this.secretKey);
    }

    public byte[] encode()
    {
	byte[] tab = new byte[6];
	Bits.putInt(tab, 0, type.ordinal());
	Bits.putShort(tab, 4, keySize);
	return Bits.concateEncodingWithShortSizedTabs(tab, secretKey);
    }

    @Override
    public boolean equals(Object o)
    {
	if (o == null)
	    return false;
	if (o == this)
	    return true;
	if (o instanceof SymmetricSecretKey)
	{
	    SymmetricSecretKey other = ((SymmetricSecretKey) o);
	    return Arrays.equals(secretKey, other.secretKey)
		    && type == other.type;
	}
	return false;
    }

    public SymmetricEncryptionType getAlgorithmType()
    {
	return type;
    }

    public short getKeySize()
    {
	return keySize;
    }

    public int getMaxBlockSize()
    {
	return Integer.MAX_VALUE;
    }

    @Override
    public int hashCode()
    {
	return hashCode;
    }

    @Override
    public gnu.vm.javax.crypto.SecretKey toGnuKey()
    {
	if (gnuSecretKey == null)
	    gnuSecretKey = SymmetricEncryptionType
		    .decodeGnuSecretKey(secretKey);

	return gnuSecretKey;
    }

    @Override
    public SecretKey toJavaNativeKey()
    {
	if (javaNativeSecretKey == null)
	    javaNativeSecretKey = SymmetricEncryptionType
		    .decodeNativeSecretKey(secretKey);

	return javaNativeSecretKey;
    }

    @Override
    public String toString()
    {
	return Base64.encode(encode());
    }

    /*
     * public static SymmetricSecretKey generate(SecureRandom random,
     * SymmetricEncryptionType type) throws NoSuchAlgorithmException { return
     * new SymmetricSecretKey(type, type.getKeyGenerator(random).generateKey());
     * }
     * 
     * public static SymmetricSecretKey generate(SecureRandom random) throws
     * NoSuchAlgorithmException { return new
     * SymmetricSecretKey(SymmetricEncryptionType.DEFAULT,
     * SymmetricEncryptionType.DEFAULT.getKeyGenerator(random).generateKey()); }
     */
}
