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

import java.nio.ByteBuffer;

import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.Provider;
import gnu.vm.jgnu.security.SecureRandom;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public abstract class AbstractSignature implements Cloneable
{
    AbstractSignature()
    {

    }

    /**
     * Returns a clone of this instance.
     *
     * @return a clone of this instace.
     * @throws CloneNotSupportedException
     *             if the implementation does not support cloning.
     */
    @Override
    public abstract AbstractSignature clone() throws CloneNotSupportedException;

    /**
     * Returns the name of the algorithm currently used. The names of algorithms
     * are usually SHA/DSA or SHA/RSA.
     *
     * @return name of algorithm.
     */
    public abstract String getAlgorithm();

    /**
     * Returns the {@link Provider} of this instance.
     *
     * @return the {@link Provider} of this instance.
     */
    public abstract String getProvider();

    /**
     * Initializes this class with the private key for signing purposes.
     *
     * @param privateKey
     *            the private key to sign with.
     * @throws InvalidKeyException
     *             if the key is invalid.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public abstract void initSign(ASymmetricPrivateKey privateKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Initializes this class with the private key and source of randomness for
     * signing purposes.
     *
     * @param privateKey
     *            the private key to sign with.
     * @param random
     *            the {@link SecureRandom} to use.
     * @throws InvalidKeyException
     *             if the key is invalid.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public abstract void initSign(ASymmetricPrivateKey privateKey, AbstractSecureRandom random) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Initializes this instance with the public key for verification purposes.
     *
     * @param publicKey
     *            the public key to verify with.
     * @throws InvalidKeyException
     *             if the key is invalid.
     * @throws InvalidKeySpecException
     * @throws NoSuchAlgorithmException
     */
    public abstract void initVerify(ASymmetricPublicKey publicKey) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException;

    /**
     * Returns the signature bytes of all the data fed to this instance. The
     * format of the output depends on the underlying signature algorithm.
     *
     * @return the signature bytes.
     * @throws SignatureException
     *             if the engine is not properly initialized.
     */
    public abstract byte[] sign() throws SignatureException;

    /**
     * Generates signature bytes of all the data fed to this instance and stores
     * it in the designated array. The format of the result depends on the
     * underlying signature algorithm.
     *
     * <p>
     * After calling this method, the instance is reset to its initial state and
     * can then be used to generate additional signatures.
     * </p>
     *
     * <p>
     * <b>IMPLEMENTATION NOTE:</b> Neither this method nor the GNU provider will
     * return partial digests. If <code>len</code> is less than the signature
     * length, this method will throw a {@link SignatureException}. If it is
     * greater than or equal then it is ignored.
     * </p>
     *
     * @param outbuf
     *            array of bytes of where to store the resulting signature
     *            bytes.
     * @param offset
     *            the offset to start at in the array.
     * @param len
     *            the number of the bytes to use in the array.
     * @return the real number of bytes used.
     * @throws SignatureException
     *             if the engine is not properly initialized.
     * @since 1.2
     */
    public abstract int sign(byte[] outbuf, int offset, int len) throws SignatureException;

    /**
     * Returns a rstring representation of this instance.
     *
     * @return a rstring representation of this instance.
     */
    @Override
    public abstract String toString();

    /**
     * Updates the data to be signed or verified with the specified byte.
     *
     * @param b
     *            the byte to update with.
     * @throws SignatureException
     *             if the engine is not properly initialized.
     */
    public abstract void update(byte b) throws SignatureException;

    /**
     * Updates the data to be signed or verified with the specified bytes.
     *
     * @param data
     *            the array of bytes to use.
     * @throws SignatureException
     *             if the engine is not properly initialized.
     */
    public abstract void update(byte[] data) throws SignatureException;

    /**
     * Updates the data to be signed or verified with the specified bytes.
     *
     * @param data
     *            an array of bytes to use.
     * @param off
     *            the offset to start at in the array.
     * @param len
     *            the number of bytes to use from the array.
     * @throws SignatureException
     *             if the engine is not properly initialized.
     */
    public abstract void update(byte[] data, int off, int len) throws SignatureException;

    /**
     * Update this signature with the {@link java.nio.Buffer#remaining()} bytes
     * of the input buffer.
     *
     * @param input
     *            The input buffer.
     * @throws SignatureException
     *             If this instance was not properly initialized.
     */
    public abstract void update(ByteBuffer input) throws SignatureException;

    /**
     * Verifies a designated signature.
     *
     * @param signature
     *            the signature bytes to verify.
     * @return <code>true</code> if verified, <code>false</code> otherwise.
     * @throws SignatureException
     *             if the engine is not properly initialized or the signature
     *             does not check.
     */
    public abstract boolean verify(byte[] signature) throws SignatureException;

    /**
     * Verifies a designated signature.
     *
     * @param signature
     *            the signature bytes to verify.
     * @param offset
     *            the offset to start at in the array.
     * @param length
     *            the number of the bytes to use from the array.
     * @return <code>true</code> if verified, <code>false</code> otherwise.
     * @throws IllegalArgumentException
     *             if the <code>signature</code> byte array is
     *             <code>null</code>, or the <code>offset</code> or
     *             <code>length</code> is less than <code>0</code>, or the sum
     *             of the <code>offset</code> and <code>length</code> is greater
     *             than the length of the <code>signature</code> byte array.
     * @throws SignatureException
     *             if the engine is not properly initialized or the signature
     *             does not check.
     */
    public abstract boolean verify(byte[] signature, int offset, int length) throws SignatureException;

}
