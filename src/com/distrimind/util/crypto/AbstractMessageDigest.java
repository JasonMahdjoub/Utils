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

import gnu.vm.jgnu.security.DigestException;
import gnu.vm.jgnu.security.MessageDigestSpi;
import gnu.vm.jgnu.security.Provider;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public abstract class AbstractMessageDigest implements Cloneable
{
    /**
     * Does a simple byte comparison of the two digests.
     *
     * @param digesta
     *            first digest to compare.
     * @param digestb
     *            second digest to compare.
     * @return <code>true</code> if both are equal, <code>false</code>
     *         otherwise.
     */
    public static boolean isEqual(byte[] digesta, byte[] digestb)
    {
	if (digesta.length != digestb.length)
	    return false;

	for (int i = digesta.length - 1; i >= 0; --i)
	    if (digesta[i] != digestb[i])
		return false;

	return true;
    }

    AbstractMessageDigest()
    {

    }

    /**
     * Returns a clone of this instance if cloning is supported. If it does not
     * then a {@link CloneNotSupportedException} is thrown. Cloning depends on
     * whether the subclass {@link MessageDigestSpi} implements
     * {@link Cloneable} which contains the actual implementation of the
     * appropriate algorithm.
     *
     * @return a clone of this instance.
     * @throws CloneNotSupportedException
     *             the implementation does not support cloning.
     */
    @Override
    public abstract AbstractMessageDigest clone() throws CloneNotSupportedException;

    /**
     * Computes the final digest of the stored data.
     *
     * @return a byte array representing the message digest.
     */
    public abstract byte[] digest();

    /**
     * Computes a final update using the input array of bytes, then computes a
     * final digest and returns it. It calls {@link #update(byte[])} and then
     * {@link #digest(byte[])}.
     *
     * @param input
     *            an array of bytes to perform final update with.
     * @return a byte array representing the message digest.
     */
    public abstract byte[] digest(byte[] input);

    /**
     * Computes the final digest of the stored bytes and returns the result.
     *
     * @param buf
     *            an array of bytes to store the result in.
     * @param offset
     *            an offset to start storing the result at.
     * @param len
     *            the length of the buffer.
     * @return Returns the length of the buffer.
     */
    public abstract int digest(byte[] buf, int offset, int len) throws DigestException;

    /**
     * Returns the name of message digest algorithm.
     *
     * @return the name of message digest algorithm.
     */
    public abstract String getAlgorithm();

    /**
     * Returns the length of the message digest. The default is zero which means
     * that the concrete implementation does not implement this method.
     *
     * @return length of the message digest.
     * @since 1.2
     */
    public abstract int getDigestLength();

    /**
     * Returns the {@link Provider} of this instance.
     *
     * @return the {@link Provider} of this instance.
     */
    public abstract String getProvider();

    /** Resets this instance. */
    public abstract void reset();

    /**
     * Returns a string representation of this instance.
     *
     * @return a string representation of this instance.
     */
    @Override
    public abstract String toString();

    /**
     * Updates the digest with the byte.
     *
     * @param input
     *            byte to update the digest with.
     */
    public abstract void update(byte input);

    /**
     * Updates the digest with the bytes of an array.
     *
     * @param input
     *            bytes to update the digest with.
     */
    public abstract void update(byte[] input);

    /**
     * Updates the digest with the bytes from the array starting from the
     * specified offset and using the specified length of bytes.
     *
     * @param input
     *            bytes to update the digest with.
     * @param offset
     *            the offset to start at.
     * @param len
     *            length of the data to update with.
     */
    public abstract void update(byte[] input, int offset, int len);

    /**
     * Updates the digest with the remaining bytes of a buffer.
     *
     * @param input
     *            The input byte buffer.
     * @since 1.5
     */
    public abstract void update(ByteBuffer input);
}
