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

import com.distrimind.util.Bits;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.0
 */
public abstract class AbstractCipher {

	/**
	 * Finishes a multi-part transformation, and returns the final transformed
	 * bytes.
	 *
	 * @return The final transformed bytes.
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <b>doFinal</b> call has already been made.
	 * @throws IOException if a problem occurs
	 */
	public abstract byte[] doFinal() throws IOException;

	/**
	 * Finishes a multi-part transformation or does an entire transformation on the
	 * input, and returns the transformed bytes.
	 *
	 * @param input
	 *            The final input bytes.
	 * @return The final transformed bytes.
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <b>doFinal</b> call has already been made.
	 * @throws IOException if a problem occurs
	 */
	public byte[] doFinal(byte[] input)
			throws IOException
	{
		return doFinal(input, 0, input.length);
	}

	/**
	 * Finishes a multi-part transformation and stores the transformed bytes into
	 * the given array.
	 *
	 * @param output
	 *            The destination for the transformed bytes.
	 * @param outputOffset
	 *            The offset in <b>output</b> to start storing bytes.
	 * @return The number of bytes placed into the output array.
	 * @throws IOException if a problem occurs
	 */
	public abstract int doFinal(byte[] output, int outputOffset)
			throws IOException;

	/**
	 * Finishes a multi-part transformation or does an entire transformation on the
	 * input, and returns the transformed bytes.
	 *
	 * @param input
	 *            The final input bytes.
	 * @param inputOffset
	 *            The index in the input bytes to start.
	 * @param inputLength
	 *            The number of bytes to read from the input.
	 * @return The final transformed bytes.
	 * @throws IOException if a problem occurs
	 */
	public abstract byte[] doFinal(byte[] input, int inputOffset, int inputLength)
			throws IOException;

	public int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output)
			throws IOException
	{
		return doFinal(input, inputOffset, inputLength, output, 0);
	}

	/**
	 * Finishes a multi-part transformation or transforms a portion of a byte array,
	 * and stores the result in the given byte array.
	 *
	 * @param input
	 *            The input bytes.
	 * @param inputOffset
	 *            The index in <b>input</b> to start.
	 * @param inputLength
	 *            The number of bytes to transform.
	 * @param output
	 *            The output buffer.
	 * @param outputOffset
	 *            The index in <b>output</b> to start.
	 * @return The number of bytes placed into the output array.
	 * @throws IOException if a problem occurs
	 */
	public abstract int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
			throws IOException;

	/**
	 * Finishes a multi-part transformation with, or completely transforms, a byte
	 * buffer, and stores the result into the output buffer.
	 *
	 * @param input
	 *            The input buffer.
	 * @param output
	 *            The output buffer.
	 * @return The number of bytes stored into the output buffer.
	 * @throws IOException if a problem occurs
	 * @since 1.5
	 */
	public int doFinal(ByteBuffer input, ByteBuffer output)
			throws IOException
	{
		return doFinal(input.array(), input.position(), input.remaining(), output.array(), output.position());
	}

	/**
	 * Get the name that this cipher instance was created with; 
	 *
	 * @return The cipher name.
	 */
	public abstract String getAlgorithm();

	/**
	 * Return the size of blocks, in bytes, that this cipher processes.
	 *
	 * @return The block size.
	 */
	public abstract int getBlockSize();

	public abstract InputStream getCipherInputStream(InputStream in);

	public abstract OutputStream getCipherOutputStream(OutputStream out);

	/**
	 * Return the <i>initialization vector</i> that this instance was initialized
	 * with.
	 *
	 * @return The IV.
	 */
	public abstract byte[] getIV();

	/**
	 * Returns the size an output buffer needs to be if this cipher is updated with
	 * a number of bytes.
	 *
	 * @param inputLength
	 *            The input length.
	 * @return The output length given this input length.
	 * @throws IOException
	 *             If this instance has not been initialized, or if a
	 *             <b>doFinal</b> call has already been made.
	 */
	public abstract int getOutputSize(int inputLength) throws IOException;

	/**
	 * <p>
	 * Initialize this cipher with the supplied key.
	 * </p>
	 *
	 *
	 * <p>
	 * If this cipher requires any random bytes (for example for an initilization
	 * vector) than the {@link java.security.SecureRandom} with the highest priority
	 * is used as the source of these bytes.
	 * </p>
	 *
	 * <p>
	 * A call to any of the <code>init</code> methods overrides the state of the
	 * instance, and is equivalent to creating a new instance and calling its
	 * <code>init</code> method.
	 * </p>
	 *
	 * @param opmode
	 *            The operation mode to use.
	 * @param key
	 *            The key.
	 * @throws IOException if a problem occurs
	 */
	public abstract void init(int opmode, AbstractKey key)
			throws IOException;


	/**
	 * <p>
	 * Initialize this cipher with the supplied key and source of randomness.
	 * </p>
	 *
	 * <p>
	 * A call to any of the <code>init</code> methods overrides the state of the
	 * instance, and is equivalent to creating a new instance and calling its
	 * <code>init</code> method.
	 * </p>
	 *
	 * @param opmode
	 *            The operation mode to use.
	 * @param key
	 *            The key.
	 * @param random
	 *            The source of randomness to use.

	 * @throws IOException if a problem occurs
	 */
	public abstract void init(int opmode, AbstractKey key, AbstractSecureRandom random)
			throws IOException;

	/**
	 * <p>
	 * Initialize this cipher with the supplied key.
	 * </p>
	 *
	 *
	 * <p>
	 * If this cipher requires any random bytes (for example for an initilization
	 * vector) than the {@link java.security.SecureRandom} with the highest priority
	 * is used as the source of these bytes.
	 * </p>
	 *
	 * <p>
	 * A call to any of the <code>init</code> methods overrides the state of the
	 * instance, and is equivalent to creating a new instance and calling its
	 * <code>init</code> method.
	 * </p>
	 *
	 * @param opmode
	 *            The operation mode to use.
	 * @param key
	 *            The key.
	 * @param iv
	 *            the iv parameter
	 * @throws IOException if a problem occurs
	 */
	public abstract void init(int opmode, AbstractKey key, byte[] iv) throws IOException;



	public void init(int opmode, AbstractKey key, byte[] iv, int counter) throws IOException
	{
		if (iv!=null) {
			int counterPos = iv.length - 4;
			iv = iv.clone();
			Bits.putInt(iv, counterPos, Bits.getInt(iv, counterPos) + counter);
		}
		init(opmode, key, iv);
	}

	/**
	 * Continue a multi-part transformation on an entire byte array, returning the
	 * transformed bytes.
	 *
	 * @param input
	 *            The input bytes.
	 * @return The transformed bytes.
	 * @throws IOException if a problem occurs
	 */
	public byte[] update(byte[] input) throws IOException
	{
		return update(input, 0, input.length);
	}

	/**
	 * Continue a multi-part transformation on part of a byte array, returning the
	 * transformed bytes.
	 *
	 * @param input
	 *            The input bytes.
	 * @param inputOffset
	 *            The index in the input to start.
	 * @param inputLength
	 *            The number of bytes to transform.
	 * @return The transformed bytes.
	 * @throws IOException if a problem occurs
	 */
	public abstract byte[] update(byte[] input, int inputOffset, int inputLength) throws IOException;

	/**
	 * Continue a multi-part transformation on part of a byte array, placing the
	 * transformed bytes into the given array.
	 *
	 * @param input
	 *            The input bytes.
	 * @param inputOffset
	 *            The index in the input to start.
	 * @param inputLength
	 *            The number of bytes to transform.
	 * @param output
	 *            The output byte array.
	 * @return The number of transformed bytes.
	 * @throws IOException if a problem occurs
	 */
	public int update(byte[] input, int inputOffset, int inputLength, byte[] output)
			throws IOException
	{
		return update(input, inputOffset, inputLength, output, 0);
	}

	/**
	 * Continue a multi-part transformation on part of a byte array, placing the
	 * transformed bytes into the given array.
	 *
	 * @param input
	 *            The input bytes.
	 * @param inputOffset
	 *            The index in the input to start.
	 * @param inputLength
	 *            The number of bytes to transform.
	 * @param output
	 *            The output byte array.
	 * @param outputOffset
	 *            The index in the output array to start.
	 * @return The number of transformed bytes.
	 * @throws IOException if a problem occurs
	 */
	public abstract int update(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
			throws IOException;

	/**
	 * Continue a multi-part transformation on a byte buffer, storing the
	 * transformed bytes into another buffer.
	 *
	 * @param input
	 *            The input buffer.
	 * @param output
	 *            The output buffer.
	 * @return The number of bytes stored in <i>output</i>.
	 * @throws IOException if a problem occurs
	 * @since 1.5
	 */
	public int update(ByteBuffer input, ByteBuffer output)
			throws IOException
	{
		return update(input.array(), input.position(), input.remaining(), output.array(), output.position());
	}
	

	public abstract void updateAAD(byte[] ad, int offset, int size);
	
	
	public void updateAAD(byte[] ad)
	{
		updateAAD(ad, 0, ad.length);
	}
	
	public void updateAAD(ByteBuffer ad)
	{
		updateAAD(ad.array(), ad.position(), ad.remaining());
	}

	public abstract int getMode();

}
