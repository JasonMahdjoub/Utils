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

import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.ReadOnlyBufferException;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.BadPaddingException;
import gnu.vm.jgnux.crypto.IllegalBlockSizeException;
import gnu.vm.jgnux.crypto.ShortBufferException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
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
	 *             <tt>doFinal</tt> call has already been made.
	 * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
	 *             If this instance has no padding and the input is not a multiple
	 *             of this cipher's block size.
	 * @throws gnu.vm.jgnux.crypto.BadPaddingException
	 *             If this instance is decrypting and the padding bytes do not match
	 *             this instance's padding scheme.
	 */
	public abstract byte[] doFinal() throws IllegalStateException, IllegalBlockSizeException, BadPaddingException;

	/**
	 * Finishes a multi-part transformation or does an entire transformation on the
	 * input, and returns the transformed bytes.
	 *
	 * @param input
	 *            The final input bytes.
	 * @return The final transformed bytes.
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <tt>doFinal</tt> call has already been made.
	 * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
	 *             If this instance has no padding and the input is not a multiple
	 *             of this cipher's block size.
	 * @throws gnu.vm.jgnux.crypto.BadPaddingException
	 *             If this instance is decrypting and the padding bytes do not match
	 *             this instance's padding scheme.
	 */
	public abstract byte[] doFinal(byte[] input)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException;

	/**
	 * Finishes a multi-part transformation and stores the transformed bytes into
	 * the given array.
	 *
	 * @param output
	 *            The destination for the transformed bytes.
	 * @param outputOffset
	 *            The offset in <tt>output</tt> to start storing bytes.
	 * @return The number of bytes placed into the output array.
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <tt>doFinal</tt> call has already been made.
	 * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
	 *             If this instance has no padding and the input is not a multiple
	 *             of this cipher's block size.
	 * @throws gnu.vm.jgnux.crypto.BadPaddingException
	 *             If this instance is decrypting and the padding bytes do not match
	 *             this instance's padding scheme.
	 * @throws gnu.vm.jgnux.crypto.ShortBufferException
	 *             If the output array is not large enough to hold the transformed
	 *             bytes.
	 */
	public abstract int doFinal(byte[] output, int outputOffset)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException;

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
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <tt>doFinal</tt> call has already been made.
	 * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
	 *             If this instance has no padding and the input is not a multiple
	 *             of this cipher's block size.
	 * @throws gnu.vm.jgnux.crypto.BadPaddingException
	 *             If this instance is decrypting and the padding bytes do not match
	 *             this instance's padding scheme.
	 */
	public abstract byte[] doFinal(byte[] input, int inputOffset, int inputLength)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException;

	public abstract int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException;

	/**
	 * Finishes a multi-part transformation or transforms a portion of a byte array,
	 * and stores the result in the given byte array.
	 *
	 * @param input
	 *            The input bytes.
	 * @param inputOffset
	 *            The index in <tt>input</tt> to start.
	 * @param inputLength
	 *            The number of bytes to transform.
	 * @param output
	 *            The output buffer.
	 * @param outputOffset
	 *            The index in <tt>output</tt> to start.
	 * @return The number of bytes placed into the output array.
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <tt>doFinal</tt> call has already been made.
	 * @throws gnu.vm.jgnux.crypto.IllegalBlockSizeException
	 *             If this instance has no padding and the input is not a multiple
	 *             of this cipher's block size.
	 * @throws gnu.vm.jgnux.crypto.BadPaddingException
	 *             If this instance is decrypting and the padding bytes do not match
	 *             this instance's padding scheme.
	 * @throws gnu.vm.jgnux.crypto.ShortBufferException
	 *             If the output array is not large enough to hold the transformed
	 *             bytes.
	 */
	public abstract int doFinal(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException;

	/**
	 * Finishes a multi-part transformation with, or completely transforms, a byte
	 * buffer, and stores the result into the output buffer.
	 *
	 * @param input
	 *            The input buffer.
	 * @param output
	 *            The output buffer.
	 * @return The number of bytes stored into the output buffer.
	 * @throws IllegalArgumentException
	 *             If the input and output buffers are the same object.
	 * @throws IllegalStateException
	 *             If this cipher was not initialized for encryption or decryption.
	 * @throws ReadOnlyBufferException
	 *             If the output buffer is not writable.
	 * @throws IllegalBlockSizeException
	 *             If this cipher requires a total input that is a multiple of its
	 *             block size to complete this transformation.
	 * @throws ShortBufferException
	 *             If the output buffer is not large enough to hold the transformed
	 *             bytes.
	 * @throws BadPaddingException
	 *             If the cipher is a block cipher with a padding scheme, and the
	 *             decrypted bytes do not end with a valid padding.
	 * @since 1.5
	 */
	public abstract int doFinal(ByteBuffer input, ByteBuffer output)
			throws ReadOnlyBufferException, ShortBufferException, BadPaddingException, IllegalBlockSizeException;

	/**
	 * Get the name that this cipher instance was created with; this is equivalent
	 * to the "transformation" argument given to any of the {@link #getInstance()}
	 * methods.
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
	 * @throws java.lang.IllegalStateException
	 *             If this instance has not been initialized, or if a
	 *             <tt>doFinal</tt> call has already been made.
	 */
	public abstract int getOutputSize(int inputLength) throws IllegalStateException;

	/**
	 * <p>
	 * Initialize this cipher with the supplied key.
	 * </p>
	 *
	 * <p>
	 * The cipher will be initialized for encryption, decryption, key wrapping, or
	 * key unwrapping, depending upon whether the <code>opmode</code> argument is
	 * {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE}, {@link #WRAP_MODE}, or
	 * {@link #UNWRAP_MODE}, respectively.
	 * </p>
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
	 * @throws java.security.InvalidKeyException
	 *             If the underlying cipher instance rejects the given key.
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 */
	public abstract void init(int opmode, UtilKey key)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException;

	/**
	 * <p>
	 * Initialize this cipher with the supplied key and source of randomness.
	 * </p>
	 *
	 * <p>
	 * The cipher will be initialized for encryption, decryption, key wrapping, or
	 * key unwrapping, depending upon whether the <code>opmode</code> argument is
	 * {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE}, {@link #WRAP_MODE}, or
	 * {@link #UNWRAP_MODE}, respectively.
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
	 * @throws java.security.InvalidKeyException
	 *             If the underlying cipher instance rejects the given key.
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 */
	public abstract void init(int opmode, UtilKey key, AbstractSecureRandom random)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException;

	/**
	 * <p>
	 * Initialize this cipher with the supplied key.
	 * </p>
	 *
	 * <p>
	 * The cipher will be initialized for encryption, decryption, key wrapping, or
	 * key unwrapping, depending upon whether the <code>opmode</code> argument is
	 * {@link #ENCRYPT_MODE}, {@link #DECRYPT_MODE}, {@link #WRAP_MODE}, or
	 * {@link #UNWRAP_MODE}, respectively.
	 * </p>
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
	 * @throws java.security.InvalidKeyException
	 *             If the underlying cipher instance rejects the given key.
	 * @throws InvalidKeySpecException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidAlgorithmParameterException
	 */
	public abstract void init(int opmode, UtilKey key, byte[] iv) throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException;

	/**
	 * Continue a multi-part transformation on an entire byte array, returning the
	 * transformed bytes.
	 *
	 * @param input
	 *            The input bytes.
	 * @return The transformed bytes.
	 * @throws java.lang.IllegalStateException
	 *             If this cipher was not initialized for encryption or decryption.
	 */
	public abstract byte[] update(byte[] input) throws IllegalStateException;

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
	 * @throws java.lang.IllegalStateException
	 *             If this cipher was not initialized for encryption or decryption.
	 */
	public abstract byte[] update(byte[] input, int inputOffset, int inputLength) throws IllegalStateException;

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
	 * @throws java.lang.IllegalStateException
	 *             If this cipher was not initialized for encryption or decryption.
	 * @throws javax.security.ShortBufferException
	 *             If there is not enough room in the output array to hold the
	 *             transformed bytes.
	 */
	public abstract int update(byte[] input, int inputOffset, int inputLength, byte[] output)
			throws IllegalStateException, ShortBufferException;

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
	 * @throws java.lang.IllegalStateException
	 *             If this cipher was not initialized for encryption or decryption.
	 * @throws javax.security.ShortBufferException
	 *             If there is not enough room in the output array to hold the
	 *             transformed bytes.
	 */
	public abstract int update(byte[] input, int inputOffset, int inputLength, byte[] output, int outputOffset)
			throws IllegalStateException, ShortBufferException;

	/**
	 * Continue a multi-part transformation on a byte buffer, storing the
	 * transformed bytes into another buffer.
	 *
	 * @param input
	 *            The input buffer.
	 * @param output
	 *            The output buffer.
	 * @return The number of bytes stored in <i>output</i>.
	 * @throws IllegalArgumentException
	 *             If the two buffers are the same object.
	 * @throws IllegalStateException
	 *             If this cipher was not initialized for encrypting or decrypting.
	 * @throws ReadOnlyBufferException
	 *             If the output buffer is not writable.
	 * @throws ShortBufferException
	 *             If the output buffer does not have enough available space for the
	 *             transformed bytes.
	 * @since 1.5
	 */
	public abstract int update(ByteBuffer input, ByteBuffer output)
			throws ReadOnlyBufferException, ShortBufferException;

}
