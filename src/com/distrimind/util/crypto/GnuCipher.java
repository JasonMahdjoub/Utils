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

import gnu.vm.java.security.InvalidAlgorithmParameterException;
import gnu.vm.java.security.InvalidKeyException;
import gnu.vm.java.security.NoSuchAlgorithmException;
import gnu.vm.java.security.NoSuchProviderException;
import gnu.vm.java.security.SecureRandom;
import gnu.vm.java.security.spec.InvalidKeySpecException;
import gnu.vm.javax.crypto.BadPaddingException;
import gnu.vm.javax.crypto.Cipher;
import gnu.vm.javax.crypto.CipherInputStream;
import gnu.vm.javax.crypto.CipherOutputStream;
import gnu.vm.javax.crypto.IllegalBlockSizeException;
import gnu.vm.javax.crypto.ShortBufferException;
import gnu.vm.javax.crypto.spec.IvParameterSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public final class GnuCipher extends AbstractCipher
{
    private final Cipher cipher;
    private volatile SecureRandom random;
    
    
    private SecureRandom getSecureRandom() throws NoSuchAlgorithmException, NoSuchProviderException
    {
	if (random==null)
	    return setSecureRandom(SecureRandomType.DEFAULT.getInstance());
	return random;
    }
    
    private SecureRandom setSecureRandom(AbstractSecureRandom random)
    {
	this.random=random.getGnuSecureRandom();
	return this.random;
    }
    
    GnuCipher(Cipher cipher)
    {
	this.cipher = cipher;
    }

    @Override
    public byte[] doFinal() throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
	return cipher.doFinal();
    }

    @Override
    public byte[] doFinal(byte[] _input) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
	return cipher.doFinal(_input);
    }

    @Override
    public int doFinal(byte[] _output, int _outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
	return cipher.doFinal(_output, _outputOffset);
    }

    @Override
    public byte[] doFinal(byte[] _input, int _inputOffset, int _inputLength) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException
    {
	return cipher.doFinal(_input, _inputOffset, _inputLength);
    }

    @Override
    public int doFinal(byte[] _input, int _inputOffset, int _inputLength, byte[] _output) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
	return cipher.doFinal(_input, _inputOffset, _inputLength, _output);
    }

    @Override
    public int doFinal(byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset) throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException
    {
	return cipher.doFinal(_input, _inputOffset, _inputLength, _output,
		_outputOffset);
    }

    @Override
    public int doFinal(ByteBuffer _input, ByteBuffer _output) throws ReadOnlyBufferException, ShortBufferException, BadPaddingException, IllegalBlockSizeException
    {
	return cipher.doFinal(_input, _output);
    }

    @Override
    public String getAlgorithm()
    {
	return cipher.getAlgorithm();
    }

    @Override
    public int getBlockSize()
    {
	return cipher.getBlockSize();
    }

    @Override
    public InputStream getCipherInputStream(InputStream in)
    {
	return new CipherInputStream(in, cipher);
    }

    @Override
    public OutputStream getCipherOutputStream(OutputStream out)
    {
	return new CipherOutputStream(out, cipher);
    }

    @Override
    public byte[] getIV()
    {
	return cipher.getIV();
    }

    @Override
    public int getOutputSize(int _inputLength) throws IllegalStateException
    {
	return cipher.getOutputSize(_inputLength);
    }

    @Override
    public void init(int _opmode, UtilKey _key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException
    {
	cipher.init(_opmode, _key.toGnuKey(), getSecureRandom());

    }

    @Override
    public void init(int _opmode, UtilKey _key, AbstractSecureRandom _random) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException
    {
	cipher.init(_opmode, _key.toGnuKey(), setSecureRandom(_random));

    }

    @Override
    public void init(int _opmode, UtilKey _key, byte[] _iv) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException
    {
	cipher.init(_opmode, _key.toGnuKey(), new IvParameterSpec(_iv));
    }

    @Override
    public byte[] update(byte[] _input) throws IllegalStateException
    {
	return cipher.update(_input);
    }

    @Override
    public byte[] update(byte[] _input, int _inputOffset, int _inputLength) throws IllegalStateException
    {
	return cipher.update(_input, _inputOffset, _inputLength);
    }

    @Override
    public int update(byte[] _input, int _inputOffset, int _inputLength, byte[] _output) throws IllegalStateException, ShortBufferException
    {
	return cipher.update(_input, _inputOffset, _inputLength, _output);
    }

    @Override
    public int update(byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset) throws IllegalStateException, ShortBufferException
    {
	return cipher.update(_input, _inputOffset, _inputLength, _output,
		_outputOffset);
    }

    @Override
    public int update(ByteBuffer _input, ByteBuffer _output) throws ReadOnlyBufferException, ShortBufferException
    {
	return cipher.update(_input, _output);
    }
}
