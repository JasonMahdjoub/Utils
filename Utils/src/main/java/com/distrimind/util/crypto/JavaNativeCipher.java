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

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;




/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 */
public final class JavaNativeCipher extends AbstractCipher {
	private final SymmetricEncryptionType type;
	private final Cipher cipher;
	private int mode;



	private SecureRandom setSecureRandom(AbstractSecureRandom random) {
		return random.getJavaNativeSecureRandom();
	}
	JavaNativeCipher(Cipher cipher) {
		this(null, cipher);
	}
	JavaNativeCipher(SymmetricEncryptionType type, Cipher cipher) {
		this.type=type;
		this.cipher = cipher;
	}

	@Override
	public byte[] doFinal() throws IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal();

	}



	@Override
	public int doFinal(byte[] _output, int _outputOffset)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		return cipher.doFinal(_output, _outputOffset);

	}

	@Override
	public byte[] doFinal(byte[] _input, int _inputOffset, int _inputLength)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException {
		return cipher.doFinal(_input, _inputOffset, _inputLength);

	}



	@Override
	public int doFinal(byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset)
			throws IllegalStateException, IllegalBlockSizeException, BadPaddingException, ShortBufferException {
		return cipher.doFinal(_input, _inputOffset, _inputLength, _output, _outputOffset);
	}



	@Override
	public String getAlgorithm() {
		return cipher.getAlgorithm();
	}

	@Override
	public int getBlockSize() {
		return cipher.getBlockSize();
	}

	@Override
	public InputStream getCipherInputStream(InputStream _in) {
		return new CipherInputStream(_in, cipher);
	}

	@Override
	public OutputStream getCipherOutputStream(OutputStream _out) {
		return new CipherOutputStream(_out, cipher);
	}

	@Override
	public byte[] getIV() {
		return cipher.getIV();
	}

	@Override
	public int getOutputSize(int _inputLength) throws IllegalStateException {
		return cipher.getOutputSize(_inputLength);
	}


	@Override
	public void init(int _opmode, AbstractKey _key, AbstractSecureRandom _random)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		mode=_opmode;
		cipher.init(_opmode, _key.toJavaNativeKey(), setSecureRandom(_random));

	}

	@Override
	public void init(int _opmode, AbstractKey _key) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		mode=_opmode;
		cipher.init(_opmode, _key.toJavaNativeKey());
	}


	@Override
	protected void initImpl(int _opmode, AbstractKey _key, byte[] _iv) throws InvalidKeyException, NoSuchAlgorithmException,
			InvalidKeySpecException, InvalidAlgorithmParameterException {
		mode=_opmode;
		if (type!=null && type.getBlockMode().toUpperCase().equals("GCM"))
			cipher.init(_opmode, _key.toJavaNativeKey(), new GCMParameterSpec(128, _iv));
		else if (type!=null && type.getAlgorithmName().equals(SymmetricEncryptionType.CHACHA20.getAlgorithmName()))
			init(_opmode, _key, _iv, 0);
		else
			cipher.init(_opmode, _key.toJavaNativeKey(), new IvParameterSpec(_iv));

	}

	private static final Constructor<? extends AlgorithmParameterSpec> constChachaParam;

	static
	{
		Constructor<? extends AlgorithmParameterSpec> c=null;
		try {
			//noinspection unchecked
			c=(Constructor<? extends AlgorithmParameterSpec>)Class.forName("javax.crypto.spec.ChaCha20ParameterSpec").getConstructor(byte[].class, int.class);
		} catch (NoSuchMethodException | ClassNotFoundException e) {
			e.printStackTrace();

		}
		constChachaParam=c;
	}

	@Override
	public void init(int opmode, AbstractKey key, byte[] iv, int counter) throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, InvalidAlgorithmParameterException {
		mode=opmode;
		if (type==SymmetricEncryptionType.CHACHA20)
		{
			try {
				cipher.init(opmode, key.toJavaNativeKey(), constChachaParam.newInstance(iv, counter));
			} catch (InstantiationException | IllegalAccessException | InvocationTargetException e) {
				throw new InvalidAlgorithmParameterException(e.getCause());
			}
		}
		else
			super.init(opmode, key, iv, counter);

	}

	@Override
	public byte[] update(byte[] _input, int _inputOffset, int _inputLength) throws IllegalStateException {
		return cipher.update(_input, _inputOffset, _inputLength);
	}


	@Override
	public int update(byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset)
			throws IllegalStateException, ShortBufferException {
		return cipher.update(_input, _inputOffset, _inputLength, _output, _outputOffset);

	}
	@Override
	public void updateAAD(byte[] ad, int offset, int size) {
		cipher.updateAAD(ad, offset, size);
	}

	@Override
	public int getMode() {
		return mode;
	}


}