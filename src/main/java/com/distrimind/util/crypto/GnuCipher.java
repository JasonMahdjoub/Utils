/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 */
public final class GnuCipher extends AbstractCipher {
	private final Object cipher;
	private int mode=-1;
	@Override
	public int getMode() {
		return mode;
	}


	private Object setSecureRandom(AbstractSecureRandom random) {
	    return random.getGnuSecureRandom();
	}

	GnuCipher(Object cipher) {
		super();
		this.cipher = cipher;
	}

	@Override
	public byte[] doFinal() throws IOException {
		return GnuFunctions.cipherDoFinal(cipher);
	}

	

	@Override
	public int doFinal(byte[] _output, int _outputOffset)
			throws IOException {
		return GnuFunctions.cipherDoFinal(cipher, _output, _outputOffset);
	}

	@Override
	public byte[] doFinal(byte[] _input, int _inputOffset, int _inputLength)
			throws IOException {
		return GnuFunctions.cipherDoFinal(cipher, _input, _inputOffset, _inputLength);
	}

	

	@Override
	public int doFinal(byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset)
			throws IOException {
		return GnuFunctions.cipherDoFinal(cipher, _input, _inputOffset, _inputLength, _output, _outputOffset);
	}

	

	@Override
	public String getAlgorithm() {
		return GnuFunctions.cipherGetAlgorithm(cipher);
	}

	@Override
	public int getBlockSize() {
		return GnuFunctions.cipherGetBlockSize(cipher);
	}

	@Override
	public InputStream getCipherInputStream(InputStream in) {
		return GnuFunctions.cipherGetCipherInputStream(cipher, in);
	}

	@Override
	public OutputStream getCipherOutputStream(OutputStream out) {
		return GnuFunctions.cipherGetCipherOutputStream(cipher, out);
	}

	@Override
	public byte[] getIV() {
		return GnuFunctions.cipherGetIV(cipher);
	}

	@Override
	protected int getOutputSize(int _inputLength) throws IOException {
		return GnuFunctions.cipherGetOutputSize(cipher, _inputLength);
	}

	@Override
	public void init(int opMode, AbstractKey _key)
			throws IOException {
		mode= opMode;
		try {
			GnuFunctions.cipherInit(cipher, opMode, _key.toGnuKey());
		} catch (NoSuchAlgorithmException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		} catch (InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}


	@Override
	public void init(int opMode, AbstractKey _key, AbstractSecureRandom _random)
			throws IOException {
		mode= opMode;
		try {
			GnuFunctions.cipherInit(cipher, opMode, _key.toGnuKey(), setSecureRandom(_random));
		} catch (NoSuchAlgorithmException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		} catch (InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public void init(int opMode, AbstractKey _key, byte[] _iv) throws IOException {
		mode= opMode;
		try {
			GnuFunctions.cipherInit(cipher, opMode, _key.toGnuKey(), _iv);
		}catch (NoSuchAlgorithmException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		} catch (InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	

	@Override
	public byte[] update(byte[] _input, int _inputOffset, int _inputLength) throws IOException {
		return GnuFunctions.cipherUpdate(cipher, _input, _inputOffset, _inputLength);
	}

	

	@Override
	public int update(byte[] _input, int _inputOffset, int _inputLength, byte[] _output, int _outputOffset)
			throws IOException {
		return GnuFunctions.cipherUpdate(cipher, _input, _inputOffset, _inputLength, _output, _outputOffset);
	}

	@Override
	public void updateAAD(byte[] ad, int offset, int size) {
		throw new IllegalStateException();
	}




}
