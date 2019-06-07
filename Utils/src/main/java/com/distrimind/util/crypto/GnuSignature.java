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
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 *
 */
public final class GnuSignature extends AbstractSignature {
	private final Object signature;

	GnuSignature(Object signature) {
		this.signature = signature;
	}

	@Override
	public GnuSignature clone() throws CloneNotSupportedException {
		return new GnuSignature(GnuFunctions.clone(signature));
	}

	@Override
	public String getAlgorithm() {

		return GnuFunctions.signatureGetAlgorithm(signature);
	}

	@Override
	public String getProvider() {
		return GnuFunctions.signatureGetProvider(signature);
	}

	@Override
	public void initSign(ASymmetricPrivateKey _privateKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		GnuFunctions.signatureInitSign(signature, _privateKey);

	}

	@Override
	public void initSign(ASymmetricPrivateKey _privateKey, AbstractSecureRandom _random)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		GnuFunctions.signatureInitSign(signature, _privateKey, _random);

	}

	@Override
	public void initVerify(ASymmetricPublicKey _publicKey)
			throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException {
		GnuFunctions.signatureInitVerify(signature, _publicKey);

	}

	@Override
	public byte[] sign() throws SignatureException {
		return GnuFunctions.signatureSign(signature);
	}

	@Override
	public int sign(byte[] _outbuf, int _offset, int _len) throws SignatureException {
		return GnuFunctions.signatureSign(signature, _outbuf, _offset, _len);
	}

	@Override
	public String toString() {

		return signature.toString();
	}

	@Override
	public void update(byte _b) throws SignatureException {
		GnuFunctions.signatureUpdate(signature, _b);
	}

	@Override
	public void update(byte[] _data) throws SignatureException {
		GnuFunctions.signatureUpdate(signature, _data);

	}

	@Override
	public void update(byte[] _data, int _off, int _len) throws SignatureException {
		GnuFunctions.signatureUpdate(signature, _data, _off, _len);

	}

	@Override
	public void update(ByteBuffer _input) throws SignatureException {
		GnuFunctions.signatureUpdate(signature, _input);

	}

	@Override
	public boolean verify(byte[] _signature) throws SignatureException {
		return GnuFunctions.signatureVerify(signature, _signature);
	}

	@Override
	public boolean verify(byte[] _signature, int _offset, int _length) throws SignatureException {
		return GnuFunctions.signatureVerify(signature, _signature, _offset, _length);
	}
}
