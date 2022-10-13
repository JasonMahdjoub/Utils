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

import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.security.SignatureException;
import java.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 */
public final class JavaNativeSignature extends AbstractSignature {
	private final Signature signature;
	private final boolean synchronize;
	private final ASymmetricAuthenticatedSignatureType typeToSynchronize;
	private final ASymmetricAuthenticatedSignatureType type;


	JavaNativeSignature(Signature signature, ASymmetricAuthenticatedSignatureType type) {
		this.signature = signature;
		this.type=type.getDerivedType();
		synchronize=type.name().startsWith("BCPQC_SPHINCS_PLUS");
		if (synchronize)
			this.typeToSynchronize=ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS_PLUS_SHA256_FAST;
		else
			this.typeToSynchronize=null;
	}

	@Override
	public JavaNativeSignature clone() throws CloneNotSupportedException {
		return new JavaNativeSignature((Signature) signature.clone(), type);
	}

	@Override
	public String getAlgorithm() {
		return signature.getAlgorithm();
	}

	@Override
	public String getProvider() {
		return signature.getProvider().getName();
	}

	Signature getSignature()
	{
		return signature;
	}
	@Override
	public void initSign(ASymmetricPrivateKey _privateKey)
			throws IOException {
		try {
			signature.initSign(_privateKey.toJavaNativeKey());
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}
	}

	@Override
	public void initSign(ASymmetricPrivateKey _privateKey, AbstractSecureRandom _random)
			throws IOException {
		try {
			signature.initSign(_privateKey.toJavaNativeKey(), _random.getJavaNativeSecureRandom());
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}

	}

	@Override
	public void initVerify(ASymmetricPublicKey _publicKey)
			throws IOException {
		try {
			signature.initVerify(_publicKey.toJavaNativeKey());
		} catch (InvalidKeyException | NoSuchAlgorithmException | InvalidKeySpecException e) {
			throw new MessageExternalizationException(Integrity.FAIL, e);
		}

	}

	@Override
	public byte[] sign() throws IOException {
		try {
			if (synchronize) {
				synchronized (typeToSynchronize) {
					return signature.sign();
				}
			}
			else
				return signature.sign();
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}

	}

	@Override
	public int sign(byte[] _outbuf, int _offset, int _len) throws IOException {
		try {
			if (synchronize) {
				synchronized (typeToSynchronize) {
					return signature.sign(_outbuf, _offset, _len);
				}
			}
			else
				return signature.sign(_outbuf, _offset, _len);
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}

	}

	@Override
	public String toString() {

		return signature.toString();
	}

	@Override
	public void update(byte _b) throws IOException {
		try {
			signature.update(_b);
		} catch (java.security.SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}

	}

	@Override
	public void update(byte[] _data) throws IOException {
		try {
			signature.update(_data);
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public void update(byte[] _data, int _off, int _len) throws IOException {
		try {
			signature.update(_data, _off, _len);
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public void update(ByteBuffer _input) throws IOException {
		try {
			signature.update(_input);
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public boolean verify(byte[] _signature) throws IOException {
		try {
			if (synchronize) {
				synchronized (typeToSynchronize) {
					return signature.verify(_signature);
				}
			}
			else
				return signature.verify(_signature);
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public boolean verify(byte[] _signature, int _offset, int _length) throws IOException {
		try {
			if (synchronize) {
				synchronized (typeToSynchronize) {
					return signature.verify(_signature, _offset, _length);
				}
			}
			else
				return signature.verify(_signature, _offset, _length);
		} catch (SignatureException e) {
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

}
