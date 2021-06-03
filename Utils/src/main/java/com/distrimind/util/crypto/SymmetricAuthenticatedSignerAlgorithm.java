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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 2.10.0
 */
public class SymmetricAuthenticatedSignerAlgorithm extends AbstractAuthenticatedSignerAlgorithm {

	private final AbstractMac mac;
	private final SymmetricSecretKey secretKey;

	@Override
	public boolean isPostQuantumSigner() {
		return secretKey.isPostQuantumKey();
	}


	private SymmetricAuthenticatedSignerAlgorithm(AbstractMac mac, SymmetricSecretKey secretKey) {
		if (mac == null)
			throw new NullPointerException();
		if (secretKey == null)
			throw new NullPointerException();
		this.mac = mac;
		this.secretKey = secretKey;
	}

	public SymmetricAuthenticatedSignerAlgorithm(SymmetricSecretKey secretKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		this(secretKey.getAuthenticatedSignatureAlgorithmType().getHMacInstance(), secretKey);
		mac.init(secretKey);
	}

	public AbstractMac getMac() {
		return mac;
	}

	public SymmetricSecretKey getSecretKey() {
		return secretKey;
	}


	@Override
	public void init() throws IOException {
		mac.init(secretKey);
	}

	@Override
	public void update(byte[] message, int offm, int lenm) throws IOException {
		mac.update(message, offm, lenm);

	}

	@Override
	public int getSignature(byte[] signature, int off_sig) throws IOException {
		try {
			mac.doFinal(signature, off_sig);
			return secretKey.getAuthenticatedSignatureAlgorithmType().getSignatureSizeInBits() / 8;
		}
		catch (IllegalStateException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}

	@Override
	public byte[] getSignature() throws IOException {
		try {
			return mac.doFinal();
		}
		catch (IllegalStateException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}



	@Override
	public int getMacLengthBytes() {
		return mac.getMacLengthBytes();
	}

}
