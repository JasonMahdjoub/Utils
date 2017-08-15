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

import com.distrimind.util.crypto.P2PASymmetricSecretMessageExchanger.FakeSecureRandom;

import gnu.vm.jgnu.security.SecureRandom;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public class GnuSecureRandom extends AbstractSecureRandom {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3972765139342047885L;

	private final SecureRandom secureRandom;
	
	GnuSecureRandom(FakeSecureRandom random) {
		super(SecureRandomType.GNU_DEFAULT, false);
		this.secureRandom = random;
	}

	GnuSecureRandom(SecureRandomType _type, SecureRandom secureRandom) {
		super(_type, true);
		this.secureRandom = secureRandom;
		if (_type.needInitialSeed())
			nextBytes(new byte[20]);
	}

	@Override
	public byte[] generateSeed(int _numBytes) {
		return secureRandom.generateSeed(_numBytes);
	}

	@Override
	public String getAlgorithm() {
		return secureRandom.getAlgorithm();
	}

	@Override
	public SecureRandom getGnuSecureRandom() {
		return secureRandom;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return this;
	}

	@Override
	public void nextBytes(byte[] _bytes) {
		secureRandom.nextBytes(_bytes);
		if (_bytes!=null)
			addDataProvided(_bytes.length);
	}

	@Override
	public void setSeed(byte[] _seed) {
		secureRandom.setSeed(_seed);

	}

	@Override
	public void setSeed(long _seed) {
		if (secureRandom != null)
			secureRandom.setSeed(_seed);

	}

}
