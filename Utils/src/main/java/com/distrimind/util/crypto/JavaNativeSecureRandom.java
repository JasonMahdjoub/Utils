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

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.SecureRandom;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 2.0
 */
public final class JavaNativeSecureRandom extends AbstractSecureRandom {
	private class GnuInterface extends SecureRandom {
		/**
		 * 
		 */
		private static final long serialVersionUID = 4299616485652308411L;

		protected GnuInterface() {
			super(null, null);
			
		}

		@Override
		public byte[] generateSeed(int _numBytes) {
			return JavaNativeSecureRandom.this.generateSeed(_numBytes);
		}

		@Override
		public String getAlgorithm() {
			return JavaNativeSecureRandom.this.getAlgorithm();
		}

		@Override
		public void nextBytes(byte[] _bytes) {
			JavaNativeSecureRandom.this.nextBytes(_bytes);
		}

		@Override
		public void setSeed(byte[] _seed) {
			JavaNativeSecureRandom.this.setSeed(_seed);
		}

		@Override
		public void setSeed(long _seed) {
			JavaNativeSecureRandom.this.setSeed(_seed);

		}

	}

	/**
	 * 
	 */
	private static final long serialVersionUID = -1795571548950369446L;

	protected java.security.SecureRandom secureRandom;

	private final GnuInterface secureGnuRandom;

	JavaNativeSecureRandom(SecureRandomType type, java.security.SecureRandom secureRandom) throws NoSuchAlgorithmException, NoSuchProviderException {
		this(type, secureRandom, type.needInitialSeed());
	}
	JavaNativeSecureRandom(SecureRandomType type, java.security.SecureRandom secureRandom, boolean automaticReseed) throws NoSuchAlgorithmException, NoSuchProviderException {
		super(type, automaticReseed);
		if (type == null)
			throw new NullPointerException("type");
		if (secureRandom == null)
			throw new NullPointerException("secureRandom");
		this.secureRandom=null;
		this.secureGnuRandom = new GnuInterface();
		this.secureRandom = secureRandom;
		if (type.needInitialSeed())
		{
			setSeed(SecureRandomType.tryToGenerateNativeNonBlockingSeed(55));
			nextBytes(new byte[20]);
		}
		
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
		return this.secureGnuRandom;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return secureRandom;
	}

	@Override
	public void nextBytes(byte[] _bytes) {
		synchronized(this)
		{
			secureRandom.nextBytes(_bytes);
			if (_bytes!=null)
				addDataProvided(_bytes.length);
		}
	}

	@Override
	public void setSeed(byte[] _seed) {
		synchronized(this)
		{
			secureRandom.setSeed(_seed);
		}
	}

	@Override
	public void setSeed(long _seed) {
		synchronized(this)
		{
			if (secureRandom != null)
				secureRandom.setSeed(_seed);
		}
	}

}
