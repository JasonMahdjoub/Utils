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
public class GnuSecureRandom extends AbstractSecureRandom {

	/**
	 * 
	 */
	private static final long serialVersionUID = -3972765139342047885L;

	private transient final GnuInterface secureGnuRandom;
	
	private boolean initialized;


	GnuSecureRandom(SecureRandomType _type, final SecureRandom secureRandom) throws NoSuchAlgorithmException, NoSuchProviderException {
		super(new AbstractSecureRandomSpi(true) {

			/**
			 * 
			 */
			private static final long serialVersionUID = 7215224107476788151L;

			@Override
			protected void engineSetSeed(byte[] seed) {
				if (secureRandom != null) {
					synchronized (secureRandom) {

						secureRandom.setSeed(seed);
					}
				}
			}

			@Override
			protected void engineNextBytes(byte[] bytes) {
				if (bytes != null) {
					if (secureRandom != null) {
						synchronized (secureRandom) {

							secureRandom.nextBytes(bytes);

							addDataProvided(bytes.length);
						}
					}
				}
			}

			@Override
			protected byte[] engineGenerateSeed(int numBytes) {
				synchronized(secureRandom)
				{
					return secureRandom.generateSeed(numBytes);
				}
			}}, _type);
		this.initialized=false;
		this.secureGnuRandom=new GnuInterface();
		this.initialized=true;
		if (_type.needInitialSeed())
		{
			setSeed(SecureRandomType.tryToGenerateNativeNonBlockingSeed(55));
			nextBytes(new byte[20]);
		}
	}

	@Override
	public SecureRandom getGnuSecureRandom() {
		return secureGnuRandom;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return this;
	}

	
	private class GnuInterface extends SecureRandom {
		/**
		 * 
		 */
		private static final long serialVersionUID = 4299616485652308411L;

		
		protected GnuInterface() {
			super(new gnu.vm.jgnu.security.SecureRandomSpi() {
				
				
				/**
				 * 
				 */
				private static final long serialVersionUID = 740095511171490031L;

				@Override
				protected void engineSetSeed(byte[] seed) {
					if (initialized)
						GnuSecureRandom.this.secureRandomSpi.engineSetSeed(seed);
				}
				
				@Override
				protected void engineNextBytes(byte[] bytes) {
					if (initialized)
						GnuSecureRandom.this.secureRandomSpi.engineNextBytes(bytes);
					
				}
				
				@Override
				protected byte[] engineGenerateSeed(int numBytes) {
					return GnuSecureRandom.this.secureRandomSpi.engineGenerateSeed(numBytes);
				}
			}, null);
			
		}
	}	

}
