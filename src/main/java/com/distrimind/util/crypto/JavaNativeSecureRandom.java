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


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 2.0
 */
public final class JavaNativeSecureRandom extends AbstractSecureRandom {





	/**
	 * 
	 */
	private static final long serialVersionUID = -1795571548950369446L;

	protected java.security.SecureRandom secureRandom;

	private volatile Object secureGnuRandom;

	JavaNativeSecureRandom(SecureRandomType type, java.security.SecureRandom secureRandom) {
		this(type, secureRandom, type.needInitialSeed());
	}
	JavaNativeSecureRandom(SecureRandomType type, final java.security.SecureRandom secureRandom, boolean automaticReseed) {
		super(new AbstractSecureRandomSpi(automaticReseed) {
			
			/**
			 * 
			 */
			private static final long serialVersionUID = -6399366557746420485L;

			@Override
			protected void engineSetSeed(byte[] seed) {
				synchronized(secureRandom)
				{
					byte[] tab=new byte[Math.min(32, seed.length)];
					secureRandom.nextBytes(tab);
					byte[] nc=seed.clone();
					for (int i=0;i<tab.length;i++)
						nc[i]^=tab[i];
					secureRandom.setSeed(nc);
					addDataProvided(seed.length);
				}
				
			}
			
			@Override
			protected void engineNextBytes(byte[] _bytes) {
				synchronized(secureRandom)
				{
					secureRandom.nextBytes(_bytes);
					if (_bytes!=null)
						addDataProvided(_bytes.length);
				}
				
			}
			
			@Override
			protected byte[] engineGenerateSeed(int numBytes) {
				return secureRandom.generateSeed(numBytes);
			}
		}, type);
		if (type == null)
			throw new NullPointerException("type");
		if (secureRandom == null)
			throw new NullPointerException("secureRandom");



		if (type.needInitialSeed())
		{
			setSeed(SecureRandomType.tryToGenerateNativeNonBlockingSeed(55), false);
			nextBytes(new byte[20]);
		}
		
	}

	@Override
	public Object getGnuSecureRandom() {
		if (this.secureGnuRandom==null)
			this.secureGnuRandom = GnuFunctions.getGnuRandomInterface(secureRandomSpi);
		return this.secureGnuRandom;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return this;
	}


}
