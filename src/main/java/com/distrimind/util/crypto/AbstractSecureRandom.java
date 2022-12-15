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

import java.security.*;


/**
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 2.0
 */
public abstract class AbstractSecureRandom extends SecureRandom {
	/**
	 * 
	 */
	private static final long serialVersionUID = 8080761472279881205L;

	protected abstract static class AbstractSecureRandomSpi extends SecureRandomSpi
	{
		/**
		 * 
		 */
		private static final long serialVersionUID = 5244593140887885074L;
		
		private int dataGenerated=0;
		private final boolean regenerateSeed;
		
		protected AbstractSecureRandomSpi(boolean regenerateSeed)
		{
			this.regenerateSeed=regenerateSeed;
		}
		
		protected void addDataProvided(int dataGenerated)
		{
			if (regenerateSeed)
			{
				this.dataGenerated+=dataGenerated;
				if (this.dataGenerated>maxDataGeneratedBeforeReseed)
				{
					this.dataGenerated=0;
					
					try {
						this.engineSetSeed(SecureRandomType.tryToGenerateNativeNonBlockingSeed(55));
					} catch (Exception e) {
						this.engineSetSeed(this.engineGenerateSeed(55));
					}
					this.engineNextBytes(new byte[20]);
				}
			}
		}
		
		/**
	     * Reseeds this random object. The given seed supplements, rather than
	     * replaces, the existing seed. Thus, repeated calls are guaranteed
	     * never to reduce randomness.
	     *
	     * @param seed the seed.
	     */
	    protected abstract void engineSetSeed(byte[] seed);

	    /**
	     * Generates a user-specified number of random bytes.
	     *
	     * <p> If a call to {@code engineSetSeed} had not occurred previously,
	     * the first call to this method forces this SecureRandom implementation
	     * to seed itself.  This self-seeding will not occur if
	     * {@code engineSetSeed} was previously called.
	     *
	     * @param bytes the array to be filled in with random bytes.
	     */
	    protected abstract void engineNextBytes(byte[] bytes);

	    /**
	     * Returns the given number of seed bytes.  This call may be used to
	     * seed other random number generators.
	     *
	     * @param numBytes the number of seed bytes to generate.
	     *
	     * @return the seed bytes.
	     */
	     protected abstract byte[] engineGenerateSeed(int numBytes);
		
	}

	protected SecureRandomType type;
	
	private static final int maxDataGeneratedBeforeReseed=102400;
	protected AbstractSecureRandomSpi secureRandomSpi;

	private static Provider getProvider(SecureRandomType type)
	{
		try {
			return type!=null?type.getDerivedType().getProvider().getCompatibleProvider():null;
		} catch (NoSuchProviderException ignored) {
			return null;
		}
	}
	AbstractSecureRandom(AbstractSecureRandomSpi secureRandomSpi, SecureRandomType type) {
		super(secureRandomSpi, getProvider(type));
		this.type = type==null?null:type.getDerivedType();
		this.secureRandomSpi=secureRandomSpi;
	}

	@Override
	public String getAlgorithm()
	{
		return type.getAlgorithmName();
	}
	

	public abstract Object getGnuSecureRandom();

	public abstract java.security.SecureRandom getJavaNativeSecureRandom();

	public final SecureRandomType getType() {
		return type;
	}

	@Override
	public void setSeed(byte[] seed) {
		setSeed(seed, true);
	}
	void unmodifiedSetSeed(byte[] seed)
	{
		super.setSeed(seed);
	}
	void setSeed(byte[] seed, boolean mixWithPreviousSeed) {

		byte[] tab=new byte[Math.min(32, seed.length)];
		nextBytes(tab);
		if (mixWithPreviousSeed) {
			int s= tab.length;
			for (int i = 0; i < s; i++)
				tab[i] ^= seed[i];
		}
		super.setSeed(tab);
	}
}
