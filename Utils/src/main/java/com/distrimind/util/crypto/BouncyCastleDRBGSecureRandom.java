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


import org.bouncycastle.jcajce.provider.drbg.DRBG;

import com.distrimind.util.Bits;

import gnu.vm.jgnu.security.SecureRandom;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.16.0
 */
public class BouncyCastleDRBGSecureRandom extends AbstractSecureRandom{

	


	/**
	 * 
	 */
	private static final long serialVersionUID = -8631543641906931093L;

	private static class LocalDRBG extends DRBG.Default{
		/**
		 * 
		 */
		private static final long serialVersionUID = 9204590141782433204L;
		@Override
		protected void engineSetSeed(byte[] bytes) {
			super.engineSetSeed(bytes);
		}
		@Override
		protected void engineNextBytes(byte[] bytes) {
			super.engineNextBytes(bytes);
		}
		@Override
		protected byte[] engineGenerateSeed(int numBytes) {
			return super.engineGenerateSeed(numBytes);
		}

	};
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
			return BouncyCastleDRBGSecureRandom.this.generateSeed(_numBytes);
		}

		@Override
		public String getAlgorithm() {
			return BouncyCastleDRBGSecureRandom.this.getAlgorithm();
		}

		@Override
		public void nextBytes(byte[] _bytes) {
			BouncyCastleDRBGSecureRandom.this.nextBytes(_bytes);
		}

		@Override
		public void setSeed(byte[] _seed) {
			BouncyCastleDRBGSecureRandom.this.setSeed(_seed);
		}

		@Override
		public void setSeed(long _seed) {
			BouncyCastleDRBGSecureRandom.this.setSeed(_seed);

		}

	}
	private final LocalDRBG drbg;
	private final GnuInterface gnuInterface;
	
	BouncyCastleDRBGSecureRandom() {
		super(SecureRandomType.DRBG_BOUNCYCASTLE, true);
		drbg=new LocalDRBG();
		gnuInterface=new GnuInterface();
		nextBytes(new byte[20]);
	}
	
	@Override
	public byte[] generateSeed(int numBytes) {
		return drbg.engineGenerateSeed(numBytes);
	}

	@Override
	public String getAlgorithm() {
		return "DRBG";
	}

	@Override
	public SecureRandom getGnuSecureRandom() {
		return gnuInterface;
	}

	@Override
	public java.security.SecureRandom getJavaNativeSecureRandom() {
		return this;
	}

	@Override
	public void nextBytes(byte[] bytes) {
		drbg.engineNextBytes(bytes);
		if (bytes!=null)
			addDataProvided(bytes.length);
		
	}

	@Override
	public void setSeed(byte[] seed) {
		drbg.engineSetSeed(seed);
	}

	@Override
	public void setSeed(long seed) {
		if (drbg != null)
		{
			byte[] v=new byte[8];
			Bits.putLong(v, 0, seed);
			drbg.engineSetSeed(v);
		}
	}

}
