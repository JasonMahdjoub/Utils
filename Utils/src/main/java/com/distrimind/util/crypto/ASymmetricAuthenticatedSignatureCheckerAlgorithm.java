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

import com.distrimind.util.Bits;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.PSSParameterSpec;


/**
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.7
 */
public class ASymmetricAuthenticatedSignatureCheckerAlgorithm extends AbstractAuthenticatedCheckerAlgorithm {
	private final AbstractAuthenticatedCheckerAlgorithm checker;
	public ASymmetricAuthenticatedSignatureCheckerAlgorithm(IASymmetricPublicKey distantPublicKey) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (distantPublicKey instanceof ASymmetricPublicKey)
			checker=new Checker((ASymmetricPublicKey)distantPublicKey);
		else
			checker=new HybridChecker((HybridASymmetricPublicKey)distantPublicKey);
	}

	@Override
	public int getMacLengthBytes() {
		return checker.getMacLengthBytes();
	}

	@Override
	public void init(byte[] signature, int offs, int lens) throws IOException {
		checker.init(signature, offs, lens);
	}


	@Override
	public void update(byte[] message, int offm, int lenm) throws IOException {
		checker.update(message, offm, lenm);
	}

	@Override
	public boolean verify() throws IOException {
		return checker.verify();
	}

	@Override
	public boolean isPostQuantumChecker() {
		return checker.isPostQuantumChecker();
	}

	public IASymmetricPublicKey getDistantPublicKey()
	{
		if (checker instanceof Checker)
			return ((Checker) checker).getDistantPublicKey();
		else
			return ((HybridChecker) checker).distantPublicKey;
	}


	private static class HybridChecker extends AbstractAuthenticatedCheckerAlgorithm {
		private final Checker checkerPQC, checkerNonPQC;
		private final HybridASymmetricPublicKey distantPublicKey;
		private boolean signatureValid=true;
		HybridChecker(HybridASymmetricPublicKey distantPublicKey) throws NoSuchProviderException, NoSuchAlgorithmException {
			checkerNonPQC=new Checker(distantPublicKey.getNonPQCPublicKey());
			checkerPQC=new Checker(distantPublicKey.getPQCPublicKey());
			this.distantPublicKey=distantPublicKey;
		}

		@Override
		public void init(byte[] signature, int offs, int lens) throws IOException {
			int len=(int)Bits.getUnsignedInt(signature, offs, 3);
			signatureValid=len+3<lens;
			if (signatureValid) {
				checkerNonPQC.init(signature, offs+3, len);
				checkerPQC.init(signature,offs+3+len, lens-len-3);
			}
		}

		@Override
		public void update(byte[] message, int offm, int lenm) throws IOException {
			if (signatureValid) {
				checkerNonPQC.update(message, offm, lenm);
				checkerPQC.update(message, offm, lenm);
			}
		}

		@Override
		public boolean verify() throws IOException {
			if (signatureValid) {
				boolean r=checkerNonPQC.verify();
				r=checkerPQC.verify() && r;
				return r;
			}
			else
				return false;
		}
		@Deprecated
		@Override
		public int getMacLengthBytes() {
			return checkerNonPQC.getMacLengthBytes()+checkerPQC.getMacLengthBytes()+3;
		}

		@Override
		public boolean isPostQuantumChecker() {
			return true;
		}
	}
	private static class Checker extends AbstractAuthenticatedCheckerAlgorithm {
		private final ASymmetricPublicKey distantPublicKey;

		private final AbstractSignature signer;
		private final ASymmetricAuthenticatedSignatureType type;

		private byte[] signature = null;

		@Override
		public boolean isPostQuantumChecker() {
			return distantPublicKey.isPostQuantumKey();
		}

		public Checker(ASymmetricPublicKey distantPublicKey)
				throws NoSuchAlgorithmException, NoSuchProviderException {
			if (distantPublicKey == null)
				throw new NullPointerException("distantPublicKey");
			type = distantPublicKey.getAuthenticatedSignatureAlgorithmType();
			if (type == null)
				throw new IllegalArgumentException("The given key is not destined to a signature process");
			this.distantPublicKey = distantPublicKey;
			this.signer = type.getSignatureInstance();
		}

		public ASymmetricPublicKey getDistantPublicKey() {
			return distantPublicKey;
		}


		@Override
		public void init(byte[] signature, int offs, int lens)
				throws IOException {
			if (type == ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withRSAandMGF1 || type == ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withRSAandMGF1 || type == ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withRSAandMGF1) {
				byte[][] tmp = Bits.separateEncodingsWithIntSizedTabs(signature, offs, lens);
				this.signature = tmp[0];
				byte[] encParameters = tmp[1];
				AlgorithmParameters pssParameters;
				try {
					pssParameters = AlgorithmParameters.getInstance("PSS", "BCFIPS");
					pssParameters.init(encParameters);

					PSSParameterSpec pssParameterSpec = pssParameters.getParameterSpec(PSSParameterSpec.class);
					((JavaNativeSignature) signer).getSignature().setParameter(pssParameterSpec);
				} catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidParameterSpecException | InvalidAlgorithmParameterException e) {
					throw new MessageExternalizationException(Integrity.FAIL, e);
				}
			} else {
				this.signature = new byte[lens];

				System.arraycopy(signature, offs, this.signature, 0, this.signature.length);
			}
			signer.initVerify(distantPublicKey);


		}

		@Override
		public void update(byte[] message, int offm, int lenm) throws IOException {
			signer.update(message, offm, lenm);


		}

		@Override
		public boolean verify() throws IOException {
			try {
				return distantPublicKey.areTimesValid() && signer.verify(signature);
			} finally {
				signature = null;
			}
		}
		@Deprecated
		@Override
		public int getMacLengthBytes() {
			return distantPublicKey.getAuthenticatedSignatureAlgorithmType().getSignatureSizeBytes(distantPublicKey.getKeySizeBits());
		}
	}

}
