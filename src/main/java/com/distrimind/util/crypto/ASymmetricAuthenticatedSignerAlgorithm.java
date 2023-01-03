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

import com.distrimind.util.Bits;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * 
 * @author Jason Mahdjoub
 * @version 5.0
 * @since Utils 1.7
 */
public class ASymmetricAuthenticatedSignerAlgorithm extends AbstractAuthenticatedSignerAlgorithm {

	private final AbstractAuthenticatedSignerAlgorithm signer;
	private final IASymmetricPrivateKey localPrivateKey;

	public ASymmetricAuthenticatedSignerAlgorithm(IASymmetricPrivateKey localPrivateKey) throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		if (localPrivateKey.isCleaned())
			throw new IllegalArgumentException();
		this.localPrivateKey=localPrivateKey;
		if (localPrivateKey instanceof ASymmetricPrivateKey)
			signer=new Signer((ASymmetricPrivateKey)localPrivateKey);
		else
			signer=new HybridSigner((HybridASymmetricPrivateKey) localPrivateKey);
		signer.init();
	}

	@Override
	public boolean isPostQuantumSigner() {
		return signer.isPostQuantumSigner();
	}
	@Override
	public void init() throws IOException {
		checkKeysNotCleaned();
	}

	@Override
	protected void checkKeysNotCleaned()
	{
		if (localPrivateKey.isCleaned())
			throw new IllegalAccessError();
	}

	@Override
	public void update(byte[] message, int offm, int lenm) throws IOException {
		signer.update(message, offm, lenm);
	}

	@Override
	public int getSignature(byte[] signature, int off_sig) throws IOException {
		checkKeysNotCleaned();
		return signer.getSignature(signature, off_sig);
	}

	@Override
	public int getMacLengthBytes() {
		return signer.getMacLengthBytes();
	}

	@Override
	public byte[] getSignature() throws IOException {
		checkKeysNotCleaned();
		return signer.getSignature();
	}



	private static class HybridSigner extends AbstractAuthenticatedSignerAlgorithm
	{
		private final Signer nonPQCSigner, PQCSigner;
		public HybridSigner(HybridASymmetricPrivateKey localPrivateKey) throws NoSuchProviderException, NoSuchAlgorithmException {
			nonPQCSigner=new Signer(localPrivateKey.getNonPQCPrivateKey());
			PQCSigner=new Signer(localPrivateKey.getPQCPrivateKey());
		}
		@Override
		public void init() throws IOException {
			nonPQCSigner.init();
			PQCSigner.init();
		}

		@Override
		public void update(byte[] message, int offm, int lenm) throws IOException {
			nonPQCSigner.update(message, offm, lenm);
			PQCSigner.update(message, offm, lenm);
		}

		@Override
		public int getSignature(byte[] signature, int off_sig) throws IOException {
			int nb1=nonPQCSigner.getSignature(signature, off_sig+3);
			int nb2=PQCSigner.getSignature(signature, off_sig+3+nb1);
			Bits.putUnsignedInt(signature, off_sig, nb1, 3);
			return nb1+nb2+3;
		}

		@Deprecated
		@Override
		public int getMacLengthBytes() {
			return nonPQCSigner.getMacLengthBytes()+PQCSigner.getMacLengthBytes()+3;
		}

		@Override
		public byte[] getSignature() throws IOException {
			byte[] sig1=nonPQCSigner.getSignature();
			byte[] sig2=PQCSigner.getSignature();
			byte[] res=new byte[sig1.length+sig2.length+3];
			Bits.putUnsignedInt(res, 0, sig1.length, 3);
			System.arraycopy(sig1, 0, res, 3, sig1.length);
			System.arraycopy(sig2, 0, res, 3+sig1.length, sig2.length);
			return res;
		}
		@Override
		public boolean isPostQuantumSigner() {
			return true;
		}

		@Override
		protected void checkKeysNotCleaned() {
			PQCSigner.checkKeysNotCleaned();
			nonPQCSigner.checkKeysNotCleaned();
		}
	}

	private static class Signer extends AbstractAuthenticatedSignerAlgorithm {
		private final ASymmetricPrivateKey localPrivateKey;
		private final AbstractSignature signature;
		private final int macLength;
		private final ASymmetricAuthenticatedSignatureType type;
		private boolean includeParameter = false;

		@Override
		public boolean isPostQuantumSigner() {
			return localPrivateKey.isPostQuantumKey();
		}

		@Override
		protected void checkKeysNotCleaned() {
			if (localPrivateKey.isCleaned())
				throw new IllegalAccessError();
		}

		@SuppressWarnings("deprecation")
		public Signer(ASymmetricPrivateKey localPrivateKey) throws NoSuchAlgorithmException, NoSuchProviderException {
			if (localPrivateKey == null)
				throw new NullPointerException("localPrivateKey");
			if (localPrivateKey.isCleaned())
				throw new IllegalArgumentException();
			type = localPrivateKey.getAuthenticatedSignatureAlgorithmType();
			if (type == null)
				throw new IllegalArgumentException("The given key is not destined to a signature process");
			this.localPrivateKey = localPrivateKey;
			this.signature = type.getSignatureInstance();
			this.macLength = type.getMaximumSignatureSizeBytes(localPrivateKey.getKeySizeBits());
		}


		@Override
		public void init() throws IOException {
			try {
				includeParameter = false;

				if (type == ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withRSAandMGF1) {
					((JavaNativeSignature) signature).getSignature().setParameter(new PSSParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-256"), 20, PSSParameterSpec.TRAILER_FIELD_BC));
					includeParameter = true;
				} else if (type == ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA384withRSAandMGF1) {
					((JavaNativeSignature) signature).getSignature().setParameter(new PSSParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-384"), 20, PSSParameterSpec.TRAILER_FIELD_BC));
					includeParameter = true;
				} else if (type == ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA512withRSAandMGF1) {
					((JavaNativeSignature) signature).getSignature().setParameter(new PSSParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-512"), 20, PSSParameterSpec.TRAILER_FIELD_BC));
					includeParameter = true;
				}
			} catch (InvalidAlgorithmParameterException e) {
				throw new IOException(e);
			}

			signature.initSign(localPrivateKey);
		}

		@Override
		public void update(byte[] message, int offm, int lenm) throws IOException {
			this.signature.update(message, offm, lenm);
		}

		@Override
		public byte[] getSignature() throws IOException {

			byte[] s = this.signature.sign();
			if (includeParameter) {
				return Bits.concatenateEncodingWithIntSizedTabs(s, ((JavaNativeSignature) this.signature).getSignature().getParameters().getEncoded());
			} else
				return s;
		}

		@Deprecated
		@Override
		public int getMacLengthBytes() {
			return macLength;
		}

		@Override
		public int getSignature(byte[] signature, int off_sig) throws IOException {
			if (includeParameter) {
				byte[] s = getSignature();
				System.arraycopy(s, 0, signature, off_sig, s.length);
				return s.length;
			} else {
				return this.signature.sign(signature, off_sig, macLength);
			}
		}
	}

	public IASymmetricPrivateKey getPrivateKey()
	{
		return localPrivateKey;
	}
}
