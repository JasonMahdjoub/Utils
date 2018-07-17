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

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;


import com.distrimind.util.Bits;

import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.SignatureException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 4.1
 * @since Utils 1.7
 */
public class ASymmetricAuthentifiedSignerAlgorithm extends AbstractAuthentifiedSignerAlgorithm {
	private final ASymmetricPrivateKey localPrivateKey;
	private final AbstractSignature signature;
	private final int macLength;
	private final ASymmetricAuthentifiedSignatureType type;
	private boolean includeParameter=false;
	@SuppressWarnings("deprecation")
	public ASymmetricAuthentifiedSignerAlgorithm(ASymmetricPrivateKey localPrivateKey) throws NoSuchAlgorithmException, NoSuchProviderException {
		if (localPrivateKey == null)
			throw new NullPointerException("localPrivateKey");
		type=localPrivateKey.getAuthentifiedSignatureAlgorithmType();
		if (type==null)
			throw new IllegalArgumentException("The given key is not destinated to a signature process");
		this.localPrivateKey = localPrivateKey;
		this.signature = type.getSignatureInstance();
		this.macLength = type.getSignatureSizeBytes(localPrivateKey.getKeySizeBits());
	}

	public ASymmetricPrivateKey getLocalPrivateKey() {
		return localPrivateKey;
	}

	public AbstractSignature getSignatureAlgorithm() {
		return signature;
	}


	@Override
	public void init() throws InvalidKeyException, NoSuchAlgorithmException, InvalidKeySpecException, gnu.vm.jgnu.security.InvalidAlgorithmParameterException {
		try
		{
			includeParameter=false;
			if (type==ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA256withRSAandMGF1)
			{
				((JavaNativeSignature)signature).getSignature().setParameter(new PSSParameterSpec("SHA-256","MGF1",new MGF1ParameterSpec("SHA-256"),0, PSSParameterSpec.DEFAULT.getTrailerField()));
				includeParameter=true;
			}
			else if (type==ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA384withRSAandMGF1)
			{
				((JavaNativeSignature)signature).getSignature().setParameter(new PSSParameterSpec("SHA-384","MGF1",new MGF1ParameterSpec("SHA-384"),0, PSSParameterSpec.DEFAULT.getTrailerField()));
				includeParameter=true;
			}
			else if (type==ASymmetricAuthentifiedSignatureType.BC_FIPS_SHA512withRSAandMGF1)
			{
				((JavaNativeSignature)signature).getSignature().setParameter(new PSSParameterSpec("SHA-512","MGF1",new MGF1ParameterSpec("SHA-512"),0, PSSParameterSpec.DEFAULT.getTrailerField()));
				includeParameter=true;
			}
		
			signature.initSign(localPrivateKey);
		}catch (InvalidAlgorithmParameterException e) {
			throw new gnu.vm.jgnu.security.InvalidAlgorithmParameterException(e);
		}
	}

	@Override
	public void update(byte[] message, int offm, int lenm) throws SignatureException {
		this.signature.update(message, offm, lenm);
	}

	@Override
	public byte[] getSignature() throws IllegalStateException, SignatureException, IOException {
		
		byte[] s=this.signature.sign();
		if (includeParameter)
		{
			return Bits.concateEncodingWithIntSizedTabs(s, ((JavaNativeSignature)this.signature).getSignature().getParameters().getEncoded());
		}
		else
			return s;
	}

	@Deprecated
	@Override
	public int getMacLength() {
		return macLength;
	}

	@Override
	public void getSignature(byte[] signature, int off_sig) throws IllegalStateException,
			SignatureException, IOException {
		if (includeParameter)
		{
			byte s[]=getSignature();
			System.arraycopy(s, 0, signature, off_sig, s.length);
		}
		else
		{
			this.signature.sign(signature, off_sig, macLength);
		}		
	}

}
