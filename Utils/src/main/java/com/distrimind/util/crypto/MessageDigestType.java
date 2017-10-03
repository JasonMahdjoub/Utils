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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.1
 * @since Utils 1.4
 */
public enum MessageDigestType {
	@Deprecated
	MD5("MD5", CodeProvider.SUN), @Deprecated
	SHA1("SHA", CodeProvider.SUN), 
	SHA2_256("SHA-256", CodeProvider.SUN), 
	SHA2_384("SHA-384",	CodeProvider.SUN), SHA_512("SHA-512", CodeProvider.SUN), 
	GNU_SHA2_256("SHA-256", CodeProvider.GNU_CRYPTO), GNU_SHA_384("SHA-384", CodeProvider.GNU_CRYPTO), 
	GNU_SHA2_512("SHA-512", CodeProvider.GNU_CRYPTO), GNU_WHIRLPOOL("WHIRLPOOL", CodeProvider.GNU_CRYPTO), 
	BC_FIPS_SHA2_256("SHA-256", CodeProvider.BCFIPS), 
	BC_FIPS_SHA2_384("SHA-384",CodeProvider.BCFIPS), 
	BC_FIPS_SHA2_512("SHA-512", CodeProvider.BCFIPS), 
	BC_FIPS_SHA3_256("SHA3-256", CodeProvider.BCFIPS), 
	BC_FIPS_SHA3_384("SHA3-384",CodeProvider.BCFIPS), 
	BC_FIPS_SHA3_512("SHA3-512", CodeProvider.BCFIPS), 
	BC_WHIRLPOOL("WHIRLPOOL",CodeProvider.BC), 
	DEFAULT(BC_FIPS_SHA3_384);

	private final String algorithmName;

	private final CodeProvider codeProvider;

	private MessageDigestType(MessageDigestType type) {
		this(type.algorithmName, type.codeProvider);
	}

	private MessageDigestType(String algorithmName, CodeProvider codeProvider) {
		this.algorithmName = algorithmName;
		this.codeProvider = codeProvider;
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public AbstractMessageDigest getMessageDigestInstance() throws gnu.vm.jgnu.security.NoSuchAlgorithmException, gnu.vm.jgnu.security.NoSuchProviderException {
		if (codeProvider == CodeProvider.GNU_CRYPTO) {
			return new GnuMessageDigest(gnu.vm.jgnu.security.MessageDigest.getInstance(algorithmName));
		} else if (codeProvider == CodeProvider.BCFIPS || codeProvider == CodeProvider.BC) {
			CodeProvider.ensureBouncyCastleProviderLoaded();
			try {
				return new JavaNativeMessageDigest(MessageDigest.getInstance(algorithmName, codeProvider.name()));
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}
			catch(NoSuchProviderException e)
			{
				throw new gnu.vm.jgnu.security.NoSuchProviderException(e.getMessage());
			}
			
		} else {
			try {
				return new JavaNativeMessageDigest(MessageDigest.getInstance(algorithmName));
			} catch (NoSuchAlgorithmException e) {
				throw new gnu.vm.jgnu.security.NoSuchAlgorithmException(e);
			}
		}
	}

	public CodeProvider getCodeProvider() {
		return codeProvider;
	}

}
