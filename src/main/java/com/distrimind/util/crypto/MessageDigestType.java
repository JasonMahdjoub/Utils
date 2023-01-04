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

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 2.3
 * @since Utils 1.4
 */
public enum MessageDigestType {
	@Deprecated
	MD5("MD5", CodeProvider.SUN, 128, false),
	@Deprecated
	SHA1("SHA", CodeProvider.SUN, 160, false),
	SHA2_256("SHA-256", CodeProvider.SUN, 256, true),
	SHA2_384("SHA-384",	CodeProvider.SUN, 384,true),
	SHA2_512("SHA-512", CodeProvider.SUN, 512,true),
	@Deprecated
	GNU_SHA2_256("SHA-256", CodeProvider.GNU_CRYPTO, 256,true),
	@Deprecated
	GNU_SHA2_384("SHA-384", CodeProvider.GNU_CRYPTO, 384,true),
	@Deprecated
	GNU_SHA2_512("SHA-512", CodeProvider.GNU_CRYPTO, 512,true),
	@Deprecated
	GNU_WHIRLPOOL("WHIRLPOOL", CodeProvider.GNU_CRYPTO, 512,true),
	BC_FIPS_SHA2_256("SHA-256", CodeProvider.BCFIPS, 256,true),
	BC_FIPS_SHA2_384("SHA-384",CodeProvider.BCFIPS, 384,true),
	BC_FIPS_SHA2_512("SHA-512", CodeProvider.BCFIPS, 512,true),
	BC_FIPS_SHA2_512_224("SHA-512/224", CodeProvider.BCFIPS, 224,true),
	BC_FIPS_SHA2_512_256("SHA-512/256", CodeProvider.BCFIPS, 256,true),
	BC_FIPS_SHA3_256("SHA3-256", CodeProvider.BCFIPS, 256,true),
	BC_FIPS_SHA3_384("SHA3-384",CodeProvider.BCFIPS, 384,true),
	BC_FIPS_SHA3_512("SHA3-512", CodeProvider.BCFIPS, 512,true),
	BC_WHIRLPOOL("WHIRLPOOL",CodeProvider.BC, 512,true),
	BC_BLAKE2B_160("BLAKE2B-160", CodeProvider.BC, 160, false),
	BC_BLAKE2B_256("BLAKE2B-256", CodeProvider.BC, 256,true),
	BC_BLAKE2B_384("BLAKE2B-384", CodeProvider.BC, 384,true),
	BC_BLAKE2B_512("BLAKE2B-512", CodeProvider.BC, 512,true),
    SHA2_512_224("SHA-512/224", CodeProvider.SUN, 224,false, BC_FIPS_SHA2_512_224),
    SHA2_512_256("SHA-512/256",	CodeProvider.SUN, 256,true, BC_FIPS_SHA2_512_256),
	SHA3_256("SHA3-256", CodeProvider.SUN, 256,true, BC_FIPS_SHA3_256),
	SHA3_384("SHA3-384",	CodeProvider.SUN, 384,true, BC_FIPS_SHA3_384),
	SHA3_512("SHA3-512", CodeProvider.SUN, 512,true, BC_FIPS_SHA3_512),
	DEFAULT(SHA2_384);


	public static int getMaxDigestLengthInBits()
	{
		return MAX_HASH_LENGTH_IN_BYTES*8;
	}
	public static int getMaxDigestLengthInBytes()
	{
		return MAX_HASH_LENGTH_IN_BYTES;
	}
	private final String algorithmName;

	private final CodeProvider codeProvider;
	
	private final int digestLengthBits, digestLengthBytes;

	private final MessageDigestType replacer;

	private final boolean isSecuredForSignature;

	public static final int MAX_HASH_LENGTH_IN_BYTES =64;

	private MessageDigestType derivedType;

	public boolean equals(MessageDigestType type)
	{
		if (type==null)
			return false;
		//noinspection StringEquality
		return type.algorithmName==this.algorithmName && type.codeProvider==this.codeProvider;
	}

	MessageDigestType(MessageDigestType type) {
		this(type.algorithmName, type.codeProvider, type.digestLengthBits, type.isSecuredForSignature, type.replacer);
		this.derivedType=type;
	}

	MessageDigestType(String algorithmName, CodeProvider codeProvider, int digestLengthBits, boolean isSecuredForSignature) {
		this(algorithmName, codeProvider, digestLengthBits, isSecuredForSignature, null);
	}

	MessageDigestType(String algorithmName, CodeProvider codeProvider, int digestLengthBits, boolean isSecuredForSignature, MessageDigestType replacer) {
		this.algorithmName = algorithmName;
		this.codeProvider = codeProvider;
		this.digestLengthBits=digestLengthBits;
		this.isSecuredForSignature=isSecuredForSignature;
		this.replacer=replacer;
		this.digestLengthBytes=this.digestLengthBits/8;
		this.derivedType=this;
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public int getDigestLengthInBits()
	{
		return digestLengthBits;
	}

	public int getDigestLengthInBytes()
	{
		return digestLengthBytes;
	}
	
	public AbstractMessageDigest getMessageDigestInstance() throws NoSuchAlgorithmException, NoSuchProviderException {
		//CodeProvider.ensureProviderLoaded(codeProvider);
		if (codeProvider == CodeProvider.GNU_CRYPTO) {
			return new GnuMessageDigest(this, GnuFunctions.digestGetInstance(algorithmName));
		} else if (codeProvider == CodeProvider.BCFIPS || codeProvider == CodeProvider.BC) {
			return new JavaNativeMessageDigest(this, MessageDigest.getInstance(algorithmName, codeProvider.getCompatibleProvider()));

		} else {
			try {
				return new JavaNativeMessageDigest(this, MessageDigest.getInstance(algorithmName, codeProvider.getCompatibleProvider()));
			} catch (NoSuchAlgorithmException | NoSuchProviderException e) {
				if (replacer!=null)
					return replacer.getMessageDigestInstance();
				throw e;
			}
		}
	}

	public CodeProvider getCodeProvider() {
		return codeProvider;
	}

	public boolean isPostQuantumAlgorithm() {
		return isSecuredForSignature && digestLengthBits>=384;
	}

	public boolean isSecuredForSignature() {
		return isSecuredForSignature;
	}

	public MessageDigestType getDerivedType() {
		return derivedType;
	}
}
