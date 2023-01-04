package com.distrimind.util.crypto;

/**
 *
 *
 * @author Jason Mahdjoub
 * @version 3.9
 * @since Utils 5.25.0
 */
public enum MessageDigestAlgorithmType {
	@Deprecated
	MD5(128, false),
	@Deprecated
	SHA1(160, false),
	SHA2_256(256, true),
	SHA2_384(384, true),
	SHA2_512(512, true),
	SHA2_512_224(224, true),
	SHA2_512_256(256, true),
	SHA3_256(256, true),
	SHA3_384(384, true),
	SHA3_512(512, true),
	WHIRLPOOL(512, true),
	BLAKE2B_160(160, false),
	BLAKE2B_256(256, true),
	BLAKE2B_384(384, true),
	BLAKE2B_512(512, true);

	private final int digestLengthBits, digestLengthBytes;
	private final boolean isSecuredForSignature;
	public static final int MAX_HASH_LENGTH_IN_BYTES =64;

	MessageDigestAlgorithmType(int digestLengthBits, boolean isSecuredForSignature) {
		this.digestLengthBits = digestLengthBits;
		this.digestLengthBytes = digestLengthBits/8;
		this.isSecuredForSignature = isSecuredForSignature;
	}

	public int getDigestLengthInBits()
	{
		return digestLengthBits;
	}

	public int getDigestLengthInBytes()
	{
		return digestLengthBytes;
	}

	public boolean isPostQuantumAlgorithm() {
		return isSecuredForSignature && digestLengthBits>=384;
	}

	public boolean isSecuredForSignature() {
		return isSecuredForSignature;
	}
}
