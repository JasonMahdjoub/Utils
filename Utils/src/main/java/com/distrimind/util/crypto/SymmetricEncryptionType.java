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

import com.distrimind.util.OS;
import com.distrimind.util.OSVersion;
import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.general.ChaCha20;
import org.bouncycastle.crypto.general.Serpent;
import org.bouncycastle.crypto.general.Twofish;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.AccessController;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivilegedAction;
import java.util.Arrays;

/**
 * List of symmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 5.1
 * @since Utils 1.4
 */
public enum SymmetricEncryptionType {

	AES_CBC_PKCS5Padding("AES", "CBC", "PKCS5Padding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_256, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false, (short)118, (short)146, (short)132, (short)148, (short)322, (short)583, true, true, true, true, true, true, (short)16, 1L<<32),
	AES_GCM("AES", "GCM", "NoPadding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_256, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, true, (short)40, (short)48, (short)58, (short) 58, (short)144, (short)613, true, true, true, true, true, true, (short)12, 1L<<32),
	AES_CTR("AES", "CTR", "NoPadding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_256, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false, (short)126, (short)112, (short)111, (short) 117, (short)560, (short)252, true, true, true, true, true, true, (short)16, 1L<<32),
	@Deprecated
	DES_CBC_PKCS5Padding("DES", "CBC", "PKCS5Padding", (short) 56, (short) 8, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_384, org.bouncycastle.crypto.general.DES.ALGORITHM, (short)64, false, (short)41, (short)39, (short)40, (short)37, (short)36, (short)45, true, true, true,true, true, true, (short)8, 1L<<32),
	@Deprecated
	DESede_CBC_PKCS5Padding("DESede", "CBC", "PKCS5Padding", (short) 168, (short) 24, CodeProvider.SunJCE, CodeProvider.SunJCE,SymmetricAuthentifiedSignatureType.HMAC_SHA2_384, org.bouncycastle.crypto.general.DES.ALGORITHM, (short)64, false, (short)16, (short)16, (short)15, (short)15, (short)17, (short)17, true, true, true,true, true, true, (short)8, 1L<<32),
	@Deprecated
	Blowfish_CBC_PKCS5Padding("Blowfish", "CBC", "PKCS5Padding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_384, org.bouncycastle.crypto.general.Blowfish.ALGORITHM, (short)64, false, (short)49, (short)51, (short)55, (short)51, (short)69, (short)71, true, true, true, true, false, true, (short)8, 1L<<32),
	GNU_AES_CBC_PKCS5Padding("AES", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false, (short)67, (short)63, (short)63, (short)64, (short)62, (short)4, true, true, true, true, true, true, (short)16, 1L<<32),
	GNU_TWOFISH_CBC_PKCS5Padding("TWOFISH","CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Twofish.ALGORITHM, (short)128, false, (short)57, (short)56, (short)55, (short)55, (short)66, (short)4, true, false, true, true, false, true, (short)16, 1L<<32),
	GNU_SERPENT_CBC_PKCS5Padding("Serpent", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Serpent.ALGORITHM, (short)128, false, (short)37, (short)37, (short)35, (short)37, (short)40, (short)4, false, false, false, false, false, false, (short)16, 1L<<32),
	GNU_ANUBIS_CBC_PKCS5Padding("Anubis", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, null, (short)128, false, (short)61, (short)58, (short)57, (short)57, (short)67, (short)4, false, false, false, false, false, false, (short)16, 1L<<32),
	GNU_SQUARE_CBC__PKCS5Padding("Square", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, null, (short)128, false, (short)69, (short)67, (short)61, (short)62, (short)84, (short)4, false, false, false, false, false, false, (short)16, 1L<<32),
	BC_FIPS_AES_CBC_PKCS7Padding("AES", "CBC", "PKCS7Padding", (short) 128, CodeProvider.BCFIPS, CodeProvider.BCFIPS, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false, (short)60, (short)75, (short)60, (short)73, (short)76, (short)67, true, true, true, true, true, true, (short)16, 1L<<32),
	BC_FIPS_AES_GCM("AES", "GCM", "NoPadding", (short) 128, CodeProvider.BCFIPS, CodeProvider.BCFIPS, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, true, (short)42, (short)48, (short)47, (short)57, (short)54, (short)55, true, true, true, true, true, true, (short)12, 1L<<32),
	BC_AES_EAX("AES", "EAX", "NoPadding", (short) 128, CodeProvider.BC, CodeProvider.BC, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, true, (short)36, (short)43, (short)44, (short)39, (short)35, (short)35, true, true, true, true, true, true, (short)16, 1L<<32),
	BC_FIPS_AES_CTR("AES", "CTR", "NoPadding", (short) 128, CodeProvider.BCFIPS, CodeProvider.BCFIPS, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false, (short)50, (short)64, (short)52, (short)65, (short)63, (short)48, true, true, true, true, true, true, (short)16, 1L<<32),
	BC_TWOFISH_CBC_PKCS7Padding("TWOFISH", "CBC", "PKCS7Padding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Twofish.ALGORITHM, (short)128, false, (short)45, (short)56, (short)45, (short)57, (short)71, (short)72, true, false, true, true, false, true , (short)16, 1L<<32),
	BC_TWOFISH_GCM("TWOFISH", "GCM", "NoPadding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Twofish.ALGORITHM, (short)128, true, (short)35, (short)41, (short)39, (short)46, (short)54, (short)56, true, false, true, true, false, true, (short)12, 1L<<32),
	BC_TWOFISH_EAX("TWOFISH", "EAX", "NoPadding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Twofish.ALGORITHM, (short)128, true, (short)27, (short)30, (short)28, (short)31, (short)34, (short)35, true, false, true, true, false, true, (short)16, 1L<<32),
	BC_TWOFISH_CTR("TWOFISH", "CTR", "NoPadding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Twofish.ALGORITHM, (short)128, false, (short)35, (short)44, (short)42, (short)50, (short)68, (short)70, true, false, true, true, false, true, (short)16, 1L<<32),
	BC_SERPENT_CBC_PKCS7Padding("Serpent", "CBC", "PKCS7Padding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Serpent.ALGORITHM, (short)128, false, (short)40, (short)42,(short)39, (short)41, (short)53, (short)47, false, false, false, false, false, false, (short)16, 1L<<32),
	BC_SERPENT_CTR("Serpent", "CTR", "NoPadding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Serpent.ALGORITHM, (short)128, false, (short)33, (short)37,(short)35, (short)40, (short)49, (short)50, false, false, false, false, false, false, (short)16, 1L<<32),
	BC_SERPENT_GCM("Serpent", "GCM", "NoPadding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Serpent.ALGORITHM, (short)128, true, (short)31, (short)35, (short)33, (short)38, (short)43, (short)43, false, false, false, false, false, false, (short)12, 1L<<32),
	BC_SERPENT_EAX("Serpent", "EAX", "NoPadding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_512, Serpent.ALGORITHM, (short)128, true, (short)22, (short)24, (short)23, (short)24, (short)26, (short)26, false, false, false, false, false, false, (short)16, 1L<<32),
	CHACHA20_NO_RANDOM_ACCESS("ChaCha20", "", "", (short) 256, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_256, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)512, false, (short)113, (short)79, (short)113, (short) 79, (short)278, (short)274, false, false, false,  true, false, false, (short)12, 13_000_000_000L),
	CHACHA20_POLY1305("ChaCha20-Poly1305", "", "", (short) 256, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA2_256, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)512, true, (short)113, (short)79, (short)113, (short) 79, (short)204, (short)192, false, false, false,  true, false, false, (short)12, 13_000_000_000L),
	BC_CHACHA20_NO_RANDOM_ACCESS("ChaCha20", "", "", (short) 256, CodeProvider.BC, CodeProvider.BC, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_256, ChaCha20.ALGORITHM, (short)512, false, (short)75, (short)78, (short)75, (short) 78, (short)75, (short)78, false, false, false,  true, false, false, (short)12, 13_000_000_000L),
	BC_CHACHA20_POLY1305("ChaCha20-Poly1305", "", "", (short) 256, CodeProvider.BC, CodeProvider.BC, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA2_256, ChaCha20.ALGORITHM, (short)512, true, (short)114, (short)81, (short)114, (short) 81, (short)114, (short)81, false, false, false,  true, false, false, (short)12, 13_000_000_000L),
	DEFAULT(AES_CTR);
	

	static Object decodeGnuSecretKey(byte[] encodedSecretKey, String algorithmName) {
		return decodeGnuSecretKey(encodedSecretKey, 0, encodedSecretKey.length, algorithmName);
	}

	@SuppressWarnings("SameParameterValue")
	static Object decodeGnuSecretKey(byte[] encodedSecretKey, int off, int len, String algorithmName) {
		//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
		return GnuFunctions.secretKeySpecGetInstance(encodedSecretKey, off, len, algorithmName);
	}

	static SecretKey decodeNativeSecretKey(byte[] encodedSecretKey, String algorithmName) {
		return decodeNativeSecretKey(encodedSecretKey, 0, encodedSecretKey.length, algorithmName);
	}

	@SuppressWarnings("SameParameterValue")
	static SecretKey decodeNativeSecretKey(byte[] encodedSecretKey, int off, int len, String algorithmName) {
		//byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
		
		return new SecretKeySpec(encodedSecretKey, off, len, algorithmName);
	}
	
	static org.bouncycastle.crypto.SymmetricSecretKey decodeBCSecretKey(Algorithm algorithm, byte[] encodedSecretKey) {
        return new org.bouncycastle.crypto.SymmetricSecretKey(algorithm, encodedSecretKey);
		//return decodeBCSecretKey(algorithm, encodedSecretKey, 0, encodedSecretKey.length, algorithmName);
	}
	/*@SuppressWarnings("SameParameterValue")
	static org.bouncycastle.crypto.SymmetricSecretKey decodeBCSecretKey(Algorithm algorithm, byte[] encodedSecretKey, int off, int len, String algorithmName) {
		//final byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
		
		return new org.bouncycastle.crypto.SymmetricSecretKey(algorithmName, encodedSecretKey);
	}*/

	public SymmetricSecretKey generateSecretKeyFromByteArray(byte[] tab) throws NoSuchProviderException, NoSuchAlgorithmException {
		return generateSecretKeyFromByteArray(tab, getDefaultKeySizeBits());
	}

	public SymmetricSecretKey generateSecretKeyFromByteArray(byte[] tab, short keySizeBits) throws NoSuchProviderException, NoSuchAlgorithmException {
		if (keySizeBits<56 || keySizeBits>512)
			throw new IllegalArgumentException();
		AbstractMessageDigest md=(keySizeBits>256?MessageDigestType.SHA3_512:MessageDigestType.SHA3_256).getMessageDigestInstance();
		md.update(tab);
		byte[] d=md.digest();
		return new SymmetricSecretKey(this, Arrays.copyOfRange(d, 0, keySizeBits/8), keySizeBits);
	}

	static byte[] encodeGnuSecretKey(Object key) {
		return GnuFunctions.keyGetEncoded(key);
		//return Bits.concateEncodingWithShortSizedTabs(algorithmName.encode(), key.keyGetEncoded());
	}

	static byte[] encodeSecretKey(SecretKey key) {
		return key.getEncoded();
		//return Bits.concateEncodingWithShortSizedTabs(algorithmName.encode(), key.keyGetEncoded());
	}
	
	static byte[] encodeSecretKey(final org.bouncycastle.crypto.SymmetricSecretKey key)
	{
		return AccessController.doPrivileged(new PrivilegedAction<byte[]>() {
			public byte[] run() {
				return key.getKeyBytes();
			}
		});
		/*return Bits.concateEncodingWithShortSizedTabs(algorithmName.encode(), AccessController.doPrivileged(new PrivilegedAction<byte[]>() {
            public byte[] run() {
                return key.getKeyBytes();
            }
        }));*/
	}

	static SymmetricEncryptionType valueOf(int ordinal) throws IllegalArgumentException {
		for (SymmetricEncryptionType a : values()) {
			if (a.ordinal() == ordinal)
				return a;
		}
		throw new IllegalArgumentException();
	}

	// TODO voir si ajout de GNU crypto ou de Twofish
	// TODO revoir la regenération de l'IV
	private final String algorithmName;

	private final String blockMode;

	private final String padding;

	private final short keySizeBits;

	private final short keySizeBytes;

	private final CodeProvider codeProviderForEncryption, CodeProviderForKeyGenerator;

	private final SymmetricAuthentifiedSignatureType defaultSignature;
	
	private final Algorithm bcAlgorithm;
	
	private final short blockSizeBits;
	
	private final boolean authenticated;
	
	
	private final short encodingSpeedIndexJava7;
	
	private final short decodingSpeedIndexJava7;

	private final short encodingSpeedIndexJava8;
	
	private final short decodingSpeedIndexJava8;

	private final short encodingSpeedIndexJava9;
	
	private final short decodingSpeedIndexJava9;
	
	private final byte maxModeCounterSize;


	private final boolean timingAttackPossible;
	private final boolean cacheAttackPossible;
	private final boolean powerMonitoringAttackPossible;
	private final boolean electromagneticAttackPossible;
	private final boolean acousticAttackPossible;
	private final boolean dfaAttackPossible;//Differential fault analysis
	private final short ivLengthBytes;
	private long maxIVGenerationWithOneSecretKey;
	private static final boolean invalidOSForChaCha =(OSVersion.getCurrentOSVersion().getOS()!=OS.ANDROID && OS.getCurrentJREVersionByte()<11) || (OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID && OSVersion.getCurrentOSVersion().compareTo(OSVersion.ANDROID_28_P)<0);

	public boolean equals(SymmetricEncryptionType o)
	{
		if (o==this)
			return true;
		if (o==null)
			return false;
		//noinspection StringEquality
		return o.algorithmName==this.algorithmName && o.blockMode==this.blockMode && o.padding==this.padding && o.codeProviderForEncryption==this.codeProviderForEncryption;
	}


	SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits,
			CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenerator, SymmetricAuthentifiedSignatureType defaultSignature, Algorithm bcAlgorithm, short blockSize, boolean authentified, short encodingSpeedIndexJava7, short decodingSpeedIndexJava7, short encodingSpeedIndexJava8, short decodingSpeedIndexJava8, short encodingSpeedIndexJava9, short decodingSpeedIndexJava9,
							boolean timingAttackPossible,
							boolean cacheAttackPossible,
							boolean powerMonitoringAttackPossible, boolean electromagneticAttackPossible, boolean acousticAttackPossible,
							boolean dfaAttackPossible, short ivLengthBytes, long maxIVGenerationWithOneSecretKey) {
		this(algorithmName, blockMode, padding, keySizeBits, (short) (keySizeBits / 8), codeProviderForEncryption, codeProviderForKeyGenerator, defaultSignature, bcAlgorithm, blockSize, authentified, encodingSpeedIndexJava7, decodingSpeedIndexJava7, encodingSpeedIndexJava8, decodingSpeedIndexJava8, encodingSpeedIndexJava9, decodingSpeedIndexJava9,
				timingAttackPossible, cacheAttackPossible, powerMonitoringAttackPossible, electromagneticAttackPossible, acousticAttackPossible, dfaAttackPossible, ivLengthBytes, maxIVGenerationWithOneSecretKey);
	}
	SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits,
			short keySizeBytes, CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenerator, SymmetricAuthentifiedSignatureType defaultSignature, Algorithm bcAlgorithm, short blockSize, boolean authentified, short encodingSpeedIndexJava7, short decodingSpeedIndexJava7, short encodingSpeedIndexJava8, short decodingSpeedIndexJava8, short encodingSpeedIndexJava9, short decodingSpeedIndexJava9,
							boolean timingAttackPossible, boolean cacheAttackPossible,
							boolean powerMonitoringAttackPossible, boolean electromagneticAttackPossible, boolean acousticAttackPossible,
							boolean dfaAttackPossible, short ivLengthBytes, long maxIVGenerationWithOneSecretKey) {
		if (algorithmName==null)
			throw new NullPointerException();
		this.algorithmName = algorithmName;
		this.blockMode = blockMode;
		this.padding = padding;
		this.keySizeBits = keySizeBits;
		this.keySizeBytes = keySizeBytes;
		this.codeProviderForEncryption = codeProviderForEncryption;
		this.CodeProviderForKeyGenerator=codeProviderForKeyGenerator;
		this.defaultSignature = defaultSignature;
		this.bcAlgorithm=bcAlgorithm;
		this.blockSizeBits=blockSize;
		this.authenticated=authentified;
		this.encodingSpeedIndexJava7=encodingSpeedIndexJava7;
		this.decodingSpeedIndexJava7=decodingSpeedIndexJava7;
		this.encodingSpeedIndexJava8=encodingSpeedIndexJava8;
		this.decodingSpeedIndexJava8=decodingSpeedIndexJava8;
		this.encodingSpeedIndexJava9=encodingSpeedIndexJava9;
		this.decodingSpeedIndexJava9=decodingSpeedIndexJava9;
		if (blockMode.toUpperCase().equals("CTR") && !codeProviderForEncryption.equals(CodeProvider.SunJCE))
			maxModeCounterSize=8;
		else if (this.algorithmName.toUpperCase().equals("CHACHA20"))
			maxModeCounterSize=4;
		else
			maxModeCounterSize=0;
		this.timingAttackPossible=timingAttackPossible;
		this.cacheAttackPossible=cacheAttackPossible;
		this.powerMonitoringAttackPossible=powerMonitoringAttackPossible;
		this.electromagneticAttackPossible=electromagneticAttackPossible;
		this.acousticAttackPossible=acousticAttackPossible;
		this.dfaAttackPossible=dfaAttackPossible;
		this.ivLengthBytes = ivLengthBytes;
		this.maxIVGenerationWithOneSecretKey=maxIVGenerationWithOneSecretKey;
	}

	@SuppressWarnings("CopyConstructorMissesField")
	SymmetricEncryptionType(SymmetricEncryptionType type) {
		this(type.algorithmName, type.blockMode, type.padding, type.keySizeBits, type.keySizeBytes, type.codeProviderForEncryption, type.CodeProviderForKeyGenerator,
				type.defaultSignature, type.bcAlgorithm, type.blockSizeBits, type.authenticated, type.encodingSpeedIndexJava7, type.decodingSpeedIndexJava7, type.encodingSpeedIndexJava8, type.decodingSpeedIndexJava8, type.encodingSpeedIndexJava9, type.decodingSpeedIndexJava9,
				type.timingAttackPossible, type.cacheAttackPossible, type.powerMonitoringAttackPossible, type.electromagneticAttackPossible, type.acousticAttackPossible, type.dfaAttackPossible, type.ivLengthBytes, type.maxIVGenerationWithOneSecretKey);
	}

	public String getAlgorithmName() {
		return algorithmName;
	}

	public String getBlockMode() {
		return blockMode;
	}

	public boolean isAuthenticatedAlgorithm()
	{
		return authenticated;
	}
	
	
	public short getBlockSizeBits() {
		return blockSizeBits;
	}

	private String getCipherAlgorithmName()
	{
		if (blockMode.equals(""))
			return algorithmName;
		else
			return algorithmName + "/" + blockMode + "/" + padding;
	}

	public AbstractCipher getCipherInstance() throws IOException {
		CodeProvider.ensureProviderLoaded(codeProviderForEncryption);
		try {
			if (codeProviderForEncryption == CodeProvider.GNU_CRYPTO) {
				return new GnuCipher(GnuFunctions.cipherGetInstance(getCipherAlgorithmName()));

			} else if (codeProviderForEncryption == CodeProvider.BCFIPS || codeProviderForEncryption == CodeProvider.BC) {
				if (this.equals(BC_CHACHA20_POLY1305))
					return new JavaNativeCipher(this, Cipher.getInstance(getCipherAlgorithmName(), codeProviderForEncryption.name()));
				else
					return new BCCipher(this);

			} else {
				if (this.equals(CHACHA20_NO_RANDOM_ACCESS) && invalidOSForChaCha)
					return BC_CHACHA20_NO_RANDOM_ACCESS.getCipherInstance();
				else if (this.equals(CHACHA20_POLY1305) && invalidOSForChaCha)
					return BC_CHACHA20_POLY1305.getCipherInstance();
				if (OS.getCurrentJREVersionDouble() < 1.8 && this.equals(AES_GCM))
					return BC_FIPS_AES_GCM.getCipherInstance();
				return new JavaNativeCipher(this, Cipher.getInstance(getCipherAlgorithmName(), codeProviderForEncryption.name()));
			}
		}
		catch(NoSuchAlgorithmException | NoSuchPaddingException | NoSuchProviderException e)
		{
			throw new IOException(e);
		}
	}

	public short getDefaultKeySizeBits() {
		return keySizeBits;
	}

	public short getDefaultKeySizeBytes() {
		return keySizeBytes;
	}

	public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random) throws NoSuchAlgorithmException, NoSuchProviderException {
		return getKeyGenerator(random, keySizeBits);
	}

	public AbstractKeyGenerator getKeyGenerator(AbstractSecureRandom random, short keySizeBits)
			throws NoSuchAlgorithmException, NoSuchProviderException {
		CodeProvider.ensureProviderLoaded(CodeProviderForKeyGenerator);
		AbstractKeyGenerator res ;
		if (CodeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			res = new GnuKeyGenerator(this, GnuFunctions.keyGeneratorGetInstance(algorithmName));
		} else if (CodeProviderForKeyGenerator == CodeProvider.BCFIPS || CodeProviderForKeyGenerator == CodeProvider.BC) {

			res = new BCKeyGenerator(this);

		} else {
			if (this.equals(CHACHA20_NO_RANDOM_ACCESS) && invalidOSForChaCha)
				return BC_CHACHA20_NO_RANDOM_ACCESS.getKeyGenerator(random, keySizeBits);
			else if (this.equals(CHACHA20_POLY1305) && invalidOSForChaCha)
				return BC_CHACHA20_POLY1305.getKeyGenerator(random, keySizeBits);
			if (OS.getCurrentJREVersionDouble()<1.8 && this.getAlgorithmName().equals(AES_GCM.getAlgorithmName()) && this.getBlockMode().equals(AES_GCM.getBlockMode()) && this.getPadding().equals(AES_GCM.getPadding()))
				return BC_FIPS_AES_GCM.getKeyGenerator(random, keySizeBits);
			String alg=algorithmName;
			if (alg.equals(CHACHA20_POLY1305.algorithmName))
				alg=CHACHA20_NO_RANDOM_ACCESS.algorithmName;
			res = new JavaNativeKeyGenerator(this, javax.crypto.KeyGenerator.getInstance(alg, CodeProviderForKeyGenerator.checkProviderWithCurrentOS().name()));
		}
		res.init(keySizeBits, random);
		return res;

	}

	public String getPadding() {
		return padding;
	}

	public CodeProvider getCodeProviderForEncryption() {
		return codeProviderForEncryption;
	}
	public CodeProvider getCodeProviderForKeyGenerator() {
		return CodeProviderForKeyGenerator;
	}

	public SymmetricAuthentifiedSignatureType getDefaultSignatureAlgorithm() {
		return defaultSignature;
	}

	public SymmetricSecretKey getSymmetricSecretKey(byte[] secretKey) {
		return this.getSymmetricSecretKey(secretKey, getDefaultKeySizeBits());
	}

	public SymmetricSecretKey getSymmetricSecretKey(byte[] secretKey, short keySizeBits) {
		if (CodeProviderForKeyGenerator == CodeProvider.BCFIPS || CodeProviderForKeyGenerator == CodeProvider.SunJCE) {
			return new SymmetricSecretKey(this, new SecretKeySpec(secretKey, getAlgorithmName()), keySizeBits);
		} else if (CodeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			return new SymmetricSecretKey(this,GnuFunctions.secretKeySpecGetInstance(secretKey, getAlgorithmName()), keySizeBits);
		} else
			throw new IllegalAccessError();

	}
	
	Algorithm getBouncyCastleAlgorithm()
	{
		return bcAlgorithm;
	}
	
	public int getIVSizeBytes()
	{
		return ivLengthBytes;
	}
	
	public boolean supportAssociatedData()
	{
		return isAuthenticatedAlgorithm();
	}
	

	
	public short getEncodingSpeedIndex()
	{
		
		return getEncodingSpeedIndex(OS.getCurrentJREVersionByte(), OS.supportAESIntrinsicsAcceleration());
	}
	public short getDecodingSpeedIndex()
	{
		return getDecodingSpeedIndex(OS.getCurrentJREVersionByte(), OS.supportAESIntrinsicsAcceleration());
	}
	
	public short getAverageSpeedIndex()
	{
		return (short)( (getEncodingSpeedIndex()+getDecodingSpeedIndex())/2);
	}
	public short getEncodingSpeedIndex(byte javaVersion, boolean supportAESIntrinsics)
	{
		if (!supportAESIntrinsics)
			javaVersion=7;
			
		if (javaVersion<=7)
			return encodingSpeedIndexJava7;
		else if (javaVersion==8)
			return encodingSpeedIndexJava8;
		else
			return encodingSpeedIndexJava9;
	}
	public short getDecodingSpeedIndex(byte javaVersion, boolean supportAESIntrinsics)
	{
		if (!supportAESIntrinsics)
			javaVersion=7;
		if (javaVersion<=7)
			return decodingSpeedIndexJava7;
		else if (javaVersion==8)
			return decodingSpeedIndexJava8;
		else
			return decodingSpeedIndexJava9;
	}
	
	public short getAverageSpeedIndex(byte javaVersion, boolean supportAESIntrinsics)
	{
		return (short)( (getEncodingSpeedIndex(javaVersion, supportAESIntrinsics)+getDecodingSpeedIndex(javaVersion, supportAESIntrinsics))/2);
	}
	
	public boolean isBlockModeSupportingCounter()
	{
		return maxModeCounterSize>0;
	}
	public byte getMaxCounterSizeInBytesUsedWithBlockMode()
	{
		return maxModeCounterSize;
	}
	
	public boolean isPostQuantumAlgorithm(short keySizeBits) 
	{
		if (keySizeBits<256)
			return false;
		return getBlockSizeBits() >= 128;
	}

	public boolean supportRandomReadWrite()
	{
		return /*this.algorithmName.equals(CHACHA20.algorithmName) || */blockMode.equals("CTR");
	}

	public boolean timingAttackPossibleWithSomeImplementations()
	{
		return timingAttackPossible;
	}

	public boolean timingAttackPossibleIntoThisMachine()
	{
		if (timingAttackPossible)
		{
			if (this.algorithmName.equals(AES_CTR.algorithmName) && this.codeProviderForEncryption==CodeProvider.SunJCE && OS.supportAESIntrinsicsAcceleration())
			{
				if (OS.getCurrentJREVersionDouble()<1.8 && this.equals(AES_GCM))
					return BC_FIPS_AES_GCM.timingAttackPossibleIntoThisMachine();
				return false;
			}
			else
				return true;
		}
		else
			return false;
	}

	public boolean isCacheAttackPossible() {
		return cacheAttackPossible;
	}

	public boolean isPowerMonitoringAttackPossible() {
		return powerMonitoringAttackPossible;
	}

	public boolean isElectromagneticAttackPossible() {
		return electromagneticAttackPossible;
	}

	public boolean isAcousticAttackPossible() {
		return acousticAttackPossible;
	}

	public boolean isDfaAttackPossible() {
		return dfaAttackPossible;
	}

	public long getMaxIVGenerationWithOneSecretKey()
	{
		return maxIVGenerationWithOneSecretKey;
	}
	void setMaxIVGenerationWithOneSecretKey(long maxIVGenerationWithOneSecretKey)
	{
		this.maxIVGenerationWithOneSecretKey=maxIVGenerationWithOneSecretKey;
	}
}
