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

import java.security.AccessController;
import java.security.PrivilegedAction;

import javax.crypto.Cipher;

import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnux.crypto.KeyGenerator;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.Algorithm;
import org.bouncycastle.crypto.general.Serpent;
import org.bouncycastle.crypto.general.Twofish;

import com.distrimind.util.Bits;
import com.distrimind.util.OSValidator;

/**
 * List of symmetric encryption algorithms
 * 
 * @author Jason Mahdjoub
 * @version 3.0
 * @since Utils 1.4
 */
public enum SymmetricEncryptionType {

	AES_CBC_PKCS5Padding("AES", "CBC", "PKCS5Padding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA_384, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false), 
	AES_GCM("AES", "GCM", "NoPadding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA_384, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, true),
	@Deprecated
	DES_CBC("DES", "CBC", "PKCS5Padding", (short) 56, (short) 8, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA_384, org.bouncycastle.crypto.general.DES.ALGORITHM, (short)64, false), 
	@Deprecated
	DESede_CBC("DESede", "CBC", "PKCS5Padding", (short) 168, (short) 24, CodeProvider.SunJCE, CodeProvider.SunJCE,SymmetricAuthentifiedSignatureType.HMAC_SHA_384, org.bouncycastle.crypto.general.DES.ALGORITHM, (short)64, false), 
	@Deprecated
	Blowfish_CBC("Blowfish", "CBC", "PKCS5Padding", (short) 128, CodeProvider.SunJCE, CodeProvider.SunJCE, SymmetricAuthentifiedSignatureType.HMAC_SHA_384, org.bouncycastle.crypto.general.Blowfish.ALGORITHM, (short)64, false), 
	GNU_AES_CBC_PKCS5Padding("AES", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false), 
	GNU_TWOFISH_CBC_PKCS5Padding("TWOFISH","CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Twofish.ALGORITHM, (short)128, false), 
	GNU_SERPENT_CBC_PKCS5Padding("Serpent", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Serpent.ALGORITHM, (short)128, false), 
	GNU_ANUBIS_CBC_PKCS5Padding("Anubis", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, null, (short)128, false), 
	GNU_SQUARE_CBC__PKCS5Padding("Square", "CBC", "PKCS5Padding", (short) 128, CodeProvider.GNU_CRYPTO, CodeProvider.GNU_CRYPTO, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, null, (short)128, false), 
	BC_FIPS_AES_CBC_PKCS7Padding("AES", "CBC", "PKCS7Padding", (short) 128, CodeProvider.BCFIPS, CodeProvider.BCFIPS, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, false),
	BC_FIPS_AES_GCM("AES", "GCM", "NoPadding", (short) 128, CodeProvider.BCFIPS, CodeProvider.BCFIPS, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, true),
	BC_AES_EAX("AES", "EAX", "NoPadding", (short) 128, CodeProvider.BC, CodeProvider.BC, SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, org.bouncycastle.crypto.general.AES.ALGORITHM, (short)128, true),
	BC_TWOFISH_CBC_PKCS7Padding("TWOFISH", "CBC", "PKCS7Padding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Twofish.ALGORITHM, (short)128, false),
	BC_TWOFISH_GCM("TWOFISH", "GCM", "NoPadding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Twofish.ALGORITHM, (short)128, true),
	BC_TWOFISH_EAX("TWOFISH", "EAX", "NoPadding", (short) 128,CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Twofish.ALGORITHM, (short)128, true),
	BC_SERPENT_CBC_PKCS7Padding("Serpent", "CBC", "PKCS7Padding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Serpent.ALGORITHM, (short)128, false),
	BC_SERPENT_GCM("Serpent", "GCM", "NoPadding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Serpent.ALGORITHM, (short)128, true),
	BC_SERPENT_EAX("Serpent", "EAX", "NoPadding",(short) 128, CodeProvider.BC, CodeProvider.BC,SymmetricAuthentifiedSignatureType.BC_FIPS_HMAC_SHA_512, Serpent.ALGORITHM, (short)128, true),
	DEFAULT(AES_GCM);
	
		
	static gnu.vm.jgnux.crypto.SecretKey decodeGnuSecretKey(byte[] encodedSecretKey) {
		return decodeGnuSecretKey(encodedSecretKey, 0, encodedSecretKey.length);
	}

	static gnu.vm.jgnux.crypto.SecretKey decodeGnuSecretKey(byte[] encodedSecretKey, int off, int len) {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
		return new gnu.vm.jgnux.crypto.spec.SecretKeySpec(parts[1], new String(parts[0]));
	}

	static SecretKey decodeNativeSecretKey(byte[] encodedSecretKey) {
		return decodeNativeSecretKey(encodedSecretKey, 0, encodedSecretKey.length);
	}

	static SecretKey decodeNativeSecretKey(byte[] encodedSecretKey, int off, int len) {
		byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
		
		return new SecretKeySpec(parts[1], new String(parts[0]).split("/")[0]);
	}
	
	static org.bouncycastle.crypto.SymmetricSecretKey decodeBCSecretKey(Algorithm algorithm, byte[] encodedSecretKey) {
		
		return decodeBCSecretKey(algorithm, encodedSecretKey, 0, encodedSecretKey.length);
	}
	static org.bouncycastle.crypto.SymmetricSecretKey decodeBCSecretKey(Algorithm algorithm, byte[] encodedSecretKey, int off, int len) {
		final byte[][] parts = Bits.separateEncodingsWithShortSizedTabs(encodedSecretKey, off, len);
		
		return new org.bouncycastle.crypto.SymmetricSecretKey(algorithm, parts[1]);
	}
	
	

	static byte[] encodeSecretKey(gnu.vm.jgnux.crypto.SecretKey key) {
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	}

	static byte[] encodeSecretKey(SecretKey key) {
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getBytes(), key.getEncoded());
	}
	
	static byte[] encodeSecretKey(final org.bouncycastle.crypto.SymmetricSecretKey key)
	{
		
		return Bits.concateEncodingWithShortSizedTabs(key.getAlgorithm().getName().getBytes(), AccessController.doPrivileged(new PrivilegedAction<byte[]>()
        {
            public byte[] run()
            {
                return key.getKeyBytes();
            }
        }));
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

	private SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits,
			CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenerator, SymmetricAuthentifiedSignatureType defaultSignature, Algorithm bcAlgorithm, short blockSize, boolean authentified) {
		this(algorithmName, blockMode, padding, keySizeBits, (short) (keySizeBits / 8), codeProviderForEncryption, codeProviderForKeyGenerator, defaultSignature, bcAlgorithm, blockSize, authentified);
	}

	private SymmetricEncryptionType(String algorithmName, String blockMode, String padding, short keySizeBits,
			short keySizeBytes, CodeProvider codeProviderForEncryption, CodeProvider codeProviderForKeyGenerator, SymmetricAuthentifiedSignatureType defaultSignature, Algorithm bcAlgorithm, short blockSize, boolean authentified) {
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
	}

	private SymmetricEncryptionType(SymmetricEncryptionType type) {
		this(type.algorithmName, type.blockMode, type.padding, type.keySizeBits, type.keySizeBytes, type.codeProviderForEncryption, type.CodeProviderForKeyGenerator,
				type.defaultSignature, type.bcAlgorithm, type.blockSizeBits, type.authenticated);
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

	public AbstractCipher getCipherInstance() throws NoSuchAlgorithmException, NoSuchPaddingException, NoSuchProviderException {
		if (codeProviderForEncryption == CodeProvider.GNU_CRYPTO) {
			return new GnuCipher(
					gnu.vm.jgnux.crypto.Cipher.getInstance(algorithmName + "/" + blockMode + "/" + padding));
		} else if (codeProviderForEncryption == CodeProvider.BCFIPS || codeProviderForEncryption == CodeProvider.BC) {

			CodeProvider.ensureBouncyCastleProviderLoaded();
			return new BCCipher(this);
					
		} else {
			if (OSValidator.getCurrentJREVersion()<1.8 && this.getAlgorithmName().equals(AES_GCM.getAlgorithmName()) && this.getBlockMode().equals(AES_GCM.getBlockMode()) && this.getPadding().equals(AES_GCM.getPadding()))
					return BC_FIPS_AES_GCM.getCipherInstance();
			try {
				return new JavaNativeCipher(this, Cipher.getInstance(algorithmName + "/" + blockMode + "/" + padding, codeProviderForEncryption.name()));
			} catch (java.security.NoSuchAlgorithmException e) {
				throw new NoSuchAlgorithmException(e);
			} catch (javax.crypto.NoSuchPaddingException e) {
				throw new NoSuchPaddingException(e.getMessage());
			}catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
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
		AbstractKeyGenerator res = null;
		if (CodeProviderForKeyGenerator == CodeProvider.GNU_CRYPTO) {
			res = new GnuKeyGenerator(this, KeyGenerator.getInstance(algorithmName));
		} else if (CodeProviderForKeyGenerator == CodeProvider.BCFIPS || CodeProviderForKeyGenerator == CodeProvider.BC) {

			CodeProvider.ensureBouncyCastleProviderLoaded();
			res = new BCKeyGenerator(this);

		} else {
			if (OSValidator.getCurrentJREVersion()<1.8 && this.getAlgorithmName().equals(AES_GCM.getAlgorithmName()) && this.getBlockMode().equals(AES_GCM.getBlockMode()) && this.getPadding().equals(AES_GCM.getPadding()))
				return BC_FIPS_AES_GCM.getKeyGenerator(random, keySizeBits);
			try {
				res = new JavaNativeKeyGenerator(this, javax.crypto.KeyGenerator.getInstance(algorithmName, CodeProviderForKeyGenerator.checkProviderWithCurrentOS().name()));
			} catch (java.security.NoSuchAlgorithmException e) {
				throw new NoSuchAlgorithmException(e);
			}
			catch (java.security.NoSuchProviderException e) {
				throw new NoSuchProviderException(e.getMessage());
			}
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
			return new SymmetricSecretKey(this,
					new gnu.vm.jgnux.crypto.spec.SecretKeySpec(secretKey, getAlgorithmName()), keySizeBits);
		} else
			throw new IllegalAccessError();

	}
	
	Algorithm getBouncyCastleAlgorithm()
	{
		return bcAlgorithm;
	}
	
	public int getIVSizeBytes()
	{
		if (getBlockMode().toUpperCase().equals("GCM"))
			return 12;
		else
			return getBlockSizeBits()/8;
	}
	
	public boolean supportAssociatedData()
	{
		return isAuthenticatedAlgorithm();
	}
	
}
