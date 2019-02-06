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
package com.distrimind.util;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.Calendar;

import com.distrimind.util.version.Description;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.9
 */
public class Utils {
	public static final Version VERSION;

	static {
		Calendar c = Calendar.getInstance();
		c.set(2016, Calendar.JANUARY, 4);
		Calendar c2 = Calendar.getInstance();
		c.set(2018, Calendar.FEBRUARY, 6);
		VERSION = new Version("Utils", "Utils", (short)3, (short)25, (short)1, Version.Type.Stable, (short)0, c.getTime(), c2.getTime());
		try {

			InputStream is = Utils.class.getResourceAsStream("build.txt");
			if (is!=null)
				VERSION.loadBuildNumber(is);
			
			VERSION.addCreator(new Person("mahdjoub", "jason"));
			c = Calendar.getInstance();
			c.set(2016, Calendar.JANUARY, 4);
			VERSION.addDeveloper(new PersonDeveloper("mahdjoub", "jason", c.getTime()));

			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 6);
			Description d = new Description((short)3, (short)25, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Do not zeroize public keys");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 5);
			d = new Description((short)3, (short)25, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add public constructor into ASymmetricKeyPair");
			d.addItem("Add function ASymmetricKeyPair.getKeyPairWithNewExpirationTime(long)");
			d.addItem("Add function ASymmetricPublicKey.getPublicKeyWithNewExpirationTime(long)");
			d.addItem("Security fix : fill byte array with zero when decoding keys");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.DECEMBER, 17);
			d = new Description((short)3, (short)24, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add P2PLopinKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER");
			d.addItem("Add P2PLopinKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE");
			d.addItem("Change Agreement.receiveData(int stepNumber, byte[] data) signature");
			d.addItem("Several minimal security fix");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.DECEMBER, 4);
			d = new Description((short)3, (short)23, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add P2P login asymmetric signature");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.NOVEMBER, 12);
			d = new Description((short)3, (short)22, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add Symmetric signature algorithms : Native HMAC_SHA3 (experimental)");
            d.addItem("Add message digest : Native SHA3");
			d.addItem("Update BouncyCastle to 1.60");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.NOVEMBER, 8);
			d = new Description((short)3, (short)21, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Change default symmetric signer to HMAC_SHA2_256.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.NOVEMBER, 5);
			d = new Description((short)3, (short)21, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add DNSCheck class.");
			d.addItem("Add EmailCheck class.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.OCTOBER, 15);
			d = new Description((short)3, (short)20, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Update snakeyaml to 1.23.");
			d.addItem("Debug YAML Calendar saving.");
			d.addItem("Clean code.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.SEPTEMBER, 25);
			d = new Description((short)3, (short)20, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.");
			d.addItem("Add SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.AUGUST, 1);
			d = new Description((short)3, (short)19, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Optimize encoding of encryption and signature keys.");
			d.addItem("Version class has now short values (instead of int).");
			d.addItem("Optimize encoding of curve25519.");
			d.addItem("Correction of Calendar saving into YAML documents.");
			d.addItem("Remove unsupported curves.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.JULY, 27);
			d = new Description((short)3, (short)18, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("MultiFormatProperties : Add possibility to only save properties that different from a reference.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.JULY, 17);
			d = new Description((short)3, (short)17, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Improve OS's Version detection.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.JULY, 11);
			d = new Description((short)3, (short)16, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add HumanReadableBytesCount class.");
			d.addItem("Update hardrive and partitions detections.");
            d.addItem("Clean code.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MAY, 15);
			d = new Description((short)3, (short)15, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add P2P login agreement based on symmetric signature.");
			d.addItem("Add P2P multi login agreement based on symmetric signature and JPAKE.");
			d.addItem("XMLProperties is renamed to MultiFormatProperties.");
			d.addItem("MultiFormatProperties support YAML format.");
			d.addItem("Historical of modifications can be exported to Markdown code : Version.getMarkdownCode().");
			d.addItem("Sign git commits.");
			VERSION.addDescription(d);
			

			c = Calendar.getInstance();
			c.set(2018, Calendar.MAY, 10);
			d = new Description((short)3, (short)14, (short)6, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Update BCFIPS to 1.0.1.");
			d.addItem("Update common-codec to 1.11.");
			d.addItem("Renaming ECDDH to ECCDH.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 28);
			d = new Description((short)3, (short)14, (short)5, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Key.encode() is now public.");
			d.addItem("Generate 'versions.html' file into jar files.");
			d.addItem("Correct a bug with collections of type Class.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 11);
			d = new Description((short)3, (short)14, (short)2, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add function KeyAgreementType.getDefaultKeySizeBits().");
			d.addItem("Add function KeyAgreementType.getCodeProvider().");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 11);
			d = new Description((short)3, (short)14, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add KeyAgreementType and KeyAgreement class. ");
			d.addItem("NewHope and ECDA use now the same protocol.");
			d.addItem("Add SHA2-512/224 message digest.");
			d.addItem("Add SHA2-512/256 message digest.");
			d.addItem("Add SHA2-512/224 HMAC.");
			d.addItem("Add SHA2-512/256 HMAC.");
			d.addItem("Add functions isPostQuantomAlgorithm into several classes.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 9);
			d = new Description((short)3, (short)13, (short)4, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correction of a null pointer exception.");
			d.addItem("Security fix : counter was transmitted to other peer.");
			d.addItem("Fill keys with zeros when they are destroyed.");
			d.addItem("Fill intermediate variables with zeros when they are destroyed of after they are used.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 27);
			d = new Description((short)3, (short)13, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add possibility to use a counter with CTR mode.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 26);
			d = new Description((short)3, (short)13, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add CTR mode support.");
			d.addItem("Optmizations of Numbers allocations.");
			d.addItem("Add function OSValidator.getJVMLocation.");
			d.addItem("Add function OSValidator.supportAESIntrinsicsAcceleration.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 10);
			d = new Description((short)3, (short)12, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add sphincs signature (Post Quantum Cryptography).");
			d.addItem("Optimize encryption and minimize memory allocation.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 10);
			d = new Description((short)3, (short)11, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add speed indexes for symmetric encryptions.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 8);
			d = new Description((short)3, (short)11, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add BouncyCastle GCM and EAX authenticated block modes for symmetric encryptions.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 10);
			d = new Description((short)3, (short)10, (short)5, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Java 7 compatible.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 10);
			d = new Description((short)3, (short)10, (short)4, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Fix a problem with BC Mac Length.");
			d.addItem("Add asymmetric encryption algorithms.");
			d.addItem("Add asymmetric key wrapper algorithms.");
			d.addItem("Rename getKeySize to getKeySizeBits.");
			d.addItem("Password hashes are now identified. Now, there is no need to know the type and the parameters of the password hash to compare it with original password.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 9);
			d = new Description((short)3, (short)10, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Encryption algorithms does not need signed JAR to work. So this release work on official Oracle JVM.");
			d.addItem("Add a post quantum cryptography algorithm : New Hope Key Exchanger.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.JANUARY, 31);
			d = new Description((short)3, (short)9, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add curve M-221 for asymmetric signatures and ECDH Key Exchangers.");
			d.addItem("Add curve M-383 for asymmetric signatures and ECDH Key Exchangers.");
			d.addItem("Add curve M-511 for asymmetric signatures and ECDH Key Exchangers.");
			d.addItem("Add curve 41417 for asymmetric signatures and ECDH Key Exchangers.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.JANUARY, 27);
			d = new Description((short)3, (short)8, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Update bouncy castle to 1.59b");
			d.addItem("Add PKBFs with SHA3 hash method");
			d.addItem("Use now BouncyCastle implementation of BCrypt (instead of Berry)");
			d.addItem("Use now BouncyCastle implementation of SCrypt (instead of Tamaya");
			d.addItem("Removing dependencies with JUnit. Use only TestNG.");
			d.addItem("Change iteration numver variable to cost variable with PBKF.");
			d.addItem("Add curve 25519 for asymmetric signatures.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 25);
			d = new Description((short)3, (short)7, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add function AbstractEncryptionIOAlgorithm.decode(InputStream is, OutputStream os, int length)");
			d.addItem("Add function AbstractEncryptionOutputAlgorithm.public void encode(byte[] bytes, int off, int len, OutputStream os)");
			d.addItem("Add scrypt algorithm");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 25);
			d = new Description((short)3, (short)7, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correction of Mac OS Compatibility");
			d.addItem("Add scrypt algorithm");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 2);
			d = new Description((short)3, (short)6, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add blake 2b message digest");
			d.addItem("ECDDH are now FIPS compliant");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 2);
			d = new Description((short)3, (short)4, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add data buffers classes");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 23);
			d = new Description((short)3, (short)3, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Improving key wrapping process");
			d.addItem("Decentralized ID can now be entirely hashed");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 9);
			d = new Description((short)3, (short)2, (short)4, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Fix an issue with signature process");
			d.addItem("Fix an issue with signature size");
			d.addItem("Add throw exception when local et distant public keys are the same with ECDH key agreement");
			d.addItem("Fix issue with ASymmetricKeyPair for signature encoding");
			VERSION.addDescription(d);

			
			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 6);
			d = new Description((short)3, (short)2, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Changing default JVM secured random");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 6);
			d = new Description((short)3, (short)1, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding abstract random into class ClientASymmetricEncryptionAlgorithm");
			d.addItem("Adding function MessageDigestType.getDigestLengthInBits()");
			d.addItem("Adding function SymmetricAuthentifiedSignatureType.getSignatureSizeInBits()");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 5);
			d = new Description((short)3, (short)1, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correcting a bug with seed generator");
			d.addItem("Improving fortuna random speed");
			d.addItem("Add native non blocking secure random");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 5);
			d = new Description((short)3, (short)0, (short)5, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correcting a bug with seed generator");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 4);
			d = new Description((short)3, (short)0, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Minimal corrections into PasswordHash class");
			d.addItem("Updating Bouncy Castle to 1.58 version");
			d.addItem("FIPS compliant");
			d.addItem("Add symmetric and asymmetric key wrappers classes");
			d.addItem("Add BCFIPS password hash algorithms");
			d.addItem("Add password key derivation class");
			d.addItem("Add generic aggreement protocol class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.SEPTEMBER, 1);
			d = new Description((short)2, (short)16, (short)2, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Renforcing MAC address anonymization");
			d.addItem("Possibility to convert UUID to DencentelizedID");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.SEPTEMBER, 1);
			d = new Description((short)2, (short)16, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding support for SHA3");
			d.addItem("Dencentralized ID's use now anonymized MAC address and random numbers");
			d.addItem("Adding NIST SP 800 support with DRBG_BOUNCYCASTLE SecureRandomType");
			d.addItem("Adding NIST SP 800 support with Fortuna");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 21);
			d = new Description((short)2, (short)15, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Minimal corrections");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 15);
			d = new Description((short)2, (short)15, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Add FortunaSecureRandom class");
			d.addItem("Making FortunaSecureRandom default secured random generator");
			d.addItem("Auto-reseed for all secured random generators");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 13);
			d = new Description((short)2, (short)14, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Debuging EllipticCurveDiffieHellmanAlgorithm");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 10);
			d = new Description((short)2, (short)12, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Enabling 256 bits SUN AES encryption");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 5);
			d = new Description((short)2, (short)12, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Minimal corrections");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 4);
			d = new Description((short)2, (short)11, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Converting project to gradle project");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JUNE, 19);
			d = new Description((short)2, (short)10, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding symmetric signture algorithms");
			d.addItem("Altereging P2PJPAKESecretMessageExchanger class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JUNE, 18);
			d = new Description((short)2, (short)9, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding Elliptic Curve Diffie-Hellman key exchange support");
			d.addItem("Password Authenticated Key Exchange by Juggling (2008) algorithm");
			d.addItem("Adding Bouncy Castle algorithms");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JUNE, 1);
			d = new Description((short)2, (short)8, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Managing enum type into XML properties");
			d.addItem("XML properties are able to manage abstract sub XML properties");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MAY, 23);
			d = new Description((short)2, (short)7, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Altering ListClasses");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MAY, 3);
			d = new Description((short)2, (short)7, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding primitive tab support for XML Properties");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.APRIL, 24);
			d = new Description((short)2, (short)6, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("JDK 7 compatible");
			d.addItem("Correcting a bug with testReadWriteDataPackaged in CryptoTests");
			VERSION.addDescription(d);

			d = new Description((short)2, (short)6, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding RegexTools class");
			d.addItem("JDK 7 compatible");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MARCH, 7);
			d = new Description((short)2, (short)5, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Improving and renforcing P2PAsymmetricSecretMessageExchanger");
			d.addItem("Additional manifest content possibility for projects export");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MARCH, 4);
			d = new Description((short)2, (short)4, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Debugging documentation export");
			d.addItem("Updating common net to 3.6 version");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.FEBRUARY, 7);
			d = new Description((short)2, (short)3, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("AbstractXMLObjectParser is now serializable");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JANUARY, 5);
			d = new Description((short)2, (short)2, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Updating IDGeneratorInt class and fix memory leak problem");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 31);
			d = new Description((short)2, (short)1, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding expiration time for public keys");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 23);
			d = new Description((short)2, (short)0, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Changing gnu cryto packages");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 17);
			d = new Description((short)2, (short)0, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Including Gnu Crypto Algorithms.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 6);
			d = new Description((short)1, (short)9, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem(
					"Correcting a bug with the use of IV parameter. Now, the IV parameter is generated for each encryption.");
			d.addItem("Adding class SecureRandomType.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.OCTOBER, 13);
			d = new Description((short)1, (short)8, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding password hash (PBKDF and bcrypt)");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.SEPTEMBER, 15);
			d = new Description((short)1, (short)7, (short)2, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correcting a bug for P2PASymmetricSecretMessageExchanger");
			d.addItem("Adding toString and valueOf functions for crypto keys");
			d.addItem("Possibility to put crypto keys in XMLProperties class");
			d.addItem("Adding 'valueOf' for Decentralized IDs");
			d.addItem("Decentralized IDs are exportable into XML Properties");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.AUGUST, 23);
			d = new Description((short)1, (short)7, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correcting a bug for loop back network interface speed");
			d.addItem("Correcting a bug for P2PASymmetricSecretMessageExchanger");
			d.addItem("Correcting a bug big data asymmetric encryption");
			d.addItem("Adding symmetric et asymmetric keys encapsulation");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.JULY, 4);
			d = new Description((short)1, (short)7, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Renaming class ASymmetricEncryptionAlgorithm to P2PASymmetricEncryptionAlgorithm");
			d.addItem("Adding class SignatureCheckerAlgorithm");
			d.addItem("Adding class SignerAlgorithm");
			d.addItem("Adding class ClientASymmetricEncryptionAlgorithm");
			d.addItem("Adding class ServerASymmetricEncryptionAlgorithm");
			d.addItem("Updating to Common-Net 3.5");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.JUNE, 10);
			d = new Description((short)1, (short)6, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Correcting bug into XMLProperties class");
			d.addItem("Adding tests for XMLProperties class");
			d.addItem("Changing license to CECILL-C.");
			d.addItem("Correcting bugs into DecentralizedIDGenerator classes");
			d.addItem("Adding salt management into SecuredIDGenerator class");
			d.addItem("Adding salt management into PeerToPeerASymetricSecretMessageExanger class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.MARCH, 15);
			d = new Description((short)1, (short)6, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding unit tests possibility for project export tools");
			d.addItem("Adding unit compilation for project export tools");
			d.addItem("Adding new licences");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.MARCH, 9);
			d = new Description((short)1, (short)5, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding PeerToPeerASymmetricSecretMessageExchanger class");
			d.addItem("Adding ObjectSizer class (determins sizeof each java object instance)");
			d.addItem("Adding keys encoding");
			d.addItem("Adding decentralized id encoding/decoding");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.MARCH, 1);
			d = new Description((short)1, (short)4, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding encryption utilities");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 24);
			d = new Description((short)1, (short)3, (short)1, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Set Bits static functions public");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 22);
			d = new Description((short)1, (short)3, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding SecuredDecentralizedID class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 15);
			d = new Description((short)1, (short)2, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding function AbstractXMLObjectParser.isValid(Class)");
			d.addItem("Correcting export bug : temporary files were not deleted.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 14);
			d = new Description((short)1, (short)1, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Adding some internal modifications to ReadWriteLocker");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 4);
			d = new Description((short)1, (short)0, (short)0, Version.Type.Stable, (short)0, c.getTime());
			d.addItem("Realeasing first version of Utils");
			VERSION.addDescription(d);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("ResultOfMethodCallIgnored")
    public static void main(String[] args) throws IOException
	{
		String html=VERSION.getMarkdownCode();
        File f=new File("../versions.md");
        if (f.exists())
            f.delete();
		try(FileWriter fr=new FileWriter(f))
		{
			fr.write(html);
			fr.flush();
		}
		String lastVersion=VERSION.getFileHeadVersion();
        f=new File("../lastVersion.md");
        if (f.exists())
            f.delete();
		try(FileWriter fr=new FileWriter(f))
		{
			fr.write(lastVersion);
			fr.flush();
		}
	}
	
}
