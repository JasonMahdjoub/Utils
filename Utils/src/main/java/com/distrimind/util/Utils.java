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

import com.distrimind.util.version.Description;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import static com.distrimind.util.version.DescriptionType.*;

/**
 * 
 * @author Jason Mahdjoub
 * @version 3.9
 */
public class Utils {
	public static final Version VERSION;

	static {
		VERSION = new Version("Utils", "Utils",
				"2016-01-04");
		try {

			InputStream is = Utils.class.getResourceAsStream("build.txt");
			if (is!=null)
				VERSION.loadBuildNumber(is);

			VERSION.addCreator(new Person("mahdjoub", "jason"))
					.addDeveloper(new PersonDeveloper("mahdjoub", "jason", "2016-01-04"))
					.addDescription(
							new Description((short)5, (short)21, (short)4, Version.Type.STABLE, (short)0, "2021-12-15")
									.addItem(INTERNAL_CHANGE, "Optimization of sleep function into PoolExecutor.")
									.addItem(BUG_FIX, "Base Timer class on System.nanoTime() function and not on System.currentTimeMillis(). The timer could return negative elapsed durations with the old method.")
					)
					.addDescription(
							new Description((short)5, (short)21, (short)3, Version.Type.STABLE, (short)0, "2021-12-09")
									.addItem(BUG_FIX, "Fix issue with add function into CircularArrayList class.")
					)
					.addDescription(
							new Description((short)5, (short)21, (short)2, Version.Type.STABLE, (short)0, "2021-12-03")
									.addItem(INTERNAL_CHANGE, "Add optimisation when calculating encryption/decryption size, by using cache.")
					)
					.addDescription(
							new Description((short)5, (short)21, (short)1, Version.Type.STABLE, (short)0, "2021-12-02")
									.addItem(INTERNAL_CHANGE, "Correction into RandomByteArrayOutputStream(long) when reserving memory into constructor.")
									.addItem(NEW_FEATURE, "Add method ReflectionTools.getField(Class, String).")
					)
					.addDescription(
							new Description((short)5, (short)21, (short)0, Version.Type.STABLE, (short)0, "2021-11-02")
									.addItem(INTERNAL_CHANGE, "Update BouncyCastle to 1.69.")
									.addItem(INTERNAL_CHANGE, "Update Snake YML to 1.29")
									.addItem(NEW_FEATURE, "Manage description type into versioning tools.")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)6, Version.Type.STABLE, (short)0, "2021-10-18")
									.addItem(INTERNAL_CHANGE, "Optimize CircularArrayList class.")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)5, Version.Type.STABLE, (short)0, "2021-10-18")
									.addItem(BUG_FIX, "Fix issues with CircularArrayList class.")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)4, Version.Type.STABLE, (short)0, "2021-10-18")
									.addItem(BUG_FIX, "Fix bad cipher initialisation when using external counter. The bug was not producing security consequences.")
									.addItem(INTERNAL_CHANGE, "Better clean cache into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder and fix issues with bad encryption/decryption.")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)3, Version.Type.STABLE, (short)0, "2021-10-12")
									.addItem(BUG_FIX, "Pool executor : fix bad use of maximum number of threads, and permit to create more threads when the maximum of threads was not reached and when tasks are waiting to be executed.")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)2, Version.Type.STABLE, (short)0, "2021-10-12")
									.addItem(NEW_FEATURE, "Add exception InvalidEncodedValue.")
									.addItem(NEW_FEATURE, "Use exception InvalidEncodedValue during values decoding.")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)1, Version.Type.STABLE, (short)0, "2021-10-12")
									.addItem(NEW_FEATURE, "Add function DecentralizedValue.toShortString(DecentralizedValue).")
									.addItem(NEW_FEATURE, "Add function DecentralizedValue.toShortString(Collection<DecentralizedValue>).")
					)
					.addDescription(
							new Description((short)5, (short)20, (short)0, Version.Type.STABLE, (short)0, "2021-10-07")
									.addItem(NEW_FEATURE, "Add function DecentralizedValue.toShortString().")
									.addItem(NEW_FEATURE, "Add function WrappedData.toShortData().")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)7, Version.Type.STABLE, (short)0, "2021-10-01")
									.addItem(BUG_FIX, "Fix null pointer exception with EncryptionSignatureHashEncoder.")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)6, Version.Type.STABLE, (short)0, "2021-09-30")
									.addItem(BUG_FIX, "Fix issue with secure random loading when used with Android.")
									.addItem(BUG_FIX, "Disable Path serialization to make Utils compatible with Android.")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)5, Version.Type.STABLE, (short)0, "2021-08-30")
									.addItem(BUG_FIX, "Fix issue with CHACHA20_NO_RANDOM_ACCESS driver when using Java 8.")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)4, Version.Type.STABLE, (short)0, "2021-08-30")
									.addItem(BUG_FIX, "Fix issue with human readable bytes quantity.")
									.addItem(BUG_FIX, "Fix issue with ethtool localisation into Debian OS.")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)2, Version.Type.STABLE, (short)0, "2021-08-30")
									.addItem(BUG_FIX, "Delay garbage collector which zeroise unwrapped key.")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)1, Version.Type.STABLE, (short)0, "2021-08-30")
									.addItem(NEW_FEATURE, "Add functions into PoolExecutor.")
									.addItem(BUG_FIX, "Fix regression with MacOSHardDriveDetect.")
									.addItem(BUG_FIX, "Delay garbage collector which zeroise unwrapped key.")
					)
					.addDescription(
							new Description((short)5, (short)19, (short)0, Version.Type.STABLE, (short)0, "2021-08-17")
									.addItem(NEW_FEATURE, "Add class DocumentBuilderFactoryWithNonDTD.")
					)

					.addDescription(
							new Description((short)5, (short)18, (short)5, Version.Type.STABLE, (short)0, "2021-07-07")
									.addItem(BUG_FIX, "Use recompiled Bouncy Castle FIPS dependency in order to make it compatible with Android.")
					)
					.addDescription(
							new Description((short)5, (short)18, (short)4, Version.Type.STABLE, (short)0, "2021-07-05")
									.addItem(BUG_FIX, "Fix high cpu usage issue when testing if thread must be killed.")
					)
					.addDescription(
							new Description((short)5, (short)18, (short)3, Version.Type.STABLE, (short)0, "2021-06-30")
									.addItem(NEW_FEATURE, "Permit to create a random cache file center into a personalized directory.")
									.addItem(INTERNAL_CHANGE, "Change the permissions of the random cache file center directory.")
									.addItem(NEW_FEATURE, "Add possibility to serialize Files and Paths into RandomInputStreams and RandomOutputStreams.")
					)
					.addDescription(
							new Description((short)5, (short)18, (short)2, Version.Type.STABLE, (short)0, "2021-06-07")
									.addItem(NEW_FEATURE, "Add function EncryptionSignatureHashDecoder.isEncrypted(RandomInputStream).")
									.addItem(NEW_FEATURE,"Add function EncryptionSignatureHashDecoder.getLastDataLength().")
									.addItem(BUG_FIX, "Fix some issues into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder.")
					)
					.addDescription(
							new Description((short)5, (short)18, (short)1, Version.Type.STABLE, (short)0, "2021-05-30")
									.addItem(SECURITY_FIX, "Fix issue with function IASymmetricPublicKey.areTimesValid(). Overflow value was reached.")
									.addItem(INTERNAL_CHANGE, "Change methods signatures into P2PLoginAgreementType class.")
					)
					.addDescription(
							new Description((short)5, (short)18, (short)0, Version.Type.STABLE, (short)0, "2021-05-28")
									.addItem(INTERNAL_CHANGE, "Update BouncyCastle to 1.68")
									.addItem(INTERNAL_CHANGE, "Update BouncyCastle FIPS to 1.0.2.1. Use original BouncyCastle FIPS dependency and not recompiled one.")
									.addItem(NEW_FEATURE, "Add functions into P2PLoginAgreementType")
									.addItem(NEW_FEATURE, "Add functions into P2PUnidirectionalLoginSignerWithAsymmetricSignature")
									.addItem(NEW_FEATURE, "Add functions into P2PUnidirectionalLoginCheckerWithAsymmetricSignature")
									.addItem(NEW_FEATURE, "Add creation date for public keys")
									.addItem(INTERNAL_CHANGE, "Reimplements provider's loading")
									.addItem(NEW_FEATURE, "Add Strong SecureRandom type")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)7, Version.Type.STABLE, (short)0, "2021-05-25")
									.addItem(BUG_FIX, "Fix issue with RandomFileInputStream when reading a byte whereas end of file has been reached : the file position shouldn't be incremented !")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)6, Version.Type.STABLE, (short)0, "2021-05-24")
									.addItem(BUG_FIX, "Fix issue with stream closed too quickly when decoding encrypted data")
									.addItem(BUG_FIX, "Fix memory allocation issues with RandomCacheFileCenter")
									.addItem(BUG_FIX, "Fix file position update issue when using file in both read and write modes")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)5, Version.Type.STABLE, (short)0, "2021-04-30")
									.addItem(INTERNAL_CHANGE, "Add function SecuredObjectInputStream.readBytesArray(byte[] array, int offset, boolean nullAccepted, int maxSizeBytes)")
									.addItem(INTERNAL_CHANGE, "Remove function SecuredObjectInputStream.readBytesArray(byte[] array, int offset, int size, boolean nullAccepted)")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)4, Version.Type.STABLE, (short)0, "2021-04-29")
									.addItem(INTERNAL_CHANGE, "Minimal corrections into function signatures into SecuredObjectInputStream")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)3, Version.Type.STABLE, (short)0, "2021-03-25")
									.addItem(INTERNAL_CHANGE, "Decentralized IDs are now generated with random initial sequence")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)2, Version.Type.STABLE, (short)0, "2021-02-21")
									.addItem(NEW_FEATURE, "Add function MessageDigestType.isPostQuantumAlgorithm()")
									.addItem(NEW_FEATURE, "Use post quantum HMacs as default signature algorithms associated with symmetric encryption algorithms")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)1, Version.Type.STABLE, (short)0, "2021-02-21")
									.addItem(NEW_FEATURE, "Exclude wrapping when wrapped keys are not authenticated")
					)
					.addDescription(
							new Description((short)5, (short)17, (short)0, Version.Type.STABLE, (short)0, "2021-02-19")
									.addItem(NEW_FEATURE, "Add functions into WrappedData and WrappedString")
									.addItem(BUG_FIX, "Fix bad parameter into function ServerASymmetricEncryptionAlgorithm.decode(byte[], int, int)")
									.addItem(SECURITY_FIX, "Fix security issue into KeyWrapperAlgorithm class : signatures where not always generated")
									.addItem(NEW_FEATURE, "Complete KeyWrapperAlgorithm class with symmetric and asymmetric signatures")
					)
					.addDescription(
							new Description((short)5, (short)16, (short)0, Version.Type.STABLE, (short)0, "2021-02-18")
									.addItem(NEW_FEATURE, "Add Client/server login agreement")
									.addItem(SECURITY_FIX, "Fix security issue : fix P2P login agreement with asymmetric key pairs")
									.addItem(SECURITY_FIX, "Fix security issue : fix P2P login agreement with symmetric secret key when salt is the same with the two peers")
					)
					.addDescription(
							new Description((short)5, (short)15, (short)1, Version.Type.STABLE, (short)0, "2021-02-04")
									.addItem(SECURITY_FIX, "Fix issues when checking signatures with EncryptionProfileProvider")
					)
					.addDescription(
							new Description((short)5, (short)15, (short)0, Version.Type.STABLE, (short)0, "2021-02-03")
									.addItem(INTERNAL_CHANGE, "rename class SecureExternalizableWithEncryptionProfileProvider to SecureExternalizableWithEncryptionEncoder")
									.addItem(NEW_FEATURE, "Add class SecureExternalizableWithPublicKeysSignatures")
									.addItem(NEW_FEATURE, "Add class SecureExternalizableThatUseEncryptionProfileProvider")
									.addItem(INTERNAL_CHANGE, "Reimplement ProfileFileTree")
									.addItem(SECURITY_FIX, "Fix a possibility of vulnerability when EncryptionProfileProvider's user does not generate an exception when the profile id is not valid. Add the function EncryptionProfileProvider.isValidProfileID.")
									.addItem(NEW_FEATURE, "Add class CachedSecureExternalizable")
									.addItem(NEW_FEATURE, "Add possibility to generate only hash and signatures into EncryptionSignatureHashEncoder and into EncryptionSignatureHashDecoder")
					)
					.addDescription(
							new Description((short)5, (short)14, (short)0, Version.Type.STABLE, (short)0, "2021-01-18")
									.addItem(INTERNAL_CHANGE, "Alter SecureExternalizableWithEncryptionProfileProvider")
					)
					.addDescription(
							new Description((short)5, (short)13, (short)0, Version.Type.STABLE, (short)0, "2021-01-18")
									.addItem(NEW_FEATURE, "Add class ProfileProviderTree")
									.addItem(NEW_FEATURE, "Add interface SecureExternalizableWithEncryptionProfileProvider")
									.addItem(NEW_FEATURE, "Add equals, hashCode, toString functions into Reference class")
					)
					.addDescription(
							new Description((short)5, (short)12, (short)5, Version.Type.STABLE, (short)0, "2021-01-15")
									.addItem(BUG_FIX, "Improve detection of drives and partitions")
					)
					.addDescription(
							new Description((short)5, (short)12, (short)4, Version.Type.STABLE, (short)0, "2021-01-06")
									.addItem(BUG_FIX, "Fix issue with disk and partition detection with macos")
					)
					.addDescription(
							new Description((short)5, (short)12, (short)3, Version.Type.STABLE, (short)0, "2021-01-05")
									.addItem(INTERNAL_CHANGE, "make DecentralizedValue class an interface")
					)
					.addDescription(
							new Description((short)5, (short)12, (short)2, Version.Type.STABLE, (short)0, "2020-12-15")
									.addItem(BUG_FIX, "Fix issue with SerializationTools.isSerializableType(Class)")
					)
					.addDescription(
							new Description((short)5, (short)12, (short)1, Version.Type.STABLE, (short)0, "2020-12-15")
									.addItem(NEW_FEATURE, "Add EncryptionProfileProviderFactory class")
									.addItem(NEW_FEATURE, "Add EncryptionProfileCollection class")
									.addItem(NEW_FEATURE, "Add EncryptionProfileCollectionWithEncryptedKeys class")
					)
					.addDescription(
							new Description((short)5, (short)11, (short)5, Version.Type.STABLE, (short)0, "2020-12-03")
									.addItem(INTERNAL_CHANGE, "Alter SecureObjectInputStream.readCollection")
					)
					.addDescription(
							new Description((short)5, (short)11, (short)1, Version.Type.STABLE, (short)0, "2020-12-03")
									.addItem(NEW_FEATURE, "Add function EncryptionProfileProvider.getKeyID(IASymmetricPublicKey)")
					)
					.addDescription(
							new Description((short)5, (short)11, (short)0, Version.Type.STABLE, (short)0, "2020-11-30")
									.addItem(INTERNAL_CHANGE, "Reimplement KeyWrapperAlgorithm")
									.addItem(INTERNAL_CHANGE, "Refactoring of SecuredObjectOutputStream, SecuredObjectInputStream and Bits")
					)
					.addDescription(
							new Description((short)5, (short)10, (short)0, Version.Type.STABLE, (short)0, "2020-11-18")
									.addItem(NEW_FEATURE, "Add SessionLockableEncryptionProfileProvider class")
									.addItem(NEW_FEATURE, "Add EncryptionProfileProviderWithEncryptedKeys class")
									.addItem(NEW_FEATURE, "Add KeyWrapperAlgorithm class")
									.addItem(SECURITY_FIX, "Security : Better zeroize secrets data")
									.addItem(NEW_FEATURE, "Security : Add WrappedPassword class")
									.addItem(NEW_FEATURE, "Security : Add WrappedHashedPassword class")
									.addItem(NEW_FEATURE, "Security : Add WrappedHashedPasswordString class")
									.addItem(NEW_FEATURE, "Security : Add WrappedSecretDataString class")
									.addItem(NEW_FEATURE, "Security : Add WrappedSecretData class")
									.addItem(NEW_FEATURE, "Security : Add WrappedEncryptedSymmetricSecretKey class")
									.addItem(NEW_FEATURE, "Security : Add WrappedEncryptedASymmetricPrivateKey class")
									.addItem(NEW_FEATURE, "Security : Add WrappedEncryptedSymmetricSecretKeyString class")
									.addItem(NEW_FEATURE, "Security : Add WrappedEncryptedASymmetricPrivateKeyString class")
									.addItem(NEW_FEATURE, "Add SecureObjectOutputStream.writeChars(char[], boolean, int)")
									.addItem(NEW_FEATURE, "Add SecureObjectInputStream.readChars(boolean, int)")
					)
					.addDescription(
							new Description((short)5, (short)9, (short)2, Version.Type.STABLE, (short)0, "2020-11-08")
									.addItem(INTERNAL_CHANGE, "Reimplement collections serialization")
									.addItem(NEW_FEATURE, "Add method SerializationTools.isSerializableType(Class)")
					)
					.addDescription(
							new Description((short)5, (short)9, (short)1, Version.Type.STABLE, (short)0, "2020-11-08")
									.addItem(INTERNAL_CHANGE, "Reimplement maximum key sizes api")
					)
					.addDescription(
							new Description((short)5, (short)9, (short)0, Version.Type.STABLE, (short)0, "2020-11-08")
									.addItem(INTERNAL_CHANGE, "Update BouncyCastle to 1.67")
					)
					.addDescription(
							new Description((short)5, (short)8, (short)0, Version.Type.STABLE, (short)0, "2020-11-04")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readDate(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readDecentralizedID(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readDecentralizedID(boolean, Class)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readInetAddress(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readInetSocketAddress(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readKey(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readKey(boolean, Class)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readKeyPair(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readKeyPair(boolean, Class)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readEnum(boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectInputStream.readEnum(boolean, Class)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeDate(Date, boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeDecentralizedID(AbstractDecentralizedID, boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeInetAddress(InetAddress, boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeInetSocketAddress(InetSocketAddress, boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeKey(AbstractKey, boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeKetPair(AbstractKeyPair, boolean)")
									.addItem(NEW_FEATURE, "Add function SecuredObjectOutputStream.writeEnum(Enum, boolean)")
					)
					.addDescription(
							new Description((short)5, (short)7, (short)0, Version.Type.STABLE, (short)0, "2020-11-02")
									.addItem(NEW_FEATURE, "Add possibility to serialize collections and maps into SerializationTools, SecuredObjectOutputStream and SecuredObjectInputStream")
									.addItem(NEW_FEATURE, "Add possibility to serialize BigInteger, BigDecimal into SerializationTools, SecuredObjectOutputStream and SecuredObjectInputStream")
									.addItem(NEW_FEATURE, "Add function SerializationTools.isSerializable(Object)")

					)
					.addDescription(
							new Description((short)5, (short)6, (short)0, Version.Type.STABLE, (short)0, "2020-10-28")
									.addItem(NEW_FEATURE, "Support sets into MultiFormatProperties")
									.addItem(INTERNAL_CHANGE, "Revisit versioning classes")
									)
					.addDescription(
							new Description((short)5, (short)5, (short)12, Version.Type.STABLE, (short)0, "2020-10-20")
									.addItem(BUG_FIX, "Typography corrections")
									.addItem(INTERNAL_CHANGE, "Update Snake YML to 1.27")
								)
					.addDescription(
							new Description((short)5, (short)5, (short)11, Version.Type.STABLE, (short)0, "2020-08-23")
									.addItem(BUG_FIX, "Fix issue with instantiation of default random secure random")
					)
					.addDescription(
							new Description((short)5, (short)5, (short)10, Version.Type.STABLE, (short)0, "2020-08-17")
									.addItem(INTERNAL_CHANGE, "Remove dependency common-codecs")
									.addItem(BUG_FIX, "Fix GitHub codeQL alerts")
					)
					.addDescription(
							new Description((short)5, (short)5, (short)8, Version.Type.STABLE, (short)0, "2020-10-28")
									.addItem(BUG_FIX, "Fix issue with associated data used into EncryptionSignatureHashEncoder")
					)
					.addDescription(
							new Description((short)5, (short)5, (short)7, Version.Type.STABLE, (short)0, "2020-07-13")
									.addItem(BUG_FIX, "Fix end stream detection issue with BufferedRandomInputStream")
									.addItem(BUG_FIX, "Fix issue with EncryptionSignatureHashDecoder.getMaximumOutputSize() when using EncryptionProfileProvider")
									.addItem(INTERNAL_CHANGE, "Rebase com.distrimind.bcfips package to com.distrimind.bouncycastle and com.distrimind.bcfips")
									.addItem(INTERNAL_CHANGE, "Rebase gnu package to com.distrimind.gnu")
									.addItem(INTERNAL_CHANGE, "Clean code")
					)
					.addDescription(
							new Description((short)5, (short)5, (short)2, Version.Type.STABLE, (short)0, "2020-07-02")
									.addItem(INTERNAL_CHANGE, "Update BouncyCastle to 1.66")
									.addItem(INTERNAL_CHANGE, "Minimum JVM version must now be compatible with Java 8")
					);



			Calendar c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 22);
			Description d = new Description((short)5, (short)5, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Alter RandomCacheFileCenter initialization");
			d.addItem(INTERNAL_CHANGE, "Rename functions withSecretKeyProvider to withEncryptionProfileProvider into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder");
			d.addItem(NEW_FEATURE, "Add SymmetricEncryptionType.MAX_IV_SIZE_IN_BYTES");
			d.addItem(NEW_FEATURE, "Add SymmetricEncryptionType.getMaxOutputSizeInBytesAfterEncryption(long)");
			d.addItem(NEW_FEATURE, "Add SymmetricEncryptionType.getMaxPlainTextSizeForEncoding()");
			d.addItem(NEW_FEATURE, "Add EncryptionSignatureHashEncoder.getMaximumOutputLengthWhateverParameters(long)");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 15);
			d = new Description((short)5, (short)5, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add functions into EncryptionSignatureHashEncoder and into EncryptionSignatureHashDecoder");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 12);
			d = new Description((short)5, (short)4, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Better manage external counter during encryption");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 11);
			d = new Description((short)5, (short)3, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Manage secret key regeneration obsolescence into EncryptionHashSignatureEncoder and into EncryptionHashSignatureDecoder when generating too much Initialisation Vectors");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 10);
			d = new Description((short)5, (short)2, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add function SymmetricEncryptionType.getMaxIVGenerationWithOneSecretKey()");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 9);
			d = new Description((short)5, (short)1, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add function EncryptionSignatureHashEncoder.getRandomOutputStream(RandomOutputStream)");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JUNE, 5);
			d = new Description((short)5, (short)0, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add class EncryptionTools");
			d.addItem(NEW_FEATURE, "Use temporary directory into RandomCacheFileCenter");
			d.addItem(BUG_FIX, "Fix issues into FilePermissions");
			d.addItem(NEW_FEATURE, "Add Chacha20 encryption algorithm with Java BC implementation");
			d.addItem(NEW_FEATURE, "Add Chacha20-POLY1305 encryption algorithm with Java BC implementation");
			d.addItem(NEW_FEATURE, "Add AggregatedRandomInputStreams and AggregatedRandomOutputStreams");
			d.addItem(NEW_FEATURE, "Add DelegatedRandomInputStream and DelegatedRandomOutputStream with next implementations : HashRandomInputStream, HashRandomOutputStream, SignatureCheckerRandomInputStream, SignerRandomOutputStream");
			d.addItem(NEW_FEATURE, "Add FragmentedRandomInputStream and FragmentedRandomOutputStream");
			d.addItem(NEW_FEATURE, "Add FragmentedRandomInputStreamPerChannel and FragmentedRandomOutputStreamPerChannel");
			d.addItem(NEW_FEATURE, "Add NullRandomOutputStream");
			d.addItem(INTERNAL_CHANGE, "Reimplement entirely AbstractEncryptionOutputAlgorithm, AbstractEncryptionIOAlgorithm and SymmetricEncryptionAlgorithm");
			d.addItem(NEW_FEATURE, "Implements EncryptionHashSignatureEncoder and EncryptionHashSignatureDecoder");
			d.addItem(NEW_FEATURE, "Add functionality to hash a stream partially thanks to a given map into order to be compared with distant data");
			d.addItem(INTERNAL_CHANGE, "Reimplement exceptions scheme");
			d.addItem(NEW_FEATURE, "Add maximum sizes of signatures and public/private/secret keys");
			d.addItem(NEW_FEATURE, "Add EncryptionProfileProvider class which enables to permit keys choosing during decryption and signature checking");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.MARCH, 30);
			d = new Description((short)4, (short)15, (short)13, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Update FIPS to a recompiled version compatible with Android");
			d.addItem(INTERNAL_CHANGE, "Update commons-codec to 1.14");
			d.addItem(INTERNAL_CHANGE, "Update snakeyaml to 2.26");
			d.addItem(NEW_FEATURE, "Make Utils compatible with Android");
			d.addItem(NEW_FEATURE, "Add AndroidHardDriveDetect class");
			d.addItem(BUG_FIX, "Revisit AbstractDecentralizedIDGenerator to make it compatible with Android");
			d.addItem(BUG_FIX, "Fix issue with check folder");
			d.addItem(NEW_FEATURE,  "Add predefined classes into SerializationTools");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.MARCH, 16);
			d = new Description((short)4, (short)13, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add ProgressMonitor class");
			VERSION.addDescription(d);


			c = Calendar.getInstance();
			c.set(2020, Calendar.FEBRUARY, 25);
			d = new Description((short)4, (short)12, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add FileTools.walkFileTree function");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.FEBRUARY, 17);
			d = new Description((short)4, (short)11, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Make FilePermissions compatible with old Android platforms");
			d.addItem(INTERNAL_CHANGE, "Asymmetric signatures based on Eduard curves use now BC FIPS implementation");
			d.addItem(INTERNAL_CHANGE,"Key agreements based on Eduard curves use now BC FIPS implementation");
			d.addItem(NEW_FEATURE, "SHA3-HMAC use now BC FIPS implementation");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.FEBRUARY, 15);
			d = new Description((short)4, (short)10, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Update Bouncy Castle to 1.64");
			d.addItem(INTERNAL_CHANGE, "Update Bouncy Castle FIPS to 1.0.2");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.FEBRUARY, 11);
			d = new Description((short)4, (short)9, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add FilePermissions class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2020, Calendar.JANUARY, 24);
			d = new Description((short)4, (short)8, (short)6, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add PoolExecutor and ScheduledPoolExecutor");
			d.addItem(NEW_FEATURE, "Add CircularArrayList");
			d.addItem(INTERNAL_CHANGE, "Change hash code computation in AbstractDecentralizedIDGenerator");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.DECEMBER, 16);
			d = new Description((short)4, (short)7, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Implements function RandomInputStream.available()");
			d.addItem(NEW_FEATURE, "Complete serialization tools function RandomInputStream.available()");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.NOVEMBER, 21);
			d = new Description((short)4, (short)7, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add classes Reference");
			d.addItem(NEW_FEATURE, "Permit secret key hashing");
			d.addItem(NEW_FEATURE, "Add SymmetricSecretKeyPair class");
			d.addItem(NEW_FEATURE, "Add functions SymmetricSecretKey.getDerivedSecretKeyPair(...)");
			d.addItem(NEW_FEATURE, "Add checksum control into DecentralizedValue.toString() and DecentralizedValue.valueOf() functions");
			d.addItem(NEW_FEATURE, "Add SymmetricEncryption.generateSecretKeyFromByteArray and SymmetricAuthenticatedSignatureType.generateSecretKeyFromByteArray functions");
			d.addItem(NEW_FEATURE, "Add key wrapper support with password");
			d.addItem(SECURITY_FIX, "old keys were not correctly filled by zeros");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.NOVEMBER, 15);
			d = new Description((short)4, (short)6, (short)5, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Upgrade gradle to 6.0.0");
			d.addItem(INTERNAL_CHANGE, "Compile with openjdk 13 (compatibility set to Java 7");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.NOVEMBER, 12);
			d = new Description((short)4, (short)6, (short)3, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add functions to IASymmetricPublicKey, IASymmetricPrivateKey, AbstractKeyPair");
			d.addItem(INTERNAL_CHANGE, "Better organize SerializationTools.getInternalSize(...)");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.OCTOBER, 19);
			d = new Description((short)4, (short)6, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Update dependencies");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.OCTOBER, 17);
			d = new Description((short)4, (short)6, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add cache file center");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.OCTOBER, 16);
			d = new Description((short)4, (short)5, (short)3, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add serialization of hybrid keys");
			d.addItem(INTERNAL_CHANGE, "Do not encode key pairs time expiration when they are unlimited.");
			d.addItem(NEW_FEATURE, "SecureSerialization encode Number objects.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.SEPTEMBER, 24);
			d = new Description((short)4, (short)5, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add HybridASymmetricPrivateKey class that manage two keys : one PQC key, and one non PQC key");
			d.addItem(NEW_FEATURE, "Add HybridASymmetricPublicKey class that manage two keys : one PQC key, and one non PQC key");
			d.addItem(NEW_FEATURE, "Add HybridASymmetricKeyPair class that manage two keys : one PQC key, and one non PQC key");
			d.addItem(NEW_FEATURE, "Asymmetric signature and asymmetric encryption can now be done with two algorithms at the same time : one PQC algorithm and one non PQC Algorithm");
			d.addItem(NEW_FEATURE, "Key agreements and login agreements can be hybrid and use both post quantum algorithms and non post quantum algorithms");
			d.addItem(NEW_FEATURE, "Asymmetric keys have key sizes code with in precision (instead of short precision)");
			d.addItem(NEW_FEATURE, "Add McEliece Post Quantum asymmetric encryption algorithm");
			d.addItem(NEW_FEATURE, "Add McEliece key wrapper");
			d.addItem(NEW_FEATURE, "Key wrappers can be hybrid and use both post quantum algorithms and non post quantum algorithms");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.JULY, 10);
			d = new Description((short)4, (short)4, (short)3, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add secure serialization tools.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.JUNE, 28);
			d = new Description((short)4, (short)3, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add BufferedRandomInputStream abd BufferedRandomOutputStream.");
			d.addItem(INTERNAL_CHANGE, "Pre-allocate bytes arrays with random byte array streams.");
			d.addItem(INTERNAL_CHANGE, "Gnu library dependency is now optional. It is possible to compile without it.");
			d.addItem(INTERNAL_CHANGE, "DecentralizedID and encryption keys have a common abstract class : DecentralizedValue.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.MAY, 26);
			d = new Description((short)3, (short)29, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add HMac-Blake2b signature.");
			d.addItem(NEW_FEATURE, "Add Ed25519 and Ed448 asymmetric signatures.");
			d.addItem(NEW_FEATURE, "Add X25519 and X448 asymmetric signatures.");
			d.addItem(NEW_FEATURE, "Add XDH key agreements.");
			d.addItem(NEW_FEATURE, "Add progress monitors.");
			d.addItem(INTERNAL_CHANGE, "Update dependencies.");
			VERSION.addDescription(d);


			c = Calendar.getInstance();
			c.set(2019, Calendar.MAY, 10);
			d = new Description((short)3, (short)27, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add IO classes.");
			VERSION.addDescription(d);


			c = Calendar.getInstance();
			c.set(2019, Calendar.MAY, 4);
			d = new Description((short)3, (short)26, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Key expiration encoding is now optional.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.APRIL, 19);
			d = new Description((short)3, (short)25, (short)6, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX, "Fix security issue with JPAKE participantID encoding. Forbid ObjectInputStream.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.MARCH, 21);
			d = new Description((short)3, (short)25, (short)5, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX, "Securing XML document reading");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.MARCH, 13);
			d = new Description((short)3, (short)25, (short)4, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Make some optimizations with process launching");
			d.addItem(NEW_FEATURE, "Add function Utils.flushAndDestroyProcess");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.FEBRUARY, 6);
			d = new Description((short)3, (short)25, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Do not zeroize public keys");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2019, Calendar.FEBRUARY, 5);
			d = new Description((short)3, (short)25, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add public constructor into ASymmetricKeyPair");
			d.addItem(NEW_FEATURE, "Add function ASymmetricKeyPair.getKeyPairWithNewExpirationTime(long)");
			d.addItem(NEW_FEATURE, "Add function ASymmetricPublicKey.getPublicKeyWithNewExpirationTime(long)");
			d.addItem(SECURITY_FIX, "fill byte array with zero when decoding keys");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.DECEMBER, 17);
			d = new Description((short)3, (short)24, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add P2PLoginKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER");
			d.addItem(NEW_FEATURE, "Add P2PLoginKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE");
			d.addItem(INTERNAL_CHANGE, "Change Agreement.receiveData(int stepNumber, byte[] data) signature");
			d.addItem(SECURITY_FIX, "Several minimal security fix");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.DECEMBER, 4);
			d = new Description((short)3, (short)23, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add P2P login asymmetric signature");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.NOVEMBER, 12);
			d = new Description((short)3, (short)22, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add Symmetric signature algorithms : Native HMAC_SHA3 (experimental)");
            d.addItem(NEW_FEATURE, "Add message digest : Native SHA3");
			d.addItem(INTERNAL_CHANGE, "Update BouncyCastle to 1.60");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.NOVEMBER, 8);
			d = new Description((short)3, (short)21, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Change default symmetric signer to HMAC_SHA2_256.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.NOVEMBER, 5);
			d = new Description((short)3, (short)21, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add DNSCheck class.");
			d.addItem(NEW_FEATURE, "Add EmailCheck class.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.OCTOBER, 15);
			d = new Description((short)3, (short)20, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Update snakeyaml to 1.23.");
			d.addItem(BUG_FIX, "Debug YAML Calendar saving.");
			d.addItem(INTERNAL_CHANGE, "Clean code.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.SEPTEMBER, 25);
			d = new Description((short)3, (short)20, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG");
			d.addItem(NEW_FEATURE, "Add SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.AUGUST, 1);
			d = new Description((short)3, (short)19, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Optimize encoding of encryption and signature keys.");
			d.addItem(INTERNAL_CHANGE, "Version class has now short values (instead of int).");
			d.addItem(INTERNAL_CHANGE, "Optimize encoding of curve25519.");
			d.addItem(BUG_FIX, "Correction of Calendar saving into YAML documents.");
			d.addItem(INTERNAL_CHANGE, "Remove unsupported curves.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.JULY, 27);
			d = new Description((short)3, (short)18, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "MultiFormatProperties : Add possibility to only save properties that different from a reference.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.JULY, 17);
			d = new Description((short)3, (short)17, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Improve OS's Version detection.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.JULY, 11);
			d = new Description((short)3, (short)16, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add HumanReadableBytesCount class.");
			d.addItem(NEW_FEATURE, "Update hard drive and partitions detections.");
            d.addItem(INTERNAL_CHANGE, "Clean code.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MAY, 15);
			d = new Description((short)3, (short)15, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add P2P login agreement based on symmetric signature.");
			d.addItem(NEW_FEATURE, "Add P2P multi login agreement based on symmetric signature and JPAKE.");
			d.addItem(INTERNAL_CHANGE, "XMLProperties is renamed to MultiFormatProperties.");
			d.addItem(NEW_FEATURE, "MultiFormatProperties support YAML format.");
			d.addItem(NEW_FEATURE, "Historical of modifications can be exported to Markdown code : Version.getMarkdownCode().");
			d.addItem(NEW_FEATURE, "Sign git commits.");
			VERSION.addDescription(d);
			

			c = Calendar.getInstance();
			c.set(2018, Calendar.MAY, 10);
			d = new Description((short)3, (short)14, (short)6, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Update BCFIPS to 1.0.1.");
			d.addItem(INTERNAL_CHANGE, "Update common-codec to 1.11.");
			d.addItem(INTERNAL_CHANGE, "Renaming ECDDH to ECCDH.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 28);
			d = new Description((short)3, (short)14, (short)5, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Key.encode() is now public.");
			d.addItem(INTERNAL_CHANGE, "Generate 'versions.html' file into jar files.");
			d.addItem(BUG_FIX, "Correct a bug with collections of type Class.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 11);
			d = new Description((short)3, (short)14, (short)2, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add function KeyAgreementType.getDefaultKeySizeBits().");
			d.addItem(NEW_FEATURE, "Add function KeyAgreementType.getCodeProvider().");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 11);
			d = new Description((short)3, (short)14, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add KeyAgreementType and KeyAgreement class. ");
			d.addItem(INTERNAL_CHANGE, "NewHope and ECDA use now the same protocol.");
			d.addItem(NEW_FEATURE, "Add SHA2-512/224 message digest.");
			d.addItem(NEW_FEATURE, "Add SHA2-512/256 message digest.");
			d.addItem(NEW_FEATURE, "Add SHA2-512/224 HMAC.");
			d.addItem(NEW_FEATURE, "Add SHA2-512/256 HMAC.");
			d.addItem(NEW_FEATURE, "Add functions isPostQuantumAlgorithm into several classes.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.APRIL, 9);
			d = new Description((short)3, (short)13, (short)4, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem( BUG_FIX, "Correction of a null pointer exception.");
			d.addItem(SECURITY_FIX, "counter was transmitted to other peer.");
			d.addItem(SECURITY_FIX, "Fill keys with zeros when they are destroyed.");
			d.addItem(SECURITY_FIX, "Fill intermediate variables with zeros when they are destroyed of after they are used.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 27);
			d = new Description((short)3, (short)13, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add possibility to use a counter with CTR mode.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 26);
			d = new Description((short)3, (short)13, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add CTR mode support.");
			d.addItem(NEW_FEATURE, "Optimizations of Numbers allocations.");
			d.addItem(NEW_FEATURE, "Add function OSValidator.getJVMLocation.");
			d.addItem(NEW_FEATURE, "Add function OSValidator.supportAESIntrinsicsAcceleration.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 10);
			d = new Description((short)3, (short)12, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add sphincs signature (Post Quantum Cryptography).");
			d.addItem(INTERNAL_CHANGE, "Optimize encryption and minimize memory allocation.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 10);
			d = new Description((short)3, (short)11, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Add speed indexes for symmetric encryption.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.MARCH, 8);
			d = new Description((short)3, (short)11, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add BouncyCastle GCM and EAX authenticated block modes for symmetric encryption.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 10);
			d = new Description((short)3, (short)10, (short)5, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Java 7 compatible.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 10);
			d = new Description((short)3, (short)10, (short)4, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Fix a problem with BC Mac Length.");
			d.addItem(NEW_FEATURE, "Add asymmetric encryption algorithms.");
			d.addItem(NEW_FEATURE, "Add asymmetric key wrapper algorithms.");
			d.addItem(INTERNAL_CHANGE, "Rename getKeySize to getKeySizeBits.");
			d.addItem(NEW_FEATURE, "Password hashes are now identified. Now, there is no need to know the type and the parameters of the password hash to compare it with original password.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.FEBRUARY, 9);
			d = new Description((short)3, (short)10, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Encryption algorithms does not need signed JAR to work. So this release work on official Oracle JVM.");
			d.addItem(NEW_FEATURE, "Add a post quantum cryptography algorithm : New Hope Key Exchanger.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.JANUARY, 31);
			d = new Description((short)3, (short)9, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add curve M-221 for asymmetric signatures and ECDH Key Exchangers.");
			d.addItem(NEW_FEATURE, "Add curve M-383 for asymmetric signatures and ECDH Key Exchangers.");
			d.addItem(NEW_FEATURE, "Add curve M-511 for asymmetric signatures and ECDH Key Exchangers.");
			d.addItem(NEW_FEATURE, "Add curve 41417 for asymmetric signatures and ECDH Key Exchangers.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2018, Calendar.JANUARY, 27);
			d = new Description((short)3, (short)8, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Update bouncy castle to 1.59b");
			d.addItem(NEW_FEATURE, "Add PKBFs with SHA3 hash method");
			d.addItem(INTERNAL_CHANGE, "Use now BouncyCastle implementation of BCrypt (instead of Berry)");
			d.addItem(INTERNAL_CHANGE, "Use now BouncyCastle implementation of SCrypt (instead of Tamaya");
			d.addItem(INTERNAL_CHANGE, "Removing dependencies with JUnit. Use only TestNG.");
			d.addItem(INTERNAL_CHANGE, "Change iteration number variable to cost variable with PBKF.");
			d.addItem(NEW_FEATURE, "Add curve 25519 for asymmetric signatures.");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 25);
			d = new Description((short)3, (short)7, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add function AbstractEncryptionIOAlgorithm.decode(InputStream is, OutputStream os, int length)");
			d.addItem(NEW_FEATURE, "Add function AbstractEncryptionOutputAlgorithm.public void encode(byte[] bytes, int off, int len, OutputStream os)");
			d.addItem(NEW_FEATURE, "Add scrypt algorithm");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 25);
			d = new Description((short)3, (short)7, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Correction of Mac OS Compatibility");
			d.addItem(NEW_FEATURE, "Add scrypt algorithm");
			VERSION.addDescription(d);
			
			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 2);
			d = new Description((short)3, (short)6, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add blake 2b message digest");
			d.addItem(INTERNAL_CHANGE, "ECDDH are now FIPS compliant");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.NOVEMBER, 2);
			d = new Description((short)3, (short)4, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add data buffers classes");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 23);
			d = new Description((short)3, (short)3, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Improving key wrapping process");
			d.addItem(INTERNAL_CHANGE, "Decentralized ID can now be entirely hashed");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 9);
			d = new Description((short)3, (short)2, (short)4, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX, "Fix an issue with signature process");
			d.addItem(BUG_FIX, "Fix an issue with signature size");
			d.addItem(NEW_FEATURE, "Add throw exception when local et distant public keys are the same with ECDH key agreement");
			d.addItem(BUG_FIX, "Fix issue with ASymmetricKeyPair for signature encoding");
			VERSION.addDescription(d);

			
			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 6);
			d = new Description((short)3, (short)2, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Changing default JVM secured random");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 6);
			d = new Description((short)3, (short)1, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding abstract random into class ClientASymmetricEncryptionAlgorithm");
			d.addItem(NEW_FEATURE, "Adding function MessageDigestType.getDigestLengthInBits()");
			d.addItem(NEW_FEATURE, "Adding function SymmetricAuthenticatedSignatureType.getSignatureSizeInBits()");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 5);
			d = new Description((short)3, (short)1, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX, "Correcting a bug with seed generator");
			d.addItem(INTERNAL_CHANGE, "Improving fortuna2 random speed");
			d.addItem(NEW_FEATURE, "Add native non blocking secure random");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 5);
			d = new Description((short)3, (short)0, (short)5, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX,"Correcting a bug with seed generator");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.OCTOBER, 4);
			d = new Description((short)3, (short)0, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Minimal corrections into PasswordHash class");
			d.addItem(INTERNAL_CHANGE, "Updating Bouncy Castle to 1.58 version");
			d.addItem(INTERNAL_CHANGE, "FIPS compliant");
			d.addItem(NEW_FEATURE, "Add symmetric and asymmetric key wrappers classes");
			d.addItem(NEW_FEATURE, "Add BCFIPS password hash algorithms");
			d.addItem(NEW_FEATURE, "Add password key derivation class");
			d.addItem(NEW_FEATURE, "Add generic agreement protocol class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.SEPTEMBER, 1);
			d = new Description((short)2, (short)16, (short)2, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Reinforcing MAC address anonymization");
			d.addItem(NEW_FEATURE, "Possibility to convert UUID to DecentralizedID");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.SEPTEMBER, 1);
			d = new Description((short)2, (short)16, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding support for SHA3");
			d.addItem(NEW_FEATURE, "Decentralized ID's use now anonymous MAC address and random numbers");
			d.addItem(NEW_FEATURE, "Adding NIST SP 800 support with DRBG_BOUNCYCASTLE SecureRandomType");
			d.addItem(NEW_FEATURE, "Adding NIST SP 800 support with Fortuna");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 21);
			d = new Description((short)2, (short)15, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Minimal corrections");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 15);
			d = new Description((short)2, (short)15, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Add FortunaSecureRandom class");
			d.addItem(NEW_FEATURE, "Making FortunaSecureRandom default secured random generator");
			d.addItem(SECURITY_FIX, "Auto-reseed for all secured random generators");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 13);
			d = new Description((short)2, (short)14, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Debugging EllipticCurveDiffieHellmanAlgorithm");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 10);
			d = new Description((short)2, (short)12, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Enabling 256 bits SUN AES encryption");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 5);
			d = new Description((short)2, (short)12, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Minimal corrections");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.AUGUST, 4);
			d = new Description((short)2, (short)11, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Converting project to gradle project");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JUNE, 19);
			d = new Description((short)2, (short)10, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding symmetric signature algorithms");
			d.addItem(NEW_FEATURE, "Altering P2PJPAKESecretMessageExchanger class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JUNE, 18);
			d = new Description((short)2, (short)9, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding Elliptic Curve Diffie-Hellman key exchange support");
			d.addItem(NEW_FEATURE, "Password Authenticated Key Exchange by Juggling (2008) algorithm");
			d.addItem(NEW_FEATURE, "Adding Bouncy Castle algorithms");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JUNE, 1);
			d = new Description((short)2, (short)8, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Managing enum type into XML properties");
			d.addItem(NEW_FEATURE, "XML properties are able to manage abstract sub XML properties");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MAY, 23);
			d = new Description((short)2, (short)7, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Altering ListClasses");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MAY, 3);
			d = new Description((short)2, (short)7, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding primitive tab support for XML Properties");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.APRIL, 24);
			d = new Description((short)2, (short)6, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "JDK 7 compatible");
			d.addItem(BUG_FIX, "Correcting a bug with testReadWriteDataPackaged in CryptoTests");
			VERSION.addDescription(d);

			d = new Description((short)2, (short)6, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding RegexTools class");
			d.addItem(INTERNAL_CHANGE, "JDK 7 compatible");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MARCH, 7);
			d = new Description((short)2, (short)5, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX, "Improving and reinforcing P2PAsymmetricSecretMessageExchanger");
			d.addItem(INTERNAL_CHANGE, "Additional manifest content possibility for projects export");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.MARCH, 4);
			d = new Description((short)2, (short)4, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Debugging documentation export");
			d.addItem(INTERNAL_CHANGE, "Updating common net to 3.6 version");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.FEBRUARY, 7);
			d = new Description((short)2, (short)3, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "AbstractXMLObjectParser is now serializable");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2017, Calendar.JANUARY, 5);
			d = new Description((short)2, (short)2, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Updating IDGeneratorInt class and fix memory leak problem");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 31);
			d = new Description((short)2, (short)1, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding expiration time for public keys");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 23);
			d = new Description((short)2, (short)0, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Changing gnu crypto packages");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 17);
			d = new Description((short)2, (short)0, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Including Gnu Crypto Algorithms.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.DECEMBER, 6);
			d = new Description((short)1, (short)9, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(SECURITY_FIX,"Correcting a bug with the use of IV parameter. Now, the IV parameter is generated for each encryption.");
			d.addItem(NEW_FEATURE, "Adding class SecureRandomType.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.OCTOBER, 13);
			d = new Description((short)1, (short)8, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding password hash (PBKF and bcrypt)");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.SEPTEMBER, 15);
			d = new Description((short)1, (short)7, (short)2, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Correcting a bug for P2PASymmetricSecretMessageExchanger");
			d.addItem(NEW_FEATURE, "Adding toString and valueOf functions for crypto keys");
			d.addItem(NEW_FEATURE, "Possibility to put crypto keys in XMLProperties class");
			d.addItem(NEW_FEATURE, "Adding 'valueOf' for Decentralized IDs");
			d.addItem(NEW_FEATURE, "Decentralized IDs are exportable into XML Properties");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.AUGUST, 23);
			d = new Description((short)1, (short)7, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Correcting a bug for loop back network interface speed");
			d.addItem(SECURITY_FIX, "Correcting a bug for P2PASymmetricSecretMessageExchanger");
			d.addItem(SECURITY_FIX, "Correcting a bug big data asymmetric encryption");
			d.addItem(NEW_FEATURE, "Adding symmetric et asymmetric keys encapsulation");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.JULY, 4);
			d = new Description((short)1, (short)7, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Renaming class ASymmetricEncryptionAlgorithm to P2PASymmetricEncryptionAlgorithm");
			d.addItem(NEW_FEATURE, "Adding class SignatureCheckerAlgorithm");
			d.addItem(NEW_FEATURE, "Adding class SignerAlgorithm");
			d.addItem(NEW_FEATURE, "Adding class ClientASymmetricEncryptionAlgorithm");
			d.addItem(NEW_FEATURE, "Adding class ServerASymmetricEncryptionAlgorithm");
			d.addItem(INTERNAL_CHANGE, "Updating to Common-Net 3.5");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.JUNE, 10);
			d = new Description((short)1, (short)6, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(BUG_FIX, "Correcting bug into XMLProperties class");
			d.addItem(INTERNAL_CHANGE, "Adding tests for XMLProperties class");
			d.addItem(INTERNAL_CHANGE, "Changing license to CECILL-C.");
			d.addItem(BUG_FIX, "Correcting bugs into DecentralizedIDGenerator classes");
			d.addItem(NEW_FEATURE, "Adding salt management into SecuredIDGenerator class");
			d.addItem(NEW_FEATURE, "Adding salt management into PeerToPeerASymmetricSecretMessageExchanger class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.MARCH, 15);
			d = new Description((short)1, (short)6, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Adding unit tests possibility for project export tools");
			d.addItem(INTERNAL_CHANGE, "Adding unit compilation for project export tools");
			d.addItem(INTERNAL_CHANGE, "Adding new licences");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.MARCH, 9);
			d = new Description((short)1, (short)5, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding PeerToPeerASymmetricSecretMessageExchanger class");
			d.addItem(NEW_FEATURE, "Adding ObjectSizer class (determines sizeof each java object instance)");
			d.addItem(NEW_FEATURE, "Adding keys encoding");
			d.addItem(NEW_FEATURE, "Adding decentralized id encoding/decoding");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.MARCH, 1);
			d = new Description((short)1, (short)4, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding encryption utilities");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 24);
			d = new Description((short)1, (short)3, (short)1, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(INTERNAL_CHANGE, "Set Bits static functions public");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 22);
			d = new Description((short)1, (short)3, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding SecuredDecentralizedID class");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 15);
			d = new Description((short)1, (short)2, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding function AbstractXMLObjectParser.isValid(Class)");
			d.addItem(BUG_FIX, "Correcting export bug : temporary files were not deleted.");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 14);
			d = new Description((short)1, (short)1, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Adding some internal modifications to ReadWriteLocker");
			VERSION.addDescription(d);

			c = Calendar.getInstance();
			c.set(2016, Calendar.FEBRUARY, 4);
			d = new Description((short)1, (short)0, (short)0, Version.Type.STABLE, (short)0, c.getTime());
			d.addItem(NEW_FEATURE, "Releasing first version of Utils");
			VERSION.addDescription(d);
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
	
	@SuppressWarnings("ResultOfMethodCallIgnored")
    public static void main(String[] args) throws IOException
	{
		String md=VERSION.getMarkdownCode();
        File f=new File("../changelog.md");
        if (f.exists())
            f.delete();
		try(FileWriter fr=new FileWriter(f))
		{
			fr.write(md);
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

	private static Thread thread=null;
	private static final List<Process> processesToFlush=new ArrayList<>();
	public static  boolean flushAndDestroyProcess(final Process p) {

		try
		{
			p.exitValue();
			return true;
		}
		catch(IllegalThreadStateException ignored)
		{
			synchronized (processesToFlush) {
				processesToFlush.add(p);
				if (thread==null) {

					thread = new Thread(() -> {


						while(true) {
							List<Process> processes;
							synchronized (processesToFlush) {
								if (processesToFlush.isEmpty()) {
									try {
										//noinspection WaitWhileHoldingTwoLocks
										processesToFlush.wait(10000);
									} catch (InterruptedException e) {
										e.printStackTrace();
									}

								}
								if (processesToFlush.isEmpty()) {

									thread = null;
									return;
								} else
									processes = new ArrayList<>(processesToFlush);
							}

							for (Process p1 : processes) {
								try (InputStream is = p1.getInputStream(); InputStream es = p1.getErrorStream()) {
									boolean inClosed = false, outClosed = false;


									try {
										int c = is.read();
										while (c != -1) {
											c = is.read();
										}
									} catch (IOException ignored1) {
										inClosed = true;
									}
									try {
										int c = es.read();
										while (c != -1)
											c = es.read();
									} catch (IOException ignored1) {
										outClosed = true;
									}
									if (inClosed && outClosed) {
										synchronized (processesToFlush) {
											processesToFlush.remove(p1);
										}
									}
								} catch (IOException e) {
									e.printStackTrace();
								}
							}
						}
					});
					thread.start();
				}
				else
					processesToFlush.notify();
			}
			try
			{

				p.waitFor();
			}
			catch (InterruptedException e)
			{
				e.printStackTrace();
				return false;
			}
			finally {
				synchronized (processesToFlush)
				{
					processesToFlush.remove(p);
				}
				p.destroy();
			}
			try
			{
				p.exitValue();
				return true;
			}
			catch(IllegalThreadStateException e)
			{
				e.printStackTrace();
				return false;
			}
		}
	}

}
