Utils
=====
5.12.4 STABLE (Build: 2205) (from 04/01/2016 to 06/01/2020)

# Creator(s):
Jason MAHDJOUB

# Developer(s):
Jason MAHDJOUB (Entered in the team at 04/01/2016)

# Modifications:


### 5.12.4 STABLE (06/01/2020)
* Fix issue with disk and partition detection with macos


### 5.12.3 STABLE (05/01/2020)
* make DecentralizedValue class an interface


### 5.12.2 STABLE (15/12/2020)
* Fix issue with SerializationTools.isSerializableType(Class)


### 5.12.1 STABLE (15/12/2020)
* Add EncryptionProfileProviderFactory class
* Add EncryptionProfileCollection class
* Add EncryptionProfileCollectionWithEncryptedKeys class


### 5.11.5 STABLE (03/12/2020)
* Alter SecureObjectInputStream.readCollection


### 5.11.1 STABLE (03/12/2020)
* Add function EncryptionProfileProvider.getKeyID(IASymmetricPublicKey)


### 5.11.0 STABLE (30/11/2020)
* Reimplement KeyWrapperAlgorithm
* Refactoring of SecuredObjectOutputStream, SecuredObjectInputStream and Bits


### 5.10.0 STABLE (18/11/2020)
* Add SessionLockableEncryptionProfileProvider class
* Add EncryptionProfileProviderWithEncryptedKeys class
* Add KeyWrapperAlgorithm class
* Security : Better zeroize secrets data
* Security : Add WrappedPassword class
* Security : Add WrappedHashedPassword class
* Security : Add WrappedHashedPasswordString class
* Security : Add WrappedSecretDataString class
* Security : Add WrappedSecretData class
* Security : Add WrappedEncryptedSymmetricSecretKey class
* Security : Add WrappedEncryptedASymmetricPrivateKey class
* Security : Add WrappedEncryptedSymmetricSecretKeyString class
* Security : Add WrappedEncryptedASymmetricPrivateKeyString class
* Add SecureObjectOutputStream.writeChars(char[], boolean, int)
* Add SecureObjectInputStream.readChars(boolean, int)


### 5.9.2 STABLE (08/11/2020)
* Revisit collections serialization
* Add method SerializationTools.isSerializableType(Class)


### 5.9.1 STABLE (08/11/2020)
* Revisit maximum key sizes api


### 5.9.0 STABLE (08/11/2020)
* Update BouncyCastle to 1.67


### 5.8.0 STABLE (04/11/2020)
* Add function SecuredObjectInputStream.readDate(boolean)
* Add function SecuredObjectInputStream.readDecentralizedID(boolean)
* Add function SecuredObjectInputStream.readDecentralizedID(boolean, Class)
* Add function SecuredObjectInputStream.readInetAddress(boolean)
* Add function SecuredObjectInputStream.readInetSocketAddress(boolean)
* Add function SecuredObjectInputStream.readKey(boolean)
* Add function SecuredObjectInputStream.readKey(boolean, Class)
* Add function SecuredObjectInputStream.readKeyPair(boolean)
* Add function SecuredObjectInputStream.readKeyPair(boolean, Class)
* Add function SecuredObjectInputStream.readEnum(boolean)
* Add function SecuredObjectInputStream.readEnum(boolean, Class)
* Add function SecuredObjectOutputStream.writeDate(Date, boolean)
* Add function SecuredObjectOutputStream.writeDecentralizedID(AbstractDecentralizedID, boolean)
* Add function SecuredObjectOutputStream.writeInetAddress(InetAddress, boolean)
* Add function SecuredObjectOutputStream.writeInetSocketAddress(InetSocketAddress, boolean)
* Add function SecuredObjectOutputStream.writeKey(AbstractKey, boolean)
* Add function SecuredObjectOutputStream.writeKetPair(AbstractKeyPair, boolean)
* Add function SecuredObjectOutputStream.writeEnum(Enum, boolean)


### 5.7.0 STABLE (02/11/2020)
* Add possibility to serialize collections and maps into SerializationTools, SecuredObjectOutputStream and SecuredObjectInputStream
* Add possibility to serialize BigInteger, BigDecimal into SerializationTools, SecuredObjectOutputStream and SecuredObjectInputStream
* Add function SerializationTools.isSerializable(Object)


### 5.6.0 STABLE (28/10/2020)
* Support sets into MultiFormatProperties
* Revisit versioning classes


### 5.5.12 STABLE (20/10/2020)
* Typography corrections
* Update Snake YML to 1.27


### 5.5.11 STABLE (23/08/2020)
* Fix issue with instantiation of default random secure random


### 5.5.10 STABLE (17/08/2020)
* Remove dependency common-codecs
* Fix GitHub codeQL alerts


### 5.5.8 STABLE (28/10/2020)
* Fix issue with associated data used into EncryptionSignatureHashEncoder


### 5.5.7 STABLE (13/07/2020)
* Fix end stream detection issue with BufferedRandomInputStream
* Fix issue with EncryptionSignatureHashDecoder.getMaximumOutputSize() when using EncryptionProfileProvider
* Rebase org.bouncycastle package to com.distrimind.bouncycastle and com.distrimind.bcfips
* Rebase gnu package to com.distrimind.gnu
* Clean code


### 5.5.2 STABLE (02/07/2020)
* Update BouncyCastle to 1.66
* Minimum JVM version must now be compatible with Java 8


### 5.5.1 STABLE (22/06/2020)
* Alter RandomCacheFileCenter initialization
* Rename functions withSecretKeyProvider to withEncryptionProfileProvider into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder
* Add SymmetricEncryptionType.MAX_IV_SIZE_IN_BYTES
* Add SymmetricEncryptionType.getMaxOutputSizeInBytesAfterEncryption(long)
* Add SymmetricEncryptionType.getMaxPlainTextSizeForEncoding()
* Add EncryptionSignatureHashEncoder.getMaximumOutputLengthWhateverParameters(long)


### 5.5.0 STABLE (15/06/2020)
* Add functions into EncryptionSignatureHashEncoder and into EncryptionSignatureHashDecoder


### 5.4.0 STABLE (12/06/2020)
* Better manage external counter during encryption


### 5.3.0 STABLE (11/06/2020)
* Manage secret key regeneration obsolescence into EncryptionHashSignatureEncoder and into EncryptionHashSignatureDecoder when generating too much Initialisation Vectors


### 5.2.0 STABLE (10/06/2020)
* Add function SymmetricEncryptionType.getMaxIVGenerationWithOneSecretKey()


### 5.1.0 STABLE (09/06/2020)
* Add function EncryptionSignatureHashEncoder.getRandomOutputStream(RandomOutputStream)


### 5.0.0 STABLE (05/06/2020)
* Add class EncryptionTools
* Use temporary directory into RandomCacheFileCenter
* Fix issues into FilePermissions
* Add Chacha20 encryption algorithm with Java BC implementation
* Add Chacha20-POLY1305 encryption algorithm with Java BC implementation
* Add AggregatedRandomInputStreams and AggregatedRandomOutputStreams
* Add DelegatedRandomInputStream and DelegatedRandomOutputStream with next implementations : HashRandomInputStream, HashRandomOutputStream, SignatureCheckerRandomInputStream, SignerRandomOutputStream
* Add FragmentedRandomInputStream and FragmentedRandomOutputStream
* Add FragmentedRandomInputStreamPerChannel and FragmentedRandomOutputStreamPerChannel
* Add NullRandomOutputStream
* Reimplement entirely AbstractEncryptionOutputAlgorithm, AbstractEncryptionIOAlgorithm and SymmetricEncryptionAlgorithm
* Implements EncryptionHashSignatureEncoder and EncryptionHashSignatureDecoder
* Add functionality to hash a stream partially thanks to a given map into order to be compared with distant data
* Reimplement exceptions scheme
* Add maximum sizes of signatures and public/private/secret keys
* Add EncryptionProfileProvider class which enables to permit keys choosing during decryption and signature checking


### 4.15.13 STABLE (30/03/2020)
* Update FIPS to a recompiled version compatible with Android
* Update commons-codec to 1.14
* Update snakeyaml to 2.26
* Make Utils compatible with Android
* Add AndroidHardDriveDetect class
* Revisit AbstractDecentralizedIDGenerator to make it compatible with Android
* Fix issue with check folder
* Add predefined classes into SerializationTools


### 4.13.0 STABLE (16/03/2020)
* Add ProgressMonitor class


### 4.12.0 STABLE (25/02/2020)
* Add FileTools.walkFileTree function


### 4.11.0 STABLE (17/02/2020)
* Make FilePermissions compatible with old Android platforms
* Asymmetric signatures based on Eduard curves use now BC FIPS implementation
* Key agreements based on Eduard curves use now BC FIPS implementation
* SHA3-HMAC use now BC FIPS implementation


### 4.10.1 STABLE (15/02/2020)
* Update Bouncy Castle to 1.64
* Update Bouncy Castle FIPS to 1.0.2


### 4.9.0 STABLE (11/02/2020)
* Add FilePermissions class


### 4.8.6 STABLE (24/01/2020)
* Add PoolExecutor and ScheduledPoolExecutor
* Add CircularArrayList
* Change hash code computation in AbstractDecentralizedIDGenerator


### 4.7.1 STABLE (16/12/2019)
* Implements function RandomInputStream.available()
* Complete serialization tools function RandomInputStream.available()


### 4.7.0 STABLE (21/11/2019)
* Add classes Reference
* Permit secret key hashing
* Add SymmetricSecretKeyPair class
* Add functions SymmetricSecretKey.getDerivedSecretKeyPair(...)
* Add checksum control into DecentralizedValue.toString() and DecentralizedValue.valueOf() functions
* Add SymmetricEncryption.generateSecretKeyFromByteArray and SymmetricAuthenticatedSignatureType.generateSecretKeyFromByteArray functions
* Add key wrapper support with password
* Fix security issue : old keys were not correctly filled by zeros


### 4.6.5 STABLE (15/11/2019)
* Upgrade gradle to 6.0.0
* Compile with openjdk 13 (compatibility set to Java 7


### 4.6.3 STABLE (12/11/2019)
* Add functions to IASymmetricPublicKey, IASymmetricPrivateKey, AbstractKeyPair
* Better organize SerializationTools.getInternalSize(...)


### 4.6.1 STABLE (19/10/2019)
* Update dependencies


### 4.6.0 STABLE (17/10/2019)
* Add cache file center


### 4.5.3 STABLE (16/10/2019)
* Add serialization of hybrid keys
* Do not encode key pairs time expiration when they are unlimited.
* SecureSerialization encode Number objects.


### 4.5.0 STABLE (24/09/2019)
* Add HybridASymmetricPrivateKey class that manage two keys : one PQC key, and one non PQC key
* Add HybridASymmetricPublicKey class that manage two keys : one PQC key, and one non PQC key
* Add HybridASymmetricKeyPair class that manage two keys : one PQC key, and one non PQC key
* Asymmetric signature and asymmetric encryption can now be done with two algorithms at the same time : one PQC algorithm and one non PQC Algorithm
* Key agreements and login agreements can be hybrid and use both post quantum algorithms and non post quantum algorithms
* Asymmetric keys have key sizes code with in precision (instead of short precision)
* Add McEliece Post Quantum asymmetric encryption algorithm
* Add McEliece key wrapper
* Key wrappers can be hybrid and use both post quantum algorithms and non post quantum algorithms


### 4.4.3 STABLE (10/07/2019)
* Add secure serialization tools.


### 4.3.1 STABLE (28/06/2019)
* Add BufferedRandomInputStream abd BufferedRandomOutputStream.
* Pre-allocate bytes arrays with random byte array streams.
* Gnu library dependency is now optional. It is possible to compile without it.
* DecentralizedID and encryption keys have a common abstract class : DecentralizedValue.


### 3.29.1 STABLE (26/05/2019)
* Add HMac-Blake2b signature.
* Add Ed25519 and Ed448 asymmetric signatures.
* Add X25519 and X448 asymmetric signatures.
* Add XDH key agreements.
* Add progress monitors.
* Update dependencies.


### 3.27.0 STABLE (10/05/2019)
* Add IO classes.


### 3.26.0 STABLE (04/05/2019)
* Key expiration encoding is now optional.


### 3.25.6 STABLE (19/04/2019)
* Fix security issue with JPAKE participantID encoding. Forbid ObjectInputStream.


### 3.25.5 STABLE (21/03/2019)
* Securing XML document reading


### 3.25.4 STABLE (13/03/2019)
* Make some optimizations with process launching
* Add function Utils.flushAndDestroyProcess


### 3.25.1 STABLE (06/02/2019)
* Do not zeroize public keys


### 3.25.0 STABLE (05/02/2019)
* Add public constructor into ASymmetricKeyPair
* Add function ASymmetricKeyPair.getKeyPairWithNewExpirationTime(long)
* Add function ASymmetricPublicKey.getPublicKeyWithNewExpirationTime(long)
* Security fix : fill byte array with zero when decoding keys


### 3.24.0 STABLE (17/12/2018)
* Add P2PLoginKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER
* Add P2PLoginKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE
* Change Agreement.receiveData(int stepNumber, byte[] data) signature
* Several minimal security fix


### 3.23.0 STABLE (04/12/2018)
* Add P2P login asymmetric signature


### 3.22.0 STABLE (12/11/2018)
* Add Symmetric signature algorithms : Native HMAC_SHA3 (experimental)
* Add message digest : Native SHA3
* Update BouncyCastle to 1.60


### 3.21.1 STABLE (08/11/2018)
* Change default symmetric signer to HMAC_SHA2_256.


### 3.21.0 STABLE (05/11/2018)
* Add DNSCheck class.
* Add EmailCheck class.


### 3.20.1 STABLE (15/10/2018)
* Update snakeyaml to 1.23.
* Debug YAML Calendar saving.
* Clean code.


### 3.20.0 STABLE (25/09/2018)
* Add SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.
* Add SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.


### 3.19.0 STABLE (01/08/2018)
* Optimize encoding of encryption and signature keys.
* Version class has now short values (instead of int).
* Optimize encoding of curve25519.
* Correction of Calendar saving into YAML documents.
* Remove unsupported curves.


### 3.18.0 STABLE (27/07/2018)
* MultiFormatProperties : Add possibility to only save properties that different from a reference.


### 3.17.0 STABLE (17/07/2018)
* Improve OS's Version detection.


### 3.16.1 STABLE (11/07/2018)
* Add HumanReadableBytesCount class.
* Update hard drive and partitions detections.
* Clean code.


### 3.15.0 STABLE (15/05/2018)
* Add P2P login agreement based on symmetric signature.
* Add P2P multi login agreement based on symmetric signature and JPAKE.
* XMLProperties is renamed to MultiFormatProperties.
* MultiFormatProperties support YAML format.
* Historical of modifications can be exported to Markdown code : Version.getMarkdownCode().
* Sign git commits.


### 3.14.6 STABLE (10/05/2018)
* Update BCFIPS to 1.0.1.
* Update common-codec to 1.11.
* Renaming ECDDH to ECCDH.


### 3.14.5 STABLE (28/04/2018)
* Key.encode() is now public.
* Generate 'versions.html' file into jar files.
* Correct a bug with collections of type Class.


### 3.14.2 STABLE (11/04/2018)
* Add function KeyAgreementType.getDefaultKeySizeBits().
* Add function KeyAgreementType.getCodeProvider().


### 3.14.0 STABLE (11/04/2018)
* Add KeyAgreementType and KeyAgreement class. 
* NewHope and ECDA use now the same protocol.
* Add SHA2-512/224 message digest.
* Add SHA2-512/256 message digest.
* Add SHA2-512/224 HMAC.
* Add SHA2-512/256 HMAC.
* Add functions isPostQuantumAlgorithm into several classes.


### 3.13.4 STABLE (09/04/2018)
* Correction of a null pointer exception.
* Security fix : counter was transmitted to other peer.
* Fill keys with zeros when they are destroyed.
* Fill intermediate variables with zeros when they are destroyed of after they are used.


### 3.13.1 STABLE (27/03/2018)
* Add possibility to use a counter with CTR mode.


### 3.13.0 STABLE (26/03/2018)
* Add CTR mode support.
* Optimizations of Numbers allocations.
* Add function OSValidator.getJVMLocation.
* Add function OSValidator.supportAESIntrinsicsAcceleration.


### 3.12.0 STABLE (10/03/2018)
* Add sphincs signature (Post Quantum Cryptography).
* Optimize encryption and minimize memory allocation.


### 3.11.1 STABLE (10/03/2018)
* Add speed indexes for symmetric encryption.


### 3.11.0 STABLE (08/03/2018)
* Add BouncyCastle GCM and EAX authenticated block modes for symmetric encryption.


### 3.10.5 STABLE (10/02/2018)
* Java 7 compatible.


### 3.10.4 STABLE (10/02/2018)
* Fix a problem with BC Mac Length.
* Add asymmetric encryption algorithms.
* Add asymmetric key wrapper algorithms.
* Rename getKeySize to getKeySizeBits.
* Password hashes are now identified. Now, there is no need to know the type and the parameters of the password hash to compare it with original password.


### 3.10.0 STABLE (09/02/2018)
* Encryption algorithms does not need signed JAR to work. So this release work on official Oracle JVM.
* Add a post quantum cryptography algorithm : New Hope Key Exchanger.


### 3.9.0 STABLE (31/01/2018)
* Add curve M-221 for asymmetric signatures and ECDH Key Exchangers.
* Add curve M-383 for asymmetric signatures and ECDH Key Exchangers.
* Add curve M-511 for asymmetric signatures and ECDH Key Exchangers.
* Add curve 41417 for asymmetric signatures and ECDH Key Exchangers.


### 3.8.0 STABLE (27/01/2018)
* Update bouncy castle to 1.59b
* Add PKBFs with SHA3 hash method
* Use now BouncyCastle implementation of BCrypt (instead of Berry)
* Use now BouncyCastle implementation of SCrypt (instead of Tamaya
* Removing dependencies with JUnit. Use only TestNG.
* Change iteration number variable to cost variable with PBKF.
* Add curve 25519 for asymmetric signatures.


### 3.7.1 STABLE (25/11/2017)
* Add function AbstractEncryptionIOAlgorithm.decode(InputStream is, OutputStream os, int length)
* Add function AbstractEncryptionOutputAlgorithm.public void encode(byte[] bytes, int off, int len, OutputStream os)
* Add scrypt algorithm


### 3.7.0 STABLE (25/11/2017)
* Correction of Mac OS Compatibility
* Add scrypt algorithm


### 3.6.0 STABLE (02/11/2017)
* Add blake 2b message digest
* ECDDH are now FIPS compliant


### 3.4.0 STABLE (02/11/2017)
* Add data buffers classes


### 3.3.0 STABLE (23/10/2017)
* Improving key wrapping process
* Decentralized ID can now be entirely hashed


### 3.2.4 STABLE (09/10/2017)
* Fix an issue with signature process
* Fix an issue with signature size
* Add throw exception when local et distant public keys are the same with ECDH key agreement
* Fix issue with ASymmetricKeyPair for signature encoding


### 3.2.0 STABLE (06/10/2017)
* Changing default JVM secured random


### 3.1.1 STABLE (06/10/2017)
* Adding abstract random into class ClientASymmetricEncryptionAlgorithm
* Adding function MessageDigestType.getDigestLengthInBits()
* Adding function SymmetricAuthenticatedSignatureType.getSignatureSizeInBits()


### 3.1.0 STABLE (05/10/2017)
* Correcting a bug with seed generator
* Improving fortuna2 random speed
* Add native non blocking secure random


### 3.0.5 STABLE (05/10/2017)
* Correcting a bug with seed generator


### 3.0.0 STABLE (04/10/2017)
* Minimal corrections into PasswordHash class
* Updating Bouncy Castle to 1.58 version
* FIPS compliant
* Add symmetric and asymmetric key wrappers classes
* Add BCFIPS password hash algorithms
* Add password key derivation class
* Add generic agreement protocol class


### 2.16.2 STABLE (01/09/2017)
* Reinforcing MAC address anonymization
* Possibility to convert UUID to DecentralizedID


### 2.16.0 STABLE (01/09/2017)
* Adding support for SHA3
* Decentralized ID's use now anonymous MAC address and random numbers
* Adding NIST SP 800 support with DRBG_BOUNCYCASTLE SecureRandomType
* Adding NIST SP 800 support with Fortuna


### 2.15.1 STABLE (21/08/2017)
* Minimal corrections


### 2.15.0 STABLE (15/08/2017)
* Add FortunaSecureRandom class
* Making FortunaSecureRandom default secured random generator
* Auto-reseed for all secured random generators


### 2.14.0 STABLE (13/08/2017)
* Debugging EllipticCurveDiffieHellmanAlgorithm


### 2.12.0 STABLE (10/08/2017)
* Enabling 256 bits SUN AES encryption


### 2.11.0 STABLE (04/08/2017)
* Converting project to gradle project


### 2.10.0 STABLE (19/06/2017)
* Adding symmetric signature algorithms
* Altering P2PJPAKESecretMessageExchanger class


### 2.9.0 STABLE (18/06/2017)
* Adding Elliptic Curve Diffie-Hellman key exchange support
* Password Authenticated Key Exchange by Juggling (2008) algorithm
* Adding Bouncy Castle algorithms


### 2.8.0 STABLE (01/06/2017)
* Managing enum type into XML properties
* XML properties are able to manage abstract sub XML properties


### 2.7.1 STABLE (23/05/2017)
* Altering ListClasses


### 2.7.0 STABLE (03/05/2017)
* Adding primitive tab support for XML Properties


### 2.6.1 STABLE (24/04/2017)
* JDK 7 compatible
* Correcting a bug with testReadWriteDataPackaged in CryptoTests


### 2.6.0 STABLE (24/04/2017)
* Adding RegexTools class
* JDK 7 compatible


### 2.5.0 STABLE (07/03/2017)
* Improving and reinforcing P2PAsymmetricSecretMessageExchanger
* Additional manifest content possibility for projects export


### 2.4.0 STABLE (04/03/2017)
* Debugging documentation export
* Updating common net to 3.6 version


### 2.3.0 STABLE (07/02/2017)
* AbstractXMLObjectParser is now serializable


### 2.2.0 STABLE (05/01/2017)
* Updating IDGeneratorInt class and fix memory leak problem


### 2.1.0 STABLE (31/12/2016)
* Adding expiration time for public keys


### 2.0.1 STABLE (23/12/2016)
* Changing gnu crypto packages


### 2.0.0 STABLE (17/12/2016)
* Including Gnu Crypto Algorithms.


### 1.9.0 STABLE (06/12/2016)
* Correcting a bug with the use of IV parameter. Now, the IV parameter is generated for each encryption.
* Adding class SecureRandomType.


### 1.8.0 STABLE (13/10/2016)
* Adding password hash (PBKF and bcrypt)


### 1.7.2 STABLE (15/09/2016)
* Correcting a bug for P2PASymmetricSecretMessageExchanger
* Adding toString and valueOf functions for crypto keys
* Possibility to put crypto keys in XMLProperties class
* Adding 'valueOf' for Decentralized IDs
* Decentralized IDs are exportable into XML Properties


### 1.7.1 STABLE (23/08/2016)
* Correcting a bug for loop back network interface speed
* Correcting a bug for P2PASymmetricSecretMessageExchanger
* Correcting a bug big data asymmetric encryption
* Adding symmetric et asymmetric keys encapsulation


### 1.7.0 STABLE (04/07/2016)
* Renaming class ASymmetricEncryptionAlgorithm to P2PASymmetricEncryptionAlgorithm
* Adding class SignatureCheckerAlgorithm
* Adding class SignerAlgorithm
* Adding class ClientASymmetricEncryptionAlgorithm
* Adding class ServerASymmetricEncryptionAlgorithm
* Updating to Common-Net 3.5


### 1.6.1 STABLE (10/06/2016)
* Correcting bug into XMLProperties class
* Adding tests for XMLProperties class
* Changing license to CECILL-C.
* Correcting bugs into DecentralizedIDGenerator classes
* Adding salt management into SecuredIDGenerator class
* Adding salt management into PeerToPeerASymmetricSecretMessageExchanger class


### 1.6.0 STABLE (15/03/2016)
* Adding unit tests possibility for project export tools
* Adding unit compilation for project export tools
* Adding new licences


### 1.5.0 STABLE (09/03/2016)
* Adding PeerToPeerASymmetricSecretMessageExchanger class
* Adding ObjectSizer class (determines sizeof each java object instance)
* Adding keys encoding
* Adding decentralized id encoding/decoding


### 1.4.0 STABLE (01/03/2016)
* Adding encryption utilities


### 1.3.1 STABLE (24/02/2016)
* Set Bits static functions public


### 1.3.0 STABLE (22/02/2016)
* Adding SecuredDecentralizedID class


### 1.2.0 STABLE (15/02/2016)
* Adding function AbstractXMLObjectParser.isValid(Class)
* Correcting export bug : temporary files were not deleted.


### 1.1.0 STABLE (14/02/2016)
* Adding some internal modifications to ReadWriteLocker


### 1.0.0 STABLE (04/02/2016)
* Releasing first version of Utils

