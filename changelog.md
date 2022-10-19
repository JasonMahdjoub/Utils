Utils
=====
5.24.0 STABLE (Build: 4795) (from 04/01/2016 to 19/10/2022)

# Creator(s):
* Jason MAHDJOUB

# Developer(s):
* Jason MAHDJOUB (Entered in the team at 04/01/2016)

# Changes:


### 5.24.0 STABLE (19/10/2022)
#### New feature(s)
* Add possibility to use several thread with SymmetricSignatureHashEncoder and SymmetricSignatureHashDecoder. Add functions SymmetricSignatureHashEncoder.withPoolExecutor(PoolExecutor) and SymmetricSignatureHashDecoder.withPoolExecutor(PoolExecutor).
* Add possibility to use encoder and decoder as continuous network stream. Main secret key is regenerated after each encoding.
* Add BouncyCastle Sphincs+ asymmetric authenticated signature post quantum algorithms.
* Add Chrystals-Kyber asymmetric key wrappers.
* Add NTRU asymmetric key wrappers.
* Add SABER asymmetric key wrappers.
* Add functions ASymmetricKeyWrapperType.getKeyPairGenerator(...).
* Add BouncyCastle Chrystals-Dilithium asymmetric authenticated signature post quantum algorithms.
* Add BouncyCastle Falcon asymmetric authenticated signature post quantum algorithms.
* Add key agreement that use key wrapping with class KeyAgreementWithKeyWrapping.
* Reorganise architecture of key agreements, and hybrid key agreements. Permit key agreement that generates both secret key for encryption and secret key for signature.
#### Internal change(s)
* Update BouncyCastle to 1.71
* Update BouncyCastle-FIPS to 1.0.2.3
* Clean code
* Improve nonce generator from seed into SecureRandomType
* Target java compatibility is set to Java 11 but source code still use Java 8
* Encode key types and algorithm types with their derived final type
#### Security fixe(s) with low severity
* Update snakeyaml dependency, and fix CVE-2022-38752, CVE-2022-38751, CVE-2022-38750, CVE-2022-38749
* Deprecate GNU algorithms because GNU dependency is no more updated into Utils.
#### Security fixe(s) with medium severity
* Add additional CPU usage during encryption using specifics algorithms to limit frequency side channel attacks and power side channel power attacks. Concerned encryption algorithm are referenced into class SymmetricEncryptionType. Asymmetric encryption are also concerned. Encryption that were used to encode little blocks are less concerned by these attacks.
* Generate new keys during encryption after using the same key with a predefined quantity of data to limit frequency side channel attacks and power side channel power attacks. Concerned encryption algorithm are referenced into class SymmetricEncryptionType. Asymmetric encryption are also concerned. Encryption that were used to encode little blocks are less concerned by these attacks.


### 5.23.5 STABLE (07/04/2022)
#### Internal change(s)
* Alter Cleanable API.
#### Bug fixe(s)
* Fix NullPointerException into finalizer of NewHopeKeyAgreementServer class.
* Fix issue with Cleaner on JVM 8. Finalize was not called. JVM greater than Java 8 was not concerned by this issue.
* Fix dead lock with Cleaner.


### 5.23.2 STABLE (05/04/2022)
#### Internal change(s)
* Add lacking files into generated libraries.
* Add constructors into classes Description and Version.


### 5.23.1 STABLE (05/04/2022)
#### Internal change(s)
* Update README files.


### 5.23.0 STABLE (04/04/2022)
#### New feature(s)
* Add interface Cleanable that use Cleanable java API when JVM version is greater than Java 8 and that use standard finalize method otherwise.
#### Internal change(s)
* Remove finalize method into all key classes, and make them using Cleanable API
#### Security fixe(s)
* Possible bad use of keys, if theses keys have been zeroized. Now an exception is thrown if these keys are used after being zeroized 


### 5.22.4 STABLE (29/03/2022)
#### Internal change(s)
* Declare dependencies as implementation instead of API gradle mode.


### 5.22.3 STABLE (25/03/2022)
#### Internal change(s)
* Improve Utils class loader
* Make MultiFormatProperties use UTF-8 as default encoding
* Zeroizable interface now extends Destroyable interface
#### Bug fixe(s)
* Fix compatibility problems with Android
* Fix array index error into IDGeneratorInt


### 5.22.2 STABLE (07/02/2022)
#### New feature(s)
* Fix bad android os detection with a false positive in some cases.
#### Internal change(s)
* Update URLs.
* Update Snakeyaml to 1.30
* Add detection of Android API 30 and 31


### 5.22.1 STABLE (25/01/2022)
#### Internal change(s)
* Do not use BouncyCastle RSA implementation with hybrid asymmetric key wrapper type.


### 5.22.0 STABLE (24/01/2022)
#### New feature(s)
* Add function MessageDigestType.isSecuredForSignature().
* Add hybrid asymmetric key wrappers.
* Add max variables into ASymmetricKeyWrapperType and into SymmetricKeyWrapperType class that gives max size in byte of wrapped keys.
* Add possibility to externalize wrapped data and wrapped strings.


### 5.21.7 STABLE (22/12/2021)
#### Bug fixe(s)
* Fix issues with CircularArrayList.


### 5.21.6 STABLE (22/12/2021)
#### Internal change(s)
* Alter P2PLoginAgreementType class and add functions.
#### Security fixe(s)
* Fix bad arrays comparison, for example when comparing signatures. Comparison where not done in constant time. This should not produce necessary security issue, but if it does, this is a serious problem since secret message can be deduced. Symmetric signatures checking where concerned.


### 5.21.5 STABLE (16/12/2021)
#### Internal change(s)
* Better serialize Version class into markdown code.
#### Bug fixe(s)
* Fix function PersonDeveloper.compareTo.


### 5.21.4 STABLE (15/12/2021)
#### Internal change(s)
* Optimization of sleep function into PoolExecutor.
#### Bug fixe(s)
* Base Timer class on System.nanoTime() function and not on System.currentTimeMillis(). The timer could return negative elapsed durations with the old method.


### 5.21.3 STABLE (09/12/2021)
#### Bug fixe(s)
* Fix issue with add function into CircularArrayList class.


### 5.21.2 STABLE (03/12/2021)
#### Internal change(s)
* Add optimisation when calculating encryption/decryption size, by using cache.


### 5.21.1 STABLE (02/12/2021)
#### New feature(s)
* Add method ReflectionTools.getField(Class, String).
#### Internal change(s)
* Correction into RandomByteArrayOutputStream(long) when reserving memory into constructor.


### 5.21.0 STABLE (02/11/2021)
#### New feature(s)
* Manage description type into versioning tools.
#### Internal change(s)
* Update BouncyCastle to 1.69.
* Update Snake YML to 1.29


### 5.20.6 STABLE (18/10/2021)
#### Internal change(s)
* Optimize CircularArrayList class.


### 5.20.5 STABLE (18/10/2021)
#### Bug fixe(s)
* Fix issues with CircularArrayList class.


### 5.20.4 STABLE (18/10/2021)
#### Internal change(s)
* Better clean cache into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder and fix issues with bad encryption/decryption.
#### Bug fixe(s)
* Fix bad cipher initialisation when using external counter. The bug was not producing security consequences.


### 5.20.3 STABLE (12/10/2021)
#### Bug fixe(s)
* Pool executor : fix bad use of maximum number of threads, and permit to create more threads when the maximum of threads was not reached and when tasks are waiting to be executed.


### 5.20.2 STABLE (12/10/2021)
#### New feature(s)
* Add exception InvalidEncodedValue.
* Use exception InvalidEncodedValue during values decoding.


### 5.20.1 STABLE (12/10/2021)
#### New feature(s)
* Add function DecentralizedValue.toShortString(DecentralizedValue).
* Add function DecentralizedValue.toShortString(Collection<DecentralizedValue>).


### 5.20.0 STABLE (07/10/2021)
#### New feature(s)
* Add function DecentralizedValue.toShortString().
* Add function WrappedData.toShortData().


### 5.19.7 STABLE (01/10/2021)
#### Bug fixe(s)
* Fix null pointer exception with EncryptionSignatureHashEncoder.


### 5.19.6 STABLE (30/09/2021)
#### Bug fixe(s)
* Fix issue with secure random loading when used with Android.
* Disable Path serialization to make Utils compatible with Android.


### 5.19.5 STABLE (30/08/2021)
#### Bug fixe(s)
* Fix issue with CHACHA20_NO_RANDOM_ACCESS driver when using Java 8.


### 5.19.4 STABLE (30/08/2021)
#### Bug fixe(s)
* Fix issue with human readable bytes quantity.
* Fix issue with ethtool localisation into Debian OS.


### 5.19.2 STABLE (30/08/2021)
#### Bug fixe(s)
* Delay garbage collector which zeroise unwrapped key.


### 5.19.1 STABLE (30/08/2021)
#### New feature(s)
* Add functions into PoolExecutor.
#### Bug fixe(s)
* Fix regression with MacOSHardDriveDetect.
* Delay garbage collector which zeroise unwrapped key.


### 5.19.0 STABLE (17/08/2021)
#### New feature(s)
* Add class DocumentBuilderFactoryWithNonDTD.


### 5.18.5 STABLE (07/07/2021)
#### Bug fixe(s)
* Use recompiled Bouncy Castle FIPS dependency in order to make it compatible with Android.


### 5.18.4 STABLE (05/07/2021)
#### Bug fixe(s)
* Fix high cpu usage issue when testing if thread must be killed.


### 5.18.3 STABLE (30/06/2021)
#### New feature(s)
* Permit to create a random cache file center into a personalized directory.
* Add possibility to serialize Files and Paths into RandomInputStreams and RandomOutputStreams.
#### Internal change(s)
* Change the permissions of the random cache file center directory.


### 5.18.2 STABLE (07/06/2021)
#### New feature(s)
* Add function EncryptionSignatureHashDecoder.isEncrypted(RandomInputStream).
* Add function EncryptionSignatureHashDecoder.getLastDataLength().
#### Bug fixe(s)
* Fix some issues into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder.


### 5.18.1 STABLE (30/05/2021)
#### Internal change(s)
* Change methods signatures into P2PLoginAgreementType class.
#### Security fixe(s)
* Fix issue with function IASymmetricPublicKey.areTimesValid(). Overflow value was reached.


### 5.18.0 STABLE (28/05/2021)
#### New feature(s)
* Add functions into P2PLoginAgreementType
* Add functions into P2PUnidirectionalLoginSignerWithAsymmetricSignature
* Add functions into P2PUnidirectionalLoginCheckerWithAsymmetricSignature
* Add creation date for public keys
* Add Strong SecureRandom type
#### Internal change(s)
* Update BouncyCastle to 1.68
* Update BouncyCastle FIPS to 1.0.2.1. Use original BouncyCastle FIPS dependency and not recompiled one.
* Reimplements provider's loading


### 5.17.7 STABLE (25/05/2021)
#### Bug fixe(s)
* Fix issue with RandomFileInputStream when reading a byte whereas end of file has been reached : the file position shouldn't be incremented !


### 5.17.6 STABLE (24/05/2021)
#### Bug fixe(s)
* Fix issue with stream closed too quickly when decoding encrypted data
* Fix memory allocation issues with RandomCacheFileCenter
* Fix file position update issue when using file in both read and write modes


### 5.17.5 STABLE (30/04/2021)
#### Internal change(s)
* Add function SecuredObjectInputStream.readBytesArray(byte[] array, int offset, boolean nullAccepted, int maxSizeBytes)
* Remove function SecuredObjectInputStream.readBytesArray(byte[] array, int offset, int size, boolean nullAccepted)


### 5.17.4 STABLE (29/04/2021)
#### Internal change(s)
* Minimal corrections into function signatures into SecuredObjectInputStream


### 5.17.3 STABLE (25/03/2021)
#### Internal change(s)
* Decentralized IDs are now generated with random initial sequence


### 5.17.2 STABLE (21/02/2021)
#### New feature(s)
* Add function MessageDigestType.isPostQuantumAlgorithm()
* Use post quantum HMacs as default signature algorithms associated with symmetric encryption algorithms


### 5.17.1 STABLE (21/02/2021)
#### New feature(s)
* Exclude wrapping when wrapped keys are not authenticated


### 5.17.0 STABLE (19/02/2021)
#### New feature(s)
* Add functions into WrappedData and WrappedString
* Complete KeyWrapperAlgorithm class with symmetric and asymmetric signatures
#### Security fixe(s)
* Fix security issue into KeyWrapperAlgorithm class : signatures where not always generated
#### Bug fixe(s)
* Fix bad parameter into function ServerASymmetricEncryptionAlgorithm.decode(byte[], int, int)


### 5.16.0 STABLE (18/02/2021)
#### New feature(s)
* Add Client/server login agreement
#### Security fixe(s)
* Fix security issue : fix P2P login agreement with asymmetric key pairs
* Fix security issue : fix P2P login agreement with symmetric secret key when salt is the same with the two peers


### 5.15.1 STABLE (04/02/2021)
#### Security fixe(s)
* Fix issues when checking signatures with EncryptionProfileProvider


### 5.15.0 STABLE (03/02/2021)
#### New feature(s)
* Add class SecureExternalizableWithPublicKeysSignatures
* Add class SecureExternalizableThatUseEncryptionProfileProvider
* Add class CachedSecureExternalizable
* Add possibility to generate only hash and signatures into EncryptionSignatureHashEncoder and into EncryptionSignatureHashDecoder
#### Internal change(s)
* rename class SecureExternalizableWithEncryptionProfileProvider to SecureExternalizableWithEncryptionEncoder
* Reimplement ProfileFileTree
#### Security fixe(s)
* Fix a possibility of vulnerability when EncryptionProfileProvider's user does not generate an exception when the profile id is not valid. Add the function EncryptionProfileProvider.isValidProfileID.


### 5.14.0 STABLE (18/01/2021)
#### Internal change(s)
* Alter SecureExternalizableWithEncryptionProfileProvider


### 5.13.0 STABLE (18/01/2021)
#### New feature(s)
* Add class ProfileProviderTree
* Add interface SecureExternalizableWithEncryptionProfileProvider
* Add equals, hashCode, toString functions into Reference class


### 5.12.5 STABLE (15/01/2021)
#### Bug fixe(s)
* Improve detection of drives and partitions


### 5.12.4 STABLE (06/01/2021)
#### Bug fixe(s)
* Fix issue with disk and partition detection with macos


### 5.12.3 STABLE (05/01/2021)
#### Internal change(s)
* make DecentralizedValue class an interface


### 5.12.2 STABLE (15/12/2020)
#### Bug fixe(s)
* Fix issue with SerializationTools.isSerializableType(Class)


### 5.12.1 STABLE (15/12/2020)
#### New feature(s)
* Add EncryptionProfileProviderFactory class
* Add EncryptionProfileCollection class
* Add EncryptionProfileCollectionWithEncryptedKeys class


### 5.11.5 STABLE (03/12/2020)
#### Internal change(s)
* Alter SecureObjectInputStream.readCollection


### 5.11.1 STABLE (03/12/2020)
#### New feature(s)
* Add function EncryptionProfileProvider.getKeyID(IASymmetricPublicKey)


### 5.11.0 STABLE (30/11/2020)
#### Internal change(s)
* Reimplement KeyWrapperAlgorithm
* Refactoring of SecuredObjectOutputStream, SecuredObjectInputStream and Bits


### 5.10.0 STABLE (18/11/2020)
#### New feature(s)
* Add SessionLockableEncryptionProfileProvider class
* Add EncryptionProfileProviderWithEncryptedKeys class
* Add KeyWrapperAlgorithm class
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
#### Security fixe(s)
* Security : Better zeroize secrets data


### 5.9.2 STABLE (08/11/2020)
#### New feature(s)
* Add method SerializationTools.isSerializableType(Class)
#### Internal change(s)
* Reimplement collections serialization


### 5.9.1 STABLE (08/11/2020)
#### Internal change(s)
* Reimplement maximum key sizes api


### 5.9.0 STABLE (08/11/2020)
#### Internal change(s)
* Update BouncyCastle to 1.67


### 5.8.0 STABLE (04/11/2020)
#### New feature(s)
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
#### New feature(s)
* Add possibility to serialize collections and maps into SerializationTools, SecuredObjectOutputStream and SecuredObjectInputStream
* Add possibility to serialize BigInteger, BigDecimal into SerializationTools, SecuredObjectOutputStream and SecuredObjectInputStream
* Add function SerializationTools.isSerializable(Object)


### 5.6.0 STABLE (28/10/2020)
#### New feature(s)
* Support sets into MultiFormatProperties
#### Internal change(s)
* Revisit versioning classes


### 5.5.12 STABLE (20/10/2020)
#### Internal change(s)
* Update Snake YML to 1.27
#### Bug fixe(s)
* Typography corrections


### 5.5.11 STABLE (23/08/2020)
#### Bug fixe(s)
* Fix issue with instantiation of default random secure random


### 5.5.10 STABLE (17/08/2020)
#### Internal change(s)
* Remove dependency common-codecs
#### Bug fixe(s)
* Fix GitHub codeQL alerts


### 5.5.8 STABLE (28/10/2020)
#### Bug fixe(s)
* Fix issue with associated data used into EncryptionSignatureHashEncoder


### 5.5.7 STABLE (13/07/2020)
#### Internal change(s)
* Rebase com.distrimind.bcfips package to com.distrimind.bouncycastle and com.distrimind.bcfips
* Rebase gnu package to com.distrimind.gnu
* Clean code
#### Bug fixe(s)
* Fix end stream detection issue with BufferedRandomInputStream
* Fix issue with EncryptionSignatureHashDecoder.getMaximumOutputSize() when using EncryptionProfileProvider


### 5.5.2 STABLE (02/07/2020)
#### Internal change(s)
* Update BouncyCastle to 1.66
* Minimum JVM version must now be compatible with Java 8


### 5.5.1 STABLE (22/06/2020)
#### New feature(s)
* Add SymmetricEncryptionType.MAX_IV_SIZE_IN_BYTES
* Add SymmetricEncryptionType.getMaxOutputSizeInBytesAfterEncryption(long)
* Add SymmetricEncryptionType.getMaxPlainTextSizeForEncoding()
* Add EncryptionSignatureHashEncoder.getMaximumOutputLengthWhateverParameters(long)
#### Internal change(s)
* Alter RandomCacheFileCenter initialization
* Rename functions withSecretKeyProvider to withEncryptionProfileProvider into EncryptionSignatureHashEncoder and EncryptionSignatureHashDecoder


### 5.5.0 STABLE (15/06/2020)
#### New feature(s)
* Add functions into EncryptionSignatureHashEncoder and into EncryptionSignatureHashDecoder


### 5.4.0 STABLE (12/06/2020)
#### Internal change(s)
* Better manage external counter during encryption


### 5.3.0 STABLE (11/06/2020)
#### New feature(s)
* Manage secret key regeneration obsolescence into EncryptionHashSignatureEncoder and into EncryptionHashSignatureDecoder when generating too much Initialisation Vectors


### 5.2.0 STABLE (10/06/2020)
#### New feature(s)
* Add function SymmetricEncryptionType.getMaxIVGenerationWithOneSecretKey()


### 5.1.0 STABLE (09/06/2020)
#### New feature(s)
* Add function EncryptionSignatureHashEncoder.getRandomOutputStream(RandomOutputStream)


### 5.0.0 STABLE (05/06/2020)
#### New feature(s)
* Add class EncryptionTools
* Use temporary directory into RandomCacheFileCenter
* Add Chacha20 encryption algorithm with Java BC implementation
* Add Chacha20-POLY1305 encryption algorithm with Java BC implementation
* Add AggregatedRandomInputStreams and AggregatedRandomOutputStreams
* Add DelegatedRandomInputStream and DelegatedRandomOutputStream with next implementations : HashRandomInputStream, HashRandomOutputStream, SignatureCheckerRandomInputStream, SignerRandomOutputStream
* Add FragmentedRandomInputStream and FragmentedRandomOutputStream
* Add FragmentedRandomInputStreamPerChannel and FragmentedRandomOutputStreamPerChannel
* Add NullRandomOutputStream
* Implements EncryptionHashSignatureEncoder and EncryptionHashSignatureDecoder
* Add functionality to hash a stream partially thanks to a given map into order to be compared with distant data
* Add maximum sizes of signatures and public/private/secret keys
* Add EncryptionProfileProvider class which enables to permit keys choosing during decryption and signature checking
#### Internal change(s)
* Reimplement entirely AbstractEncryptionOutputAlgorithm, AbstractEncryptionIOAlgorithm and SymmetricEncryptionAlgorithm
* Reimplement exceptions scheme
#### Bug fixe(s)
* Fix issues into FilePermissions


### 4.15.13 STABLE (30/03/2020)
#### New feature(s)
* Make Utils compatible with Android
* Add AndroidHardDriveDetect class
* Add predefined classes into SerializationTools
#### Internal change(s)
* Update FIPS to a recompiled version compatible with Android
* Update commons-codec to 1.14
* Update snakeyaml to 2.26
#### Bug fixe(s)
* Revisit AbstractDecentralizedIDGenerator to make it compatible with Android
* Fix issue with check folder


### 4.13.0 STABLE (16/03/2020)
#### New feature(s)
* Add ProgressMonitor class


### 4.12.0 STABLE (25/02/2020)
#### New feature(s)
* Add FileTools.walkFileTree function


### 4.11.0 STABLE (17/02/2020)
#### New feature(s)
* SHA3-HMAC use now BC FIPS implementation
#### Internal change(s)
* Asymmetric signatures based on Eduard curves use now BC FIPS implementation
* Key agreements based on Eduard curves use now BC FIPS implementation
#### Bug fixe(s)
* Make FilePermissions compatible with old Android platforms


### 4.10.1 STABLE (15/02/2020)
#### Internal change(s)
* Update Bouncy Castle to 1.64
* Update Bouncy Castle FIPS to 1.0.2


### 4.9.0 STABLE (11/02/2020)
#### New feature(s)
* Add FilePermissions class


### 4.8.6 STABLE (24/01/2020)
#### New feature(s)
* Add PoolExecutor and ScheduledPoolExecutor
* Add CircularArrayList
#### Internal change(s)
* Change hash code computation in AbstractDecentralizedIDGenerator


### 4.7.1 STABLE (16/12/2019)
#### New feature(s)
* Implements function RandomInputStream.available()
* Complete serialization tools function RandomInputStream.available()


### 4.7.0 STABLE (21/11/2019)
#### New feature(s)
* Add classes Reference
* Permit secret key hashing
* Add SymmetricSecretKeyPair class
* Add functions SymmetricSecretKey.getDerivedSecretKeyPair(...)
* Add checksum control into DecentralizedValue.toString() and DecentralizedValue.valueOf() functions
* Add SymmetricEncryption.generateSecretKeyFromByteArray and SymmetricAuthenticatedSignatureType.generateSecretKeyFromByteArray functions
* Add key wrapper support with password
#### Security fixe(s)
* old keys were not correctly filled by zeros


### 4.6.5 STABLE (15/11/2019)
#### Internal change(s)
* Upgrade gradle to 6.0.0
* Compile with openjdk 13 (compatibility set to Java 7


### 4.6.3 STABLE (12/11/2019)
#### New feature(s)
* Add functions to IASymmetricPublicKey, IASymmetricPrivateKey, AbstractKeyPair
#### Internal change(s)
* Better organize SerializationTools.getInternalSize(...)


### 4.6.1 STABLE (19/10/2019)
#### Internal change(s)
* Update dependencies


### 4.6.0 STABLE (17/10/2019)
#### New feature(s)
* Add cache file center


### 4.5.3 STABLE (16/10/2019)
#### New feature(s)
* Add serialization of hybrid keys
* SecureSerialization encode Number objects.
#### Internal change(s)
* Do not encode key pairs time expiration when they are unlimited.


### 4.5.0 STABLE (24/09/2019)
#### New feature(s)
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
#### New feature(s)
* Add secure serialization tools.


### 4.3.1 STABLE (28/06/2019)
#### New feature(s)
* Add BufferedRandomInputStream abd BufferedRandomOutputStream.
#### Internal change(s)
* Pre-allocate bytes arrays with random byte array streams.
* Gnu library dependency is now optional. It is possible to compile without it.
* DecentralizedID and encryption keys have a common abstract class : DecentralizedValue.


### 3.29.1 STABLE (26/05/2019)
#### New feature(s)
* Add HMac-Blake2b signature.
* Add Ed25519 and Ed448 asymmetric signatures.
* Add X25519 and X448 asymmetric signatures.
* Add XDH key agreements.
* Add progress monitors.
#### Internal change(s)
* Update dependencies.


### 3.27.0 STABLE (10/05/2019)
#### New feature(s)
* Add IO classes.


### 3.26.0 STABLE (04/05/2019)
#### Internal change(s)
* Key expiration encoding is now optional.


### 3.25.6 STABLE (19/04/2019)
#### Security fixe(s)
* Fix security issue with JPAKE participantID encoding. Forbid ObjectInputStream.


### 3.25.5 STABLE (21/03/2019)
#### Security fixe(s)
* Securing XML document reading


### 3.25.4 STABLE (13/03/2019)
#### New feature(s)
* Add function Utils.flushAndDestroyProcess
#### Internal change(s)
* Make some optimizations with process launching


### 3.25.1 STABLE (06/02/2019)
#### Internal change(s)
* Do not zeroize public keys


### 3.25.0 STABLE (05/02/2019)
#### New feature(s)
* Add public constructor into ASymmetricKeyPair
* Add function ASymmetricKeyPair.getKeyPairWithNewExpirationTime(long)
* Add function ASymmetricPublicKey.getPublicKeyWithNewExpirationTime(long)
#### Security fixe(s)
* fill byte array with zero when decoding keys


### 3.24.0 STABLE (17/12/2018)
#### New feature(s)
* Add P2PLoginKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER
* Add P2PLoginKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE
#### Internal change(s)
* Change Agreement.receiveData(int stepNumber, byte[] data) signature
#### Security fixe(s)
* Several minimal security fix


### 3.23.0 STABLE (04/12/2018)
#### New feature(s)
* Add P2P login asymmetric signature


### 3.22.0 STABLE (12/11/2018)
#### New feature(s)
* Add Symmetric signature algorithms : Native HMAC_SHA3 (experimental)
* Add message digest : Native SHA3
#### Internal change(s)
* Update BouncyCastle to 1.60


### 3.21.1 STABLE (08/11/2018)
#### Internal change(s)
* Change default symmetric signer to HMAC_SHA2_256.


### 3.21.0 STABLE (05/11/2018)
#### New feature(s)
* Add DNSCheck class.
* Add EmailCheck class.


### 3.20.1 STABLE (15/10/2018)
#### Internal change(s)
* Update snakeyaml to 1.23.
* Clean code.
#### Bug fixe(s)
* Debug YAML Calendar saving.


### 3.20.0 STABLE (25/09/2018)
#### New feature(s)
* Add SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG
* Add SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG


### 3.19.0 STABLE (01/08/2018)
#### Internal change(s)
* Optimize encoding of encryption and signature keys.
* Version class has now short values (instead of int).
* Optimize encoding of curve25519.
* Remove unsupported curves.
#### Bug fixe(s)
* Correction of Calendar saving into YAML documents.


### 3.18.0 STABLE (27/07/2018)
#### New feature(s)
* MultiFormatProperties : Add possibility to only save properties that different from a reference.


### 3.17.0 STABLE (17/07/2018)
#### Bug fixe(s)
* Improve OS's Version detection.


### 3.16.1 STABLE (11/07/2018)
#### New feature(s)
* Add HumanReadableBytesCount class.
* Update hard drive and partitions detections.
#### Internal change(s)
* Clean code.


### 3.15.0 STABLE (15/05/2018)
#### New feature(s)
* Add P2P login agreement based on symmetric signature.
* Add P2P multi login agreement based on symmetric signature and JPAKE.
* MultiFormatProperties support YAML format.
* Historical of modifications can be exported to Markdown code : Version.getMarkdownCode().
* Sign git commits.
#### Internal change(s)
* XMLProperties is renamed to MultiFormatProperties.


### 3.14.6 STABLE (10/05/2018)
#### Internal change(s)
* Update BCFIPS to 1.0.1.
* Update common-codec to 1.11.
* Renaming ECDDH to ECCDH.


### 3.14.5 STABLE (28/04/2018)
#### Internal change(s)
* Key.encode() is now public.
* Generate 'versions.html' file into jar files.
#### Bug fixe(s)
* Correct a bug with collections of type Class.


### 3.14.2 STABLE (11/04/2018)
#### New feature(s)
* Add function KeyAgreementType.getDefaultKeySizeBits().
* Add function KeyAgreementType.getCodeProvider().


### 3.14.0 STABLE (11/04/2018)
#### New feature(s)
* Add KeyAgreementType and KeyAgreement class. 
* Add SHA2-512/224 message digest.
* Add SHA2-512/256 message digest.
* Add SHA2-512/224 HMAC.
* Add SHA2-512/256 HMAC.
* Add functions isPostQuantumAlgorithm into several classes.
#### Internal change(s)
* NewHope and ECDA use now the same protocol.


### 3.13.4 STABLE (09/04/2018)
#### Security fixe(s)
* counter was transmitted to other peer.
* Fill keys with zeros when they are destroyed.
* Fill intermediate variables with zeros when they are destroyed of after they are used.
#### Bug fixe(s)
* Correction of a null pointer exception.


### 3.13.1 STABLE (27/03/2018)
#### New feature(s)
* Add possibility to use a counter with CTR mode.


### 3.13.0 STABLE (26/03/2018)
#### New feature(s)
* Add CTR mode support.
* Optimizations of Numbers allocations.
* Add function OSValidator.getJVMLocation.
* Add function OSValidator.supportAESIntrinsicsAcceleration.


### 3.12.0 STABLE (10/03/2018)
#### New feature(s)
* Add sphincs signature (Post Quantum Cryptography).
#### Internal change(s)
* Optimize encryption and minimize memory allocation.


### 3.11.1 STABLE (10/03/2018)
#### Internal change(s)
* Add speed indexes for symmetric encryption.


### 3.11.0 STABLE (08/03/2018)
#### New feature(s)
* Add BouncyCastle GCM and EAX authenticated block modes for symmetric encryption.


### 3.10.5 STABLE (10/02/2018)
#### Internal change(s)
* Java 7 compatible.


### 3.10.4 STABLE (10/02/2018)
#### New feature(s)
* Add asymmetric encryption algorithms.
* Add asymmetric key wrapper algorithms.
* Password hashes are now identified. Now, there is no need to know the type and the parameters of the password hash to compare it with original password.
#### Internal change(s)
* Rename getKeySize to getKeySizeBits.
#### Bug fixe(s)
* Fix a problem with BC Mac Length.


### 3.10.0 STABLE (09/02/2018)
#### New feature(s)
* Add a post quantum cryptography algorithm : New Hope Key Exchanger.
#### Internal change(s)
* Encryption algorithms does not need signed JAR to work. So this release work on official Oracle JVM.


### 3.9.0 STABLE (31/01/2018)
#### New feature(s)
* Add curve M-221 for asymmetric signatures and ECDH Key Exchangers.
* Add curve M-383 for asymmetric signatures and ECDH Key Exchangers.
* Add curve M-511 for asymmetric signatures and ECDH Key Exchangers.
* Add curve 41417 for asymmetric signatures and ECDH Key Exchangers.


### 3.8.0 STABLE (27/01/2018)
#### New feature(s)
* Add PKBFs with SHA3 hash method
* Add curve 25519 for asymmetric signatures.
#### Internal change(s)
* Update bouncy castle to 1.59b
* Use now BouncyCastle implementation of BCrypt (instead of Berry)
* Use now BouncyCastle implementation of SCrypt (instead of Tamaya
* Removing dependencies with JUnit. Use only TestNG.
* Change iteration number variable to cost variable with PBKF.


### 3.7.1 STABLE (25/11/2017)
#### New feature(s)
* Add function AbstractEncryptionIOAlgorithm.decode(InputStream is, OutputStream os, int length)
* Add function AbstractEncryptionOutputAlgorithm.public void encode(byte[] bytes, int off, int len, OutputStream os)
* Add scrypt algorithm


### 3.7.0 STABLE (25/11/2017)
#### New feature(s)
* Add scrypt algorithm
#### Bug fixe(s)
* Correction of Mac OS Compatibility


### 3.6.0 STABLE (02/11/2017)
#### New feature(s)
* Add blake 2b message digest
#### Internal change(s)
* ECDDH are now FIPS compliant


### 3.4.0 STABLE (02/11/2017)
#### New feature(s)
* Add data buffers classes


### 3.3.0 STABLE (23/10/2017)
#### Internal change(s)
* Improving key wrapping process
* Decentralized ID can now be entirely hashed


### 3.2.4 STABLE (09/10/2017)
#### New feature(s)
* Add throw exception when local et distant public keys are the same with ECDH key agreement
#### Security fixe(s)
* Fix an issue with signature process
#### Bug fixe(s)
* Fix an issue with signature size
* Fix issue with ASymmetricKeyPair for signature encoding


### 3.2.0 STABLE (06/10/2017)
#### Internal change(s)
* Changing default JVM secured random


### 3.1.1 STABLE (06/10/2017)
#### New feature(s)
* Adding abstract random into class ClientASymmetricEncryptionAlgorithm
* Adding function MessageDigestType.getDigestLengthInBits()
* Adding function SymmetricAuthenticatedSignatureType.getSignatureSizeInBits()


### 3.1.0 STABLE (05/10/2017)
#### New feature(s)
* Add native non blocking secure random
#### Internal change(s)
* Improving fortuna2 random speed
#### Security fixe(s)
* Correcting a bug with seed generator


### 3.0.5 STABLE (05/10/2017)
#### Security fixe(s)
* Correcting a bug with seed generator


### 3.0.0 STABLE (04/10/2017)
#### New feature(s)
* Add symmetric and asymmetric key wrappers classes
* Add BCFIPS password hash algorithms
* Add password key derivation class
* Add generic agreement protocol class
#### Internal change(s)
* Minimal corrections into PasswordHash class
* Updating Bouncy Castle to 1.58 version
* FIPS compliant


### 2.16.2 STABLE (01/09/2017)
#### New feature(s)
* Reinforcing MAC address anonymization
* Possibility to convert UUID to DecentralizedID


### 2.16.0 STABLE (01/09/2017)
#### New feature(s)
* Adding support for SHA3
* Decentralized ID's use now anonymous MAC address and random numbers
* Adding NIST SP 800 support with DRBG_BOUNCYCASTLE SecureRandomType
* Adding NIST SP 800 support with Fortuna


### 2.15.1 STABLE (21/08/2017)
#### Internal change(s)
* Minimal corrections


### 2.15.0 STABLE (15/08/2017)
#### New feature(s)
* Add FortunaSecureRandom class
* Making FortunaSecureRandom default secured random generator
#### Security fixe(s)
* Auto-reseed for all secured random generators


### 2.14.0 STABLE (13/08/2017)
#### Bug fixe(s)
* Debugging EllipticCurveDiffieHellmanAlgorithm


### 2.12.0 STABLE (10/08/2017)
#### Internal change(s)
* Enabling 256 bits SUN AES encryption


### 2.11.0 STABLE (04/08/2017)
#### Internal change(s)
* Converting project to gradle project


### 2.10.0 STABLE (19/06/2017)
#### New feature(s)
* Adding symmetric signature algorithms
* Altering P2PJPAKESecretMessageExchanger class


### 2.9.0 STABLE (18/06/2017)
#### New feature(s)
* Adding Elliptic Curve Diffie-Hellman key exchange support
* Password Authenticated Key Exchange by Juggling (2008) algorithm
* Adding Bouncy Castle algorithms


### 2.8.0 STABLE (01/06/2017)
#### New feature(s)
* Managing enum type into XML properties
* XML properties are able to manage abstract sub XML properties


### 2.7.1 STABLE (23/05/2017)
#### Internal change(s)
* Altering ListClasses


### 2.7.0 STABLE (03/05/2017)
#### New feature(s)
* Adding primitive tab support for XML Properties


### 2.6.1 STABLE (24/04/2017)
#### Internal change(s)
* JDK 7 compatible
#### Bug fixe(s)
* Correcting a bug with testReadWriteDataPackaged in CryptoTests


### 2.6.0 STABLE (24/04/2017)
#### New feature(s)
* Adding RegexTools class
#### Internal change(s)
* JDK 7 compatible


### 2.5.0 STABLE (07/03/2017)
#### Internal change(s)
* Additional manifest content possibility for projects export
#### Security fixe(s)
* Improving and reinforcing P2PAsymmetricSecretMessageExchanger


### 2.4.0 STABLE (04/03/2017)
#### Internal change(s)
* Debugging documentation export
* Updating common net to 3.6 version


### 2.3.0 STABLE (07/02/2017)
#### Internal change(s)
* AbstractXMLObjectParser is now serializable


### 2.2.0 STABLE (05/01/2017)
#### Bug fixe(s)
* Updating IDGeneratorInt class and fix memory leak problem


### 2.1.0 STABLE (31/12/2016)
#### New feature(s)
* Adding expiration time for public keys


### 2.0.1 STABLE (23/12/2016)
#### Internal change(s)
* Changing gnu crypto packages


### 2.0.0 STABLE (17/12/2016)
#### New feature(s)
* Including Gnu Crypto Algorithms.


### 1.9.0 STABLE (06/12/2016)
#### New feature(s)
* Adding class SecureRandomType.
#### Security fixe(s)
* Correcting a bug with the use of IV parameter. Now, the IV parameter is generated for each encryption.


### 1.8.0 STABLE (13/10/2016)
#### New feature(s)
* Adding password hash (PBKF and bcrypt)


### 1.7.2 STABLE (15/09/2016)
#### New feature(s)
* Adding toString and valueOf functions for crypto keys
* Possibility to put crypto keys in XMLProperties class
* Adding 'valueOf' for Decentralized IDs
* Decentralized IDs are exportable into XML Properties
#### Bug fixe(s)
* Correcting a bug for P2PASymmetricSecretMessageExchanger


### 1.7.1 STABLE (23/08/2016)
#### New feature(s)
* Adding symmetric et asymmetric keys encapsulation
#### Security fixe(s)
* Correcting a bug for P2PASymmetricSecretMessageExchanger
* Correcting a bug big data asymmetric encryption
#### Bug fixe(s)
* Correcting a bug for loop back network interface speed


### 1.7.0 STABLE (04/07/2016)
#### New feature(s)
* Adding class SignatureCheckerAlgorithm
* Adding class SignerAlgorithm
* Adding class ClientASymmetricEncryptionAlgorithm
* Adding class ServerASymmetricEncryptionAlgorithm
#### Internal change(s)
* Renaming class ASymmetricEncryptionAlgorithm to P2PASymmetricEncryptionAlgorithm
* Updating to Common-Net 3.5


### 1.6.1 STABLE (10/06/2016)
#### New feature(s)
* Adding salt management into SecuredIDGenerator class
* Adding salt management into PeerToPeerASymmetricSecretMessageExchanger class
#### Internal change(s)
* Adding tests for XMLProperties class
* Changing license to CECILL-C.
#### Bug fixe(s)
* Correcting bug into XMLProperties class
* Correcting bugs into DecentralizedIDGenerator classes


### 1.6.0 STABLE (15/03/2016)
#### Internal change(s)
* Adding unit tests possibility for project export tools
* Adding unit compilation for project export tools
* Adding new licences


### 1.5.0 STABLE (09/03/2016)
#### New feature(s)
* Adding PeerToPeerASymmetricSecretMessageExchanger class
* Adding ObjectSizer class (determines sizeof each java object instance)
* Adding keys encoding
* Adding decentralized id encoding/decoding


### 1.4.0 STABLE (01/03/2016)
#### New feature(s)
* Adding encryption utilities


### 1.3.1 STABLE (24/02/2016)
#### Internal change(s)
* Set Bits static functions public


### 1.3.0 STABLE (22/02/2016)
#### New feature(s)
* Adding SecuredDecentralizedID class


### 1.2.0 STABLE (15/02/2016)
#### New feature(s)
* Adding function AbstractXMLObjectParser.isValid(Class)
#### Bug fixe(s)
* Correcting export bug : temporary files were not deleted.


### 1.1.0 STABLE (14/02/2016)
#### New feature(s)
* Adding some internal modifications to ReadWriteLocker


### 1.0.0 STABLE (04/02/2016)
#### New feature(s)
* Releasing first version of Utils

