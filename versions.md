Utils
=====
3.24.0 Stable (Build: 940) (from 17/12/2018 to 17/12/2018)

# Creator(s):
Jason MAHDJOUB

# Developer(s):
Jason MAHDJOUB (Entred in the team at 04/01/2016)

# Modifications:


### 3.24.0 Stable (17/12/2018)
* Add P2PLopinKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER
* Add P2PLopinKeyAgreementType.ASYMMETRIC_SECRET_MESSAGE_EXCHANGER_AND_AGREEMENT_WITH_SYMMETRIC_SIGNATURE
* Change Agreement.receiveData(int stepNumber, byte[] data) signature
* Several minimal security fix


### 3.23.0 Stable (04/12/2018)
* Add P2P login asymmetric signature


### 3.22.0 Stable (12/11/2018)
* Add Symmetric signature algorithms : Native HMAC_SHA3 (experimental)
* Add message digest : Native SHA3
* Update BouncyCastle to 1.60


### 3.21.1 Stable (08/11/2018)
* Change default symmetric signer to HMAC_SHA2_256.


### 3.21.0 Stable (05/11/2018)
* Add DNSCheck class.
* Add EmailCheck class.


### 3.20.1 Stable (15/10/2018)
* Update snakeyaml to 1.23.
* Debug YAML Calendar saving.
* Clean code.


### 3.20.0 Stable (25/09/2018)
* Add SecureRandomType.BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.
* Add SecureRandomType.FORTUNA_WITH_BC_FIPS_APPROVED_FOR_KEYS_With_NativePRNG.


### 3.19.0 Stable (01/08/2018)
* Optimize encoding of encryption and signature keys.
* Version class has now short values (instead of int).
* Optimize encoding of curve25519.
* Correction of Calendar saving into YAML documents.
* Remove unsupported curves.


### 3.18.0 Stable (27/07/2018)
* MultiFormatProperties : Add possibility to only save properties that different from a reference.


### 3.17.0 Stable (17/07/2018)
* Improve OS's Version detection.


### 3.16.1 Stable (11/07/2018)
* Add HumanReadableBytesCount class.
* Update hardrive and partitions detections.
* Clean code.


### 3.15.0 Stable (15/05/2018)
* Add P2P login agreement based on symmetric signature.
* Add P2P multi login agreement based on symmetric signature and JPAKE.
* XMLProperties is renamed to MultiFormatProperties.
* MultiFormatProperties support YAML format.
* Historical of modifications can be exported to Markdown code : Version.getMarkdownCode().
* Sign git commits.


### 3.14.6 Stable (10/05/2018)
* Update BCFIPS to 1.0.1.
* Update common-codec to 1.11.
* Renaming ECDDH to ECCDH.


### 3.14.5 Stable (28/04/2018)
* Key.encode() is now public.
* Generate 'versions.html' file into jar files.
* Correct a bug with collections of type Class.


### 3.14.2 Stable (11/04/2018)
* Add function KeyAgreementType.getDefaultKeySizeBits().
* Add function KeyAgreementType.getCodeProvider().


### 3.14.0 Stable (11/04/2018)
* Add KeyAgreementType and KeyAgreement class. 
* NewHope and ECDA use now the same protocol.
* Add SHA2-512/224 message digest.
* Add SHA2-512/256 message digest.
* Add SHA2-512/224 HMAC.
* Add SHA2-512/256 HMAC.
* Add functions isPostQuantomAlgorithm into several classes.


### 3.13.4 Stable (09/04/2018)
* Correction of a null pointer exception.
* Security fix : counter was transmitted to other peer.
* Fill keys with zeros when they are destroyed.
* Fill intermediate variables with zeros when they are destroyed of after they are used.


### 3.13.1 Stable (27/03/2018)
* Add possibility to use a counter with CTR mode.


### 3.13.0 Stable (26/03/2018)
* Add CTR mode support.
* Optmizations of Numbers allocations.
* Add function OSValidator.getJVMLocation.
* Add function OSValidator.supportAESIntrinsicsAcceleration.


### 3.12.0 Stable (10/03/2018)
* Add sphincs signature (Post Quantum Cryptography).
* Optimize encryption and minimize memory allocation.


### 3.11.1 Stable (10/03/2018)
* Add speed indexes for symmetric encryptions.


### 3.11.0 Stable (08/03/2018)
* Add BouncyCastle GCM and EAX authenticated block modes for symmetric encryptions.


### 3.10.5 Stable (10/02/2018)
* Java 7 compatible.


### 3.10.4 Stable (10/02/2018)
* Fix a problem with BC Mac Length.
* Add asymmetric encryption algorithms.
* Add asymmetric key wrapper algorithms.
* Rename getKeySize to getKeySizeBits.
* Password hashes are now identified. Now, there is no need to know the type and the parameters of the password hash to compare it with original password.


### 3.10.0 Stable (09/02/2018)
* Encryption algorithms does not need signed JAR to work. So this release work on official Oracle JVM.
* Add a post quantum cryptography algorithm : New Hope Key Exchanger.


### 3.9.0 Stable (31/01/2018)
* Add curve M-221 for asymmetric signatures and ECDH Key Exchangers.
* Add curve M-383 for asymmetric signatures and ECDH Key Exchangers.
* Add curve M-511 for asymmetric signatures and ECDH Key Exchangers.
* Add curve 41417 for asymmetric signatures and ECDH Key Exchangers.


### 3.8.0 Stable (27/01/2018)
* Update bouncy castle to 1.59b
* Add PKBFs with SHA3 hash method
* Use now BouncyCastle implementation of BCrypt (instead of Berry)
* Use now BouncyCastle implementation of SCrypt (instead of Tamaya
* Removing dependencies with JUnit. Use only TestNG.
* Change iteration numver variable to cost variable with PBKF.
* Add curve 25519 for asymmetric signatures.


### 3.7.1 Stable (25/11/2017)
* Add function AbstractEncryptionIOAlgorithm.decode(InputStream is, OutputStream os, int length)
* Add function AbstractEncryptionOutputAlgorithm.public void encode(byte[] bytes, int off, int len, OutputStream os)
* Add scrypt algorithm


### 3.7.0 Stable (25/11/2017)
* Correction of Mac OS Compatibility
* Add scrypt algorithm


### 3.6.0 Stable (02/11/2017)
* Add blake 2b message digest
* ECDDH are now FIPS compliant


### 3.4.0 Stable (02/11/2017)
* Add data buffers classes


### 3.3.0 Stable (23/10/2017)
* Improving key wrapping process
* Decentralized ID can now be entirely hashed


### 3.2.4 Stable (09/10/2017)
* Fix an issue with signature process
* Fix an issue with signature size
* Add throw exception when local et distant public keys are the same with ECDH key agreement
* Fix issue with ASymmetricKeyPair for signature encoding


### 3.2.0 Stable (06/10/2017)
* Changing default JVM secured random


### 3.1.1 Stable (06/10/2017)
* Adding abstract random into class ClientASymmetricEncryptionAlgorithm
* Adding function MessageDigestType.getDigestLengthInBits()
* Adding function SymmetricAuthentifiedSignatureType.getSignatureSizeInBits()


### 3.1.0 Stable (05/10/2017)
* Correcting a bug with seed generator
* Improving fortuna random speed
* Add native non blocking secure random


### 3.0.5 Stable (05/10/2017)
* Correcting a bug with seed generator


### 3.0.0 Stable (04/10/2017)
* Minimal corrections into PasswordHash class
* Updating Bouncy Castle to 1.58 version
* FIPS compliant
* Add symmetric and asymmetric key wrappers classes
* Add BCFIPS password hash algorithms
* Add password key derivation class
* Add generic aggreement protocol class


### 2.16.2 Stable (01/09/2017)
* Renforcing MAC address anonymization
* Possibility to convert UUID to DencentelizedID


### 2.16.0 Stable (01/09/2017)
* Adding support for SHA3
* Dencentralized ID's use now anonymized MAC address and random numbers
* Adding NIST SP 800 support with DRBG_BOUNCYCASTLE SecureRandomType
* Adding NIST SP 800 support with Fortuna


### 2.15.1 Stable (21/08/2017)
* Minimal corrections


### 2.15.0 Stable (15/08/2017)
* Add FortunaSecureRandom class
* Making FortunaSecureRandom default secured random generator
* Auto-reseed for all secured random generators


### 2.14.0 Stable (13/08/2017)
* Debuging EllipticCurveDiffieHellmanAlgorithm


### 2.12.0 Stable (10/08/2017)
* Enabling 256 bits SUN AES encryption


### 2.12.0 Stable (05/08/2017)
* Minimal corrections


### 2.11.0 Stable (04/08/2017)
* Converting project to gradle project


### 2.10.0 Stable (19/06/2017)
* Adding symmetric signture algorithms
* Altereging P2PJPAKESecretMessageExchanger class


### 2.9.0 Stable (18/06/2017)
* Adding Elliptic Curve Diffie-Hellman key exchange support
* Password Authenticated Key Exchange by Juggling (2008) algorithm
* Adding Bouncy Castle algorithms


### 2.8.0 Stable (01/06/2017)
* Managing enum type into XML properties
* XML properties are able to manage abstract sub XML properties


### 2.7.1 Stable (23/05/2017)
* Altering ListClasses


### 2.7.0 Stable (03/05/2017)
* Adding primitive tab support for XML Properties


### 2.6.1 Stable (24/04/2017)
* JDK 7 compatible
* Correcting a bug with testReadWriteDataPackaged in CryptoTests


### 2.6.0 Stable (24/04/2017)
* Adding RegexTools class
* JDK 7 compatible


### 2.5.0 Stable (07/03/2017)
* Improving and renforcing P2PAsymmetricSecretMessageExchanger
* Additional manifest content possibility for projects export


### 2.4.0 Stable (04/03/2017)
* Debugging documentation export
* Updating common net to 3.6 version


### 2.3.0 Stable (07/02/2017)
* AbstractXMLObjectParser is now serializable


### 2.2.0 Stable (05/01/2017)
* Updating IDGeneratorInt class and fix memory leak problem


### 2.1.0 Stable (31/12/2016)
* Adding expiration time for public keys


### 2.0.1 Stable (23/12/2016)
* Changing gnu cryto packages


### 2.0.0 Stable (17/12/2016)
* Including Gnu Crypto Algorithms.


### 1.9.0 Stable (06/12/2016)
* Correcting a bug with the use of IV parameter. Now, the IV parameter is generated for each encryption.
* Adding class SecureRandomType.


### 1.8.0 Stable (13/10/2016)
* Adding password hash (PBKDF and bcrypt)


### 1.7.2 Stable (15/09/2016)
* Correcting a bug for P2PASymmetricSecretMessageExchanger
* Adding toString and valueOf functions for crypto keys
* Possibility to put crypto keys in XMLProperties class
* Adding 'valueOf' for Decentralized IDs
* Decentralized IDs are exportable into XML Properties


### 1.7.1 Stable (23/08/2016)
* Correcting a bug for loop back network interface speed
* Correcting a bug for P2PASymmetricSecretMessageExchanger
* Correcting a bug big data asymmetric encryption
* Adding symmetric et asymmetric keys encapsulation


### 1.7.0 Stable (04/07/2016)
* Renaming class ASymmetricEncryptionAlgorithm to P2PASymmetricEncryptionAlgorithm
* Adding class SignatureCheckerAlgorithm
* Adding class SignerAlgorithm
* Adding class ClientASymmetricEncryptionAlgorithm
* Adding class ServerASymmetricEncryptionAlgorithm
* Updating to Common-Net 3.5


### 1.6.1 Stable (10/06/2016)
* Correcting bug into XMLProperties class
* Adding tests for XMLProperties class
* Changing license to CECILL-C.
* Correcting bugs into DecentralizedIDGenerator classes
* Adding salt management into SecuredIDGenerator class
* Adding salt management into PeerToPeerASymetricSecretMessageExanger class


### 1.6.0 Stable (15/03/2016)
* Adding unit tests possibility for project export tools
* Adding unit compilation for project export tools
* Adding new licences


### 1.5.0 Stable (09/03/2016)
* Adding PeerToPeerASymmetricSecretMessageExchanger class
* Adding ObjectSizer class (determins sizeof each java object instance)
* Adding keys encoding
* Adding decentralized id encoding/decoding


### 1.4.0 Stable (01/03/2016)
* Adding encryption utilities


### 1.3.1 Stable (24/02/2016)
* Set Bits static functions public


### 1.3.0 Stable (22/02/2016)
* Adding SecuredDecentralizedID class


### 1.2.0 Stable (15/02/2016)
* Adding function AbstractXMLObjectParser.isValid(Class)
* Correcting export bug : temporary files were not deleted.


### 1.1.0 Stable (14/02/2016)
* Adding some internal modifications to ReadWriteLocker


### 1.0.0 Stable (04/02/2016)
* Realeasing first version of Utils

