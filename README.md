# Utils

[![CodeQL](https://github.com/JazZ51/Utils/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/JazZ51/Utils/actions/workflows/codeql-analysis.yml)

Set of Java tools :
* Decentralized identifier generation (similar to UUID, but with hash possibilities and some enforcement)
* XML, YAML and properties class mapping
* Timer
* Get size of Java memory objects
* OS tools (OS version, trace route, hardrive tools, network speed)
* DNS checking and email validation tool
* Progress monitor with progress bar wrapper to enable multi-plateform compatibility
* Cryptography tools
	* Home interface that use of three Implementations : Java native JCE, GNU CRYPT, BouncyCastle (+ BouncyCastle FIPS and BouncyCastle PQC)
	* Encryption algorithms does not need signed JAR to work. So the release work on official Oracle JVM.
	* MessageDigest algorithms
	* Symmetric signatures 
	* Asymmetric signatures
	* Symmetric encryptions
	* Asymmetric encryptions and key wrappers
	* Key agreements
	* DRBG
	* JPAKE algorithm and home secret message exchanger
	* Login thanks to a symmetric signature process
	* Login thanks to an asymmetric signature process
	* Use of post quantum algorithms (New Hope key exchanger, Sphincs, McEliece)
	* Availability of hybrid assymetric key pairs. One hybrid key pair assemble two key pairs : one used with a non post quantum algorithm, and one another used with a post quantum algorithm. Hybrid algorithms like asymmetric encrytion, asymmetric signatures, key agreements, key wrappers, ... enable to use two algorithms (non PQC and PQC) at the same time, in order to keep well-tested non post quantum algorithms with new expérimental post quantum algorithms.
* Compatible with Java 8 and newer
* Random input/output streams (byte array, file). 
* Random cache file output stream which enables to write data into a byte array until an amount of data was reached. Then, when this amount was reached, use instead a file output stream.

# Changes

[See historical of changes](./changelog.md)

###### Requirements under Ubuntu/Debian :
  * Please install the package ethtool, rng-tools, mtr(only debian)

# How to use it ?
## With Gradle :

Adapt into your build.gradle file, the next code :

	...
	repositories {
		...
		maven {
	       		url "https://artifactory.distri-mind.fr/artifactory/gradle-release"
	   	}
		...
	}
	...
	dependencies {
		...
		compile(group:'com.distrimind.util', name: 'Utils', version: '5.21.0-STABLE')
		...
		//choose one of these optional drivers for GnuCrypto algorithms
			testCompile(group:'gnu', name: 'Gnu-Crypt', version: '1.3.0')

	}
	...

To know what last version has been uploaded, please refer to versions availables into [this repository](https://artifactory.distri-mind.fr/artifactory/DistriMind-Public/com/distrimind/util/Utils/)
## With Maven :
Adapt into your pom.xml file, the next code :

	<project>
		...
		<dependencies>
			...
			<dependency>
				<groupId>com.distrimind.util</groupId>
				<artifactId>Utils</artifactId>
				<version>5.21.0-STABLE</version>
			</dependency>
			<!-- choose one of these optional drivers for GnuCrypto algorithms-->
			<dependency>
				<groupId>gnu</groupId>
				<artifactId>Gnu-Crypt</artifactId>
				<version>1.3.0</version>
			</dependency>
			...
		</dependencies>
		...
		<repositories>
			...
			<repository>
				<id>DistriMind-Public</id>
				<url>https://artifactory.distri-mind.fr/artifactory/gradle-release</url>
			</repository>
			...
		</repositories>

	</project>

To know what last version has been uploaded, please refer to versions availables into [this repository](https://artifactory.distri-mind.fr/artifactory/DistriMind-Public/com/distrimind/util/Utils/)



