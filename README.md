# Utils
Set of Java tools :
* Decentralized identifier generation (similar to UUID, but with hash possibilities and some enforcement)
* XML, YAML and properties class mapping
* Timer
* Get size of Java memory objects
* OS tools (OS version, trace route, hardrive tools, network speed)
* DNS checking and email validation tool
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
	* Use of post quantum algorithm (New Hope key exchanger, Sphincs)
* Compatible with Java 7 and newer

# Changes

[See historical of changes](./versions.md)

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
		compile(group:'com.distrimind.util', name: 'Utils', version: '3.25.2-Stable')
		...
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
				<version>3.25.2-Stable</version>
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
