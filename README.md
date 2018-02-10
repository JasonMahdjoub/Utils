# Utils
Set of Java tools :
* Decentralized identifier generation (similar to UUID, but with hash possibilities and some enforcement)
* XML class mapping
* Timer
* Get size of Java memory objects
* OS tools (OS version, trace route, hardrive tools, network speed)
* Cryptography tools
	* Home interface that use of three Implementations : Java native JCE, GNU CRYPT, BouncyCastle (And BouncyCastle FIPS)
	* Encryption algorithms does not need signed JAR to work. So the release work on official Oracle JVM.
	* MessageDigest algorithms
	* Symmetric signatures
	* Asymmetric signatures
	* Symmetric encryptions
	* Asymmetric encryptions and key wrappers
	* Key agreements
	* DRBG
	* JPAKE algorithm and home secret message exchanger
	* Use of post quantum algorithm (New Hope key exchanger)
* Compatible with Java 7 and newer



# How to use it ?
## With Gradle :

Adapt into your build.gradle file, the next code :

	...
	repositories {
		...
		maven {
	       		url "https://mahdjoub.net/artifactory/DistriMind-Public"
	   	} 
		...
	}
	...
	dependencies {
		...
		compile(group:'com.distrimind.util', name: 'Utils', version: '3.10.2')
		...
	}
	...

To know what last version has been uploaded, please refer to versions availables into [this repository](https://mahdjoub.net/artifactory/DistriMind-Public/com/distrimind/util/Utils/)
## With Maven :
Adapt into your pom.xml file, the next code :

	<project>
		...
		<dependencies>
			...
			<dependency>
				<groupId>com.distrimind.util</groupId>
				<artifactId>Utils</artifactId>
				<version>3.10.2</version>
			</dependency>
			...
		</dependencies>
		...
		<repositories>
			...
			<repository>
				<id>DistriMind-Public</id>
				<url>https://mahdjoub.net/artifactory/DistriMind-Public</url>
			</repository>
			...
		</repositories>
	</project>

To know what last version has been uploaded, please refer to versions availables into [this repository](https://mahdjoub.net/artifactory/DistriMind-Public/com/distrimind/util/Utils/)

