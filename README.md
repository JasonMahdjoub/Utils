# Utils
Set of Java tools

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
		compile(group:'com.distrimind.util', name: 'Utils', version: '3.2.4')
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
				<version>3.2.4</version>
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

