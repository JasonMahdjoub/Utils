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
import java.net.URL;
import java.util.ArrayList;

import javax.lang.model.SourceVersion;

import com.distrimind.util.export.BinaryDependency;
import com.distrimind.util.export.Dependency;
import com.distrimind.util.export.Exports;
import com.distrimind.util.export.JarDependency;
import com.distrimind.util.export.JarSourceDependancy;
import com.distrimind.util.export.JavaProjectSource;
import com.distrimind.util.export.License;
import com.distrimind.util.export.TestNGFile;
import com.distrimind.util.export.License.PredefinedLicense;
import com.distrimind.util.export.TestSuite;
import com.distrimind.util.export.Exports.ExportProperties;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */
class Export
{
    
   
    static void export() throws Exception
    {
	Exports exports=new Exports();
	File root_dir=new File("/home/jason/git_projects/Utils");
	
	File src_dir=new File(root_dir, "src");
	File src_tests_dir=new File(root_dir, "Tests");
	if (!root_dir.exists() || !src_dir.exists() || !src_tests_dir.exists())
	    throw new IllegalAccessError();
	Package root_package=Export.class.getPackage();
	Package root_tests_package=DecentralizedIDTests.class.getPackage();
	
	License[] licenses={new License(new File("/home/jason/projets/commons-net-3.5/LICENSE.txt"))};
	ArrayList<BinaryDependency> dependencies=new ArrayList<BinaryDependency>();
	dependencies.add(new JarDependency("commons-net", 
		new JarSourceDependancy(false, new File("/home/jason/projets/commons-net-3.5/commons-net-3.5-sources.jar"), null, null),
		org.apache.commons.net.SocketClient.class.getPackage(), 
		licenses, new File("/home/jason/projets/commons-net-3.5/commons-net-3.5.jar"), null, null));

	licenses=new License[1];
	licenses[0]=Utils.LICENSE;
	String regexMath=Dependency.getRegexMatchClass(Export.class);
	JavaProjectSource javaProjectSource=new JavaProjectSource(root_dir, src_dir, root_package, licenses, 
		"com/distrimind/util/build.txt", 
		null, "Utils is a set of tools that can be useful in every context of development", 
		Utils.VERSION, SourceVersion.RELEASE_7,
		dependencies,null,new File("/usr/lib/jvm/default-java-7"),
		regexMath, null);
	
	dependencies=new ArrayList<BinaryDependency>();
	licenses=new License[1];
	licenses[0]=new License(PredefinedLicense.APACHE_LICENSE_V2_0);
	String testNGDir=".eclipse/org.eclipse.platform_4.5.2_1473617060_linux_gtk_x86_64/plugins/org.testng.eclipse_6.9.11.201604020423/lib";
	dependencies.add(new JarDependency("TestNG", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/"+testNGDir+"/testng.jar")));
	dependencies.add(new JarDependency("TestNG-jcommander", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/"+testNGDir+"/jcommander.jar")));
	dependencies.add(new JarDependency("TestNG-snakeyaml", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/"+testNGDir+"/snakeyaml.jar")));
	dependencies.add(new JarDependency("TestNG-bsh-2.0b4", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/"+testNGDir+"/bsh-2.0b4.jar")));
	licenses=new License[1];
	licenses[0]=new License(PredefinedLicense.ECLIPSE_PUBLIC_LICENSE_V1_0);
	dependencies.add(new JarDependency("JUnit", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/opt/eclipse/plugins/org.junit_4.12.0.v201504281640/junit.jar")));
	
	javaProjectSource.setTestSuiteSource(root_dir, src_tests_dir, root_tests_package, 
		dependencies, null, new TestSuite(new TestNGFile(EmptyClass.class.getPackage(), "AllTestsNG.xml")));
	javaProjectSource.getAdditionalFilesAndDirectoriesToExport().add(new File(root_dir, "LICENSE_BCRYPT"));
	javaProjectSource.setGitHUBLink(new URL("https://github.com/JazZ51/Utils.git"));
	//javaProjectSource.setVerbose(true);
	exports.setProject(javaProjectSource);
	
	
	
	
	exports.setExportDirectory(new File(root_dir, "exports"));
	exports.setTemporaryDirectory(new File(root_dir, ".tmp_export"));
	ArrayList<ExportProperties> export_properties=new ArrayList<>();
	export_properties.add(new ExportProperties(true, Exports.SourceCodeExportType.SOURCE_CODE_IN_SEPERATE_FILE, true));
	export_properties.add(new ExportProperties(false, Exports.SourceCodeExportType.NO_SOURCE_CODE, false));
	export_properties.add(new ExportProperties(false, Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE, false));
	export_properties.add(new ExportProperties(true, Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE, false));
	export_properties.add(new ExportProperties(true, Exports.SourceCodeExportType.NO_SOURCE_CODE, false));
	exports.setExportsSenarios(export_properties);
	exports.export();
    }
    
    
    public static void main(String args[]) throws Exception
    {
	export();
    }
}
