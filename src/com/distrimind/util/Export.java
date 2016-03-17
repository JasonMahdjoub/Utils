/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
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
import com.distrimind.util.tests.CryptoTests;

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
	Package root_package=Export.class.getPackage();
	Package root_tests_package=CryptoTests.class.getPackage();
	
	License[] licenses={new License(new File("/home/jason/projets/commons-net-3.4/LICENSE.txt"))};
	ArrayList<BinaryDependency> dependencies=new ArrayList<BinaryDependency>();
	dependencies.add(new JarDependency("commons-net", 
		new JarSourceDependancy(false, new File("/home/jason/projets/commons-net-3.4/commons-net-3.4-sources.jar"), null, null),
		org.apache.commons.net.SocketClient.class.getPackage(), 
		licenses, new File("/home/jason/projets/commons-net-3.4/commons-net-3.4.jar"), null, null));

	licenses=new License[1];
	licenses[0]=Utils.LICENSE;
	String regexMath=Dependency.mixRegexes(Dependency.getRegexMatchClass(Export.class), Dependency.getRegexMatchPackage(root_tests_package));
	JavaProjectSource javaProjectSource=new JavaProjectSource(root_dir, src_dir, root_package, licenses, 
		"com/distrimind/util/build.txt", 
		null, "Utils is a set of tools that can be useful in every context of development", 
		Utils.VERSION, SourceVersion.RELEASE_7,
		dependencies,null,new File("/usr/lib/jvm/default-java-7"),
		regexMath, null);
	
	dependencies=new ArrayList<BinaryDependency>();
	licenses=new License[1];
	licenses[0]=new License(PredefinedLicense.APACHE_LICENSE_V2_0);
	dependencies.add(new JarDependency("TestNG", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/.eclipse/org.eclipse.platform_4.5.2_1473617060_linux_gtk_x86_64/plugins/org.testng.eclipse_6.9.10.201512240000/lib/testng.jar")));
	dependencies.add(new JarDependency("TestNG-jcommander", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/.eclipse/org.eclipse.platform_4.5.2_1473617060_linux_gtk_x86_64/plugins/org.testng.eclipse_6.9.10.201512240000/lib/jcommander.jar")));
	dependencies.add(new JarDependency("TestNG-snakeyaml", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/.eclipse/org.eclipse.platform_4.5.2_1473617060_linux_gtk_x86_64/plugins/org.testng.eclipse_6.9.10.201512240000/lib/snakeyaml.jar")));
	dependencies.add(new JarDependency("TestNG-bsh-2.0b4", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/home/jason/.eclipse/org.eclipse.platform_4.5.2_1473617060_linux_gtk_x86_64/plugins/org.testng.eclipse_6.9.10.201512240000/lib/bsh-2.0b4.jar")));
	licenses=new License[1];
	licenses[0]=new License(PredefinedLicense.ECLIPSE_PUBLIC_LICENSE_V1_0);
	dependencies.add(new JarDependency("JUnit", 
		org.testng.TestNG.class.getPackage(), 
		licenses, new File("/opt/eclipse/plugins/org.junit_4.12.0.v201504281640/junit.jar")));
	
	javaProjectSource.setTestSuiteSource(root_dir, src_tests_dir, root_tests_package, 
		dependencies, null, new TestSuite(new TestNGFile(CryptoTests.class)));
	
	javaProjectSource.setGitHUBLink(new URL("https://github.com/JazZ51/Utils.git"));
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
