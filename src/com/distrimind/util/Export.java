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
import java.util.ArrayList;

import javax.lang.model.SourceVersion;

import com.distrimind.util.export.BinaryDependency;
import com.distrimind.util.export.Dependency;
import com.distrimind.util.export.Exports;
import com.distrimind.util.export.JarDependency;
import com.distrimind.util.export.JarSourceDependancy;
import com.distrimind.util.export.JavaProjectDependency;
import com.distrimind.util.export.JavaProjectSourceDependency;
import com.distrimind.util.export.License;
import com.distrimind.util.export.Exports.ExportProperties;
import com.distrimind.util.tests.CryptoTests;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
class Export
{
   
    static void export() throws Exception
    {
	Exports exports=new Exports();
	File root_dir=new File("/home/jason/git_projects/Utils");
	File bin_dir=new File(root_dir, "bin");
	File src_dir=new File(root_dir, "src");
	Package root_package=Export.class.getPackage();
	
	ArrayList<BinaryDependency> dependencies=new ArrayList<BinaryDependency>();
	dependencies.add(new JarDependency("commons-net", 
		new JarSourceDependancy(new File("/home/jason/projets/commons-net-3.4/commons-net-3.4-sources.jar"), null, null),
		org.apache.commons.net.SocketClient.class.getPackage(), 
		new License(new File("/home/jason/projets/commons-net-3.4/LICENSE.txt")), new File("/home/jason/projets/commons-net-3.4/commons-net-3.4.jar"), null, null));

	String regexMath=Dependency.mixRegexes(Dependency.getRegexMatchClass(Export.class), Dependency.getRegexMatchPackage(CryptoTests.class.getPackage()));
	exports.setProject(new JavaProjectDependency(root_dir, bin_dir, root_package, Utils.LICENSE, 
		new JavaProjectSourceDependency(src_dir, regexMath, null), "com/distrimind/util/build.txt", 
		null, "Utils is a set of tools that can be useful in every context of development", 
		Utils.VERSION,
		dependencies,null,
		regexMath, null));
	
	
	
	exports.setExportDirectory(new File(root_dir, "exports"));
	exports.setJavaVersion(SourceVersion.RELEASE_7);
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
