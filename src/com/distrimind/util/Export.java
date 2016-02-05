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

	exports.setProject(new JavaProjectDependency(root_dir, bin_dir, root_package, new License(License.PredefinedLicense.GNU_LGPL_v3_0), 
		new JavaProjectSourceDependency(src_dir, Dependency.getRegexMatchClass(Export.class), null), "com/distrimind/util/build.txt", 
		null, "Utils is a set of tools that can be useful in every context of development", 
		Utils.VERSION,
		dependencies,null,
		Dependency.getRegexMatchClass(Export.class), null));
	
	
	
	exports.setExportDirectory(new File(root_dir, "exports"));
	exports.setJavaVersion(SourceVersion.RELEASE_7);
	exports.setTemporaryDirectory(new File(root_dir, ".tmp_export"));
	ArrayList<ExportProperties> export_properties=new ArrayList<>();
	export_properties.add(new ExportProperties(true, Exports.SourceCodeExportType.SOURCE_CODE_IN_SEPERATE_FILE, true));
	export_properties.add(new ExportProperties(false, Exports.SourceCodeExportType.NO_SOURCE_CODE, false));
	export_properties.add(new ExportProperties(false, Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE, false));
	export_properties.add(new ExportProperties(true, Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE, false));
	exports.setExportsSenarios(export_properties);
	exports.export();
    }
    
    
    public static void main(String args[]) throws Exception
    {
	export();
    }
}
