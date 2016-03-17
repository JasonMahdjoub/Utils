/*
 * MadKitGroupExtension (created by Jason MAHDJOUB (jason.mahdjoub@free.fr)) Copyright (c)
 * 2012. Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of MadKitGroupExtension.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
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
package com.distrimind.util.export;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.net.URL;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import javax.lang.model.SourceVersion;

import com.distrimind.util.FileTools;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;
/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */

public class JavaProjectSource extends SourceDependancy
{
    /**
     * 
     */
    private static final long serialVersionUID = 9090559231715064685L;

    protected String projectName;
    private File source_directory;
    private String relativeBuildFile;
    private Class<?> main_class;
    private String description;
    private Version version;
    private ArrayList<BinaryDependency> dependencies;
    private ArrayList<File> additional_directories_and_files_to_export=new ArrayList<>();
    private SourceVersion javaVersion;
    private String encoding;
    private Package representedPackage;
    private License[] licenses;
    private TestSuiteSource testSuiteSource;
    private File jdkDirectory;
    private URL projectWebSite;
    private URL gitHUBLink;
    private boolean verbose=false;
    private boolean debugMode=false;
    
    public boolean isDebugMode()
    {
        return debugMode;
    }

    public void setDebugMode(boolean _debugMode)
    {
        debugMode = _debugMode;
    }

    public boolean isVerbose()
    {
        return verbose;
    }

    public void setVerbose(boolean _verbose)
    {
        verbose = _verbose;
    }

    public URL getGitHUBLink()
    {
        return gitHUBLink;
    }

    public void setGitHUBLink(URL _gitHUBLink)
    {
        gitHUBLink = _gitHUBLink;
    }

    private File fileLogo;
    
    public File getFileLogo()
    {
        return fileLogo;
    }

    public void setFileLogo(File _fileLogo)
    {
        fileLogo = _fileLogo;
    }

    public URL getProjectWebSite()
    {
        return projectWebSite;
    }

    public void setProjectWebSite(URL _projectWebSite)
    {
        projectWebSite = _projectWebSite;
    }

    public JavaProjectSource()
    {
	
    }
    
    public JavaProjectSource(File root_directory, File source_directory, Package representedPackage, License licenses[], String relativeBuildFile, Class<?> main_class, String description, Version version, SourceVersion javaVersion, ArrayList<BinaryDependency> dependencies, ArrayList<File> additional_directories_and_files_to_export, File jdkDirectory) {
	this(root_directory, source_directory, representedPackage, licenses, relativeBuildFile, main_class, description, version, javaVersion, dependencies, additional_directories_and_files_to_export, jdkDirectory, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    
    public JavaProjectSource(File root_directory, File source_directory, Package representedPackage, License licenses[], String relativeBuildFile, Class<?> main_class, String description, Version version, SourceVersion javaVersion, ArrayList<BinaryDependency> dependencies, ArrayList<File> additional_directories_and_files_to_export, File jdkDirectory, String _exclude_regex, String _include_regex)
    {
	super(true, _exclude_regex, _include_regex);
	if (source_directory==null)
	    throw new NullPointerException("source_directory");
	if (!source_directory.exists())
	    throw new IllegalArgumentException(source_directory.toString()+" does not exists !");
	if (!source_directory.isDirectory())
	    throw new IllegalArgumentException(source_directory.toString()+" is not a directory !");
	this.source_directory=source_directory;
	
	if (!root_directory.exists())
	    throw new IllegalArgumentException(root_directory.toString()+" does not exists !");
	if (!root_directory.isDirectory())
	    throw new IllegalArgumentException(root_directory.toString()+" is not a directory !");
	projectName=root_directory.getName();
	if (relativeBuildFile==null)
	    throw new NullPointerException("relativeBuildFile");
	this.relativeBuildFile=relativeBuildFile;
	this.main_class=main_class;
	if (description==null)
	    throw new NullPointerException("description");
	this.description=description;
	if (version==null)
	    throw new NullPointerException("version");
	this.version=version;
	if (dependencies==null)
	    this.dependencies=new ArrayList<>();
	else
	    this.dependencies=dependencies;
	if (additional_directories_and_files_to_export==null)
	    this.additional_directories_and_files_to_export=new ArrayList<>();
	else
	    this.additional_directories_and_files_to_export=additional_directories_and_files_to_export;
	if (representedPackage==null)
	    throw new NullPointerException("representedPackage");
	this.representedPackage=representedPackage;
	this.licenses=licenses;
	if (javaVersion==null)
	    throw new NullPointerException("javaVersion");
	this.javaVersion=javaVersion;
	this.encoding="UTF-8";
	if (jdkDirectory==null)
	    throw new NullPointerException("jdkDirectory");
	this.jdkDirectory=jdkDirectory;
    }
    
    
    public void setEncoding(String encoding)
    {
	this.encoding=encoding;
    }
    public String getEncoding()
    {
	return this.encoding;
    }
    
    public void setTestSuiteSource(File root_directory, File _source_directory, Package _representedPackage, ArrayList<BinaryDependency> _dependencies, ArrayList<File> _additional_directories_and_files_to_export, TestSuite suite) throws IOException
    {
	this.setTestSuiteSource(root_directory, _source_directory, _representedPackage, _dependencies, _additional_directories_and_files_to_export, suite, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    
    @SuppressWarnings("unchecked")
    public void setTestSuiteSource(File root_directory, File _source_directory, Package _representedPackage, ArrayList<BinaryDependency> _additional_dependencies, ArrayList<File> _additional_directories_and_files_to_export, TestSuite suite, String _exclude_regex, String _include_regex) throws IOException
    {
	_additional_dependencies=(ArrayList<BinaryDependency>)_additional_dependencies.clone();
	_additional_dependencies.addAll(this.dependencies);
	FileTools.copy(getBuildFilePath(this.source_directory), getBuildFilePath(_source_directory));
	testSuiteSource=new TestSuiteSource(root_directory, _source_directory, _representedPackage, licenses, relativeBuildFile, "Test suite of "+projectName, this.version, javaVersion, _additional_dependencies, _additional_directories_and_files_to_export, suite, jdkDirectory, _exclude_regex, _include_regex);
	testSuiteSource.setDebugMode(true);
    }
    
    public File getBuildFilePath(File _destination_root)
    {
	return new File(_destination_root, this.relativeBuildFile);
    }

    @Override
    public void copySourceToFolder(File _folder) throws IOException
    {
	FileTools.copyFolderToFolder(source_directory, _folder, false, this.exclude_regex, this.include_regex);
    }
    
    public File getSourceDirectory()
    {
	return source_directory;
    }
    
    boolean compileSource(File _src, File _dst) throws IOException, InterruptedException
    {
	return compileSource(_src, _src, _dst, null, null);
    }
    private boolean compileSource(File root_dir, File _src, File _dst, String _package, ArrayList<String> files) throws IOException, InterruptedException
    {
	if (_src==null)
	    throw new NullPointerException("_src");
	if (_dst==null)
	    throw new NullPointerException("_dst");

	if (!_dst.exists())
	    FileTools.checkFolderRecursive(_dst);
	if (!_dst.isDirectory())
	    throw new IllegalArgumentException("_dst must be a directory");
	if (!_src.exists())
	    throw new IllegalArgumentException("_src doest not exist !");
	if (!_src.isDirectory())
	    throw new IllegalArgumentException("_src must be a directory");
	
	String antXMLbuild="<project name=\""+projectName+"\" default=\"compile\">"
		+ "<path id=\"classpath\">";
	antXMLbuild+=getAntSetFile();		
	if (projectName.equals("Utils"))
	{
	    for (BinaryDependency bd : this.testSuiteSource.getDependencies())
	    {
		    antXMLbuild+=bd.getAntSetFile();
	    }
	}
	antXMLbuild+="</path>"
		+ "<path id=\"lib.path.ref\">"
		+ "	<fileset dir=\""+this.jdkDirectory+"/jre/lib/\" includes=\"*.jar\"/>"
		+ "</path>"
		+ "<target name=\"compile\">"
		+ "	<property name=\"jdk\" location=\""+this.jdkDirectory+"\"/>"
		+ "	<property name=\"javacexec\" location=\"${jdk}/bin/javac\" />"
		+ "	<property name=\"ant.build.javac.source\" value=\"1."+javaVersion.ordinal()+"\"/>"
		+ "	<property name=\"ant.build.javac.target\" value=\"1."+javaVersion.ordinal()+"\"/>"
		+ "	<javac compiler=\"javac1."+javaVersion.ordinal()+"\" executable=\"${javacexec}\" includeAntRuntime=\"false\" srcdir=\""+_src.getAbsoluteFile()+"\" destdir=\""+_dst.getAbsolutePath()+"\" classpathref=\"classpath\" target=\"1."+javaVersion.ordinal()+"\" encoding=\""+encoding+"\" bootclasspath=\"${toString:lib.path.ref}\""+(debugMode?" debug=\"true\" debuglevel=\"vars\"":"")+">"
		+ "	</javac>"		
		+ "</target>"
		+ "</project>";
	File xmlFile=new File(_src, "build.xml");
	try
	{
	    createAntBuildXMLFile(xmlFile, antXMLbuild);
	
	    String command="ant -buildfile "+xmlFile.getAbsolutePath();
	
	    if (Export.execExternalProcess(command,_src, isVerbose(), true)!=0)
		return false;
	}
	finally
	{
	    xmlFile.delete();
	}
	FileTools.copyFolderToFolder(_src, _dst, false, Dependency.mixRegexes(Dependency.getDefaultBinaryExcludeRegex(), this.exclude_regex),  this.include_regex);	
	return true;
    }
    
    String getAntSetFile()
    {
	String antXMLbuild="";
	for (BinaryDependency bd : getDependencies())
	{
	    antXMLbuild+=bd.getAntSetFile();
	}
	return antXMLbuild;
    }
    
    private String getAntJavadocBuild(File _src, File _dst, boolean includeDependencies) throws IOException
    {
	String antXMLbuild="<project name=\""+projectName+"\" default=\"compile\">"
		+ "<path id=\"classpath\">";
	if (includeDependencies)
	{
	    for (BinaryDependency bd : getDependencies())
	    {
		if (bd.getSourceCode()!=null && bd.getSourceCode().isIncludedToDoc())
		    antXMLbuild+=bd.getSourceCode().getAntSetFile();
	    }
	}
	String HTMLMadkitLink="", HTMLGitHUBLink="";
	if (projectWebSite!=null)
	{
	    if (fileLogo!=null && fileLogo.exists() && fileLogo.isFile())
	    {
		FileTools.copy(fileLogo, new File(_dst, "logo.png"));
		HTMLMadkitLink= "		<a target='blank' href=\""+projectWebSite.toString()+"\"><img alt=\""+projectName+"\" width='20' src=\"{@docRoot}/logo.png\"></a>&nbsp;&nbsp;&nbsp;";
	    }
	    else
		HTMLMadkitLink= "		<a target='blank' href=\""+projectWebSite.toString()+"\"><H3>"+projectName+"\"</H3></a>&nbsp;&nbsp;&nbsp;";
	}
	if (this.gitHUBLink!=null)
	{
	    HTMLGitHUBLink="<a target='blank' href=\""+gitHUBLink+"\"><img alt='GitHub' width='20' src=\"https://github.com/fluidicon.png\"></a>";
	}
	
	antXMLbuild+="</path>"
		+ "<path id=\"lib.path.ref\">"
		+ "	<fileset dir=\""+this.jdkDirectory+"/jre/lib/\" includes=\"*.jar\"/>"
		+ "</path>"
		+ "<target name=\"compile\">"
		+ "	<property name=\"jdk\" location=\""+this.jdkDirectory+"\"/>"
		+ "	<property name=\"javadocexec\" location=\"${jdk}/bin/javadoc\" />"
		+ "	<property name=\"ant.build.javac.source\" value=\"1."+javaVersion.ordinal()+"\"/>"
		+ "	<property name=\"ant.build.javac.target\" value=\"1."+javaVersion.ordinal()+"\"/>"
		+ "	<javadoc sourcepath=\""+_src.getAbsoluteFile()+"\" destdir=\""+_dst.getAbsoluteFile()+"\" classpathref=\"classpath\" access=\"protected\" docfilessubdirs=\"true\" author=\"true\" version=\"true\" use=\"true\" linksource=\"no\" windowtitle=\""+projectName+"\" encoding=\""+encoding+"\">"
		+ "		<doctitle>"
		+ "			<![CDATA[<h1>"+projectName+"</h1><h2>"+description+"</h2>]]>"
		+ "		</doctitle>"
		+ "		<header>"
		+ "		<![CDATA["
		+ 			HTMLMadkitLink
		+ 			HTMLGitHUBLink
		+ 		"]]>"
		+ "		</header>"
		+ "		<bottom>"
		+ "			<![CDATA["
		+ "				<br/>"
		+ "				<p style=' text-indent: 3em;'>"
		+ 					HTMLMadkitLink
		+ 					HTMLGitHUBLink
		+ "					<i><br/>&nbsp;&nbsp;&nbsp;";
	boolean first=true;
	for (Person p : version.getDevelopers())
	{
	    if (first)
		first=false;
	    else
		antXMLbuild+=", ";
	    antXMLbuild+=p.getFirstName()+" "+p.getName();
	}
	antXMLbuild+=" - "+(new SimpleDateFormat("MMMMMMM d YYYY", Locale.ENGLISH).format(new Date(System.currentTimeMillis())))+"</i>"
		+ "				</p>"
		+ "			]]>"
		+ "		</bottom>"
		+ "		<link offline=\"false\" href=\"http://docs.oracle.com/javase/"+javaVersion.ordinal()+"/docs/api/\" />"
		+ "	</javadoc>"		
		+ "</target>"
		+ "</project>";
	return antXMLbuild;
    }
    
    boolean compileDoc(File _src, File _dst) throws IOException, InterruptedException
    {
	if (_src==null)
	    throw new NullPointerException("_src");
	if (_dst==null)
	    throw new NullPointerException("_dst");

	if (!_dst.exists())
	    FileTools.checkFolderRecursive(_dst);
	if (!_dst.isDirectory())
	    throw new IllegalArgumentException("_dst must be a directory");
	if (!_src.exists())
	    throw new IllegalArgumentException("_src doest not exist !");
	if (!_src.isDirectory())
	    throw new IllegalArgumentException("_src must be a directory");

	File xmlFile=new File(_src, "build.xml");
	try
	{
	    createAntBuildXMLFile(xmlFile, getAntJavadocBuild(_src, _dst, false));
	
	    String command="ant -buildfile "+xmlFile.getAbsolutePath();
	
	    boolean ok=Export.execExternalProcess(command,_src, isVerbose(), true)==0;
	    if (ok)
	    {
		xmlFile.delete();
		createAntBuildXMLFile(xmlFile, getAntJavadocBuild(_src, _dst, true));
			
		command="ant -buildfile "+xmlFile.getAbsolutePath();
		
		Export.execExternalProcess(command,_src, false, true);
		return true;
		
	    }
	    else
		return false;
	    
	}
	finally
	{
	    xmlFile.delete();
	}
    }

    public String getClassPath()
    {
	StringBuffer res=new StringBuffer("");
	boolean first=true;
	for (BinaryDependency d : dependencies)
	{
	    if (first)
		first=false;
	    else
		res.append(";");
	    res.append(d.getClassPath());
	}
	
	return res.toString();
    }
  
    
    public Package getRepresentedPackage()
    {
	return this.representedPackage;
    }
    
    public License[] getLicenses()
    {
	return licenses;
    }
    
    public String getRelativeBuildFile()
    {
	return relativeBuildFile;
    }

    public Class<?> getMainClass()
    {
	return main_class;
    }
    public String getDescription()
    {
	return description;
    }
    
    public Version getVersion()
    {
	return version;
    }
    
    public ArrayList<BinaryDependency> getDependencies()
    {
	return dependencies;
    }
    public ArrayList<File> getAdditionalFilesAndDirectoriesToExport()
    {
	return additional_directories_and_files_to_export;
    }
    
    public String getProjectName()
    {
	return projectName;
    }

    void exportLicences(File directory_destination) throws IOException
    {
	BinaryDependency.exportLicences(getProjectName(), licenses, directory_destination, true);
    }
    String getManifest()
    {
	String res="Manifest-Version: 1.0\n" +
	"Description: "+description+"\n"+
	"Version: "+version.toStringShort()+"\n"+
	"Author: ";
	boolean first=true;
	for (PersonDeveloper p : version.getDevelopers())
	{
	    if (first)
		first=false;
	    else
		res+=", ";
	    res+=p.getFirstName()+" "+p.getName();
	}
	res+="\nBuilt-By: ";
	first=true;
	for (Person p : version.getCreators())
	{
	    if (first)
		first=false;
	    else
		res+=", ";
	    res+=p;
	}
	res+="\n";
	if (main_class!=null)
	    res+="Main-Class: "+main_class.getCanonicalName()+"\n";
	return res;
    }
    
    void createManifestFile(File f) throws IOException
    {
	FileWriter fw=new FileWriter(f);
	BufferedWriter b=new BufferedWriter(fw);
	b.write(getManifest());
	b.flush();
	b.close();
	fw.close();
    }
    
    void createAntBuildXMLFile(File f, String antXMLbuild) throws IOException
    {
	try(FileWriter fw=new FileWriter(f))
	{
	    try(BufferedWriter b=new BufferedWriter(fw))
	    {
		b.write(antXMLbuild);
		b.flush();
	    }
	}
    }

    
    
    public TestSuiteSource getTestSuiteSource()
    {
	return testSuiteSource;
    }
    
    void createHTMLVersionFile(File directory) throws IOException
    {
	FileWriter fw=new FileWriter(new File(directory, projectName+"_version.html"));
	BufferedWriter b=new BufferedWriter(fw);
	b.write(version.getHTMLCode());
	b.flush();
	b.close();
	fw.close();
    }
    
    
}
