package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;
import java.util.ArrayList;

import com.distrimind.util.FileTools;
import com.distrimind.util.version.Version;

public class JavaProjectDependency extends BinaryDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = 4690281901500998165L;

    private File binaries_directory;
    private String relativeBuildFile;
    private Class<?> main_class;
    private String description;
    private Version version;
    private ArrayList<BinaryDependency> dependencies;
    private ArrayList<File> additional_directories_and_files_to_export=new ArrayList<>();
    
    public JavaProjectDependency(File root_directory, File binaries_directory, Package _subpackage, License license, JavaProjectSourceDependency source, String relativeBuildFile, Class<?> main_class, String description, Version version, ArrayList<BinaryDependency> dependencies, ArrayList<File> additional_directories_and_files_to_export)
    {
	this(root_directory, binaries_directory, _subpackage,license, source, relativeBuildFile, main_class,description, version, dependencies, additional_directories_and_files_to_export, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    public JavaProjectDependency(File root_directory, File binaries_directory, Package _subpackage, License license, JavaProjectSourceDependency source, String relativeBuildFile, Class<?> main_class, String description, Version version, ArrayList<BinaryDependency> dependencies, ArrayList<File> additional_directories_and_files_to_export, String _exclude_regex, String _include_regex)
    {
	
	super(root_directory.getName(), source, _subpackage, license,_exclude_regex, _include_regex);
	if (!root_directory.exists())
	    throw new IllegalArgumentException(root_directory.toString()+" does not exists !");
	if (!root_directory.isDirectory())
	    throw new IllegalArgumentException(root_directory.toString()+" is not a directory !");

	if (binaries_directory==null)
	    throw new NullPointerException("source_directory");
	if (!binaries_directory.exists())
	    throw new IllegalArgumentException(binaries_directory.toString()+" does not exists !");
	if (!binaries_directory.isDirectory())
	    throw new IllegalArgumentException(binaries_directory.toString()+" is not a directory !");
	this.binaries_directory=binaries_directory;
	if (relativeBuildFile==null)
	    throw new NullPointerException("relativeBuildFile");
	this.relativeBuildFile=relativeBuildFile;
	File f=new File(binaries_directory, relativeBuildFile);
	if (!f.exists())
	    throw new IllegalArgumentException("The build file "+f.toString()+" does not exists !");
	if (!f.isFile())
	    throw new IllegalArgumentException("The build file "+f.toString()+" is not a file !");
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
	
    }

    
    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.copyFolderToFolder(binaries_directory, _folder, false, this.exclude_regex, this.include_regex);
	
    }
    
    public File getBinariesDirectory()
    {
	return binaries_directory;
    }
    
    public File getBuildFilePath(File _destination_root)
    {
	return new File(_destination_root, relativeBuildFile);
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
}
