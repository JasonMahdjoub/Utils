package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

import com.distrimind.util.FileTools;

public class ZipDependency extends BinaryDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = -6230684853876461834L;

    private File jar_dependency;
    
    public ZipDependency(String name, Package _subpackage, License license, File jar_file_dependency)
    {
	this(name, new ZipSourceDependancy(jar_file_dependency, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex()),_subpackage,license, jar_file_dependency, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    
    public ZipDependency(String name, SourceDependancy source_code, Package _subpackage, License license, File jar_file_dependency, String _exclude_regex, String _include_regex)
    {
	super(name, source_code, _subpackage, license,_exclude_regex, _include_regex);
	if (jar_file_dependency==null)
	    throw new NullPointerException("jar_file_dependency");
	if (!jar_file_dependency.exists())
	    throw new IllegalArgumentException("The given file does not exists : "+jar_file_dependency);
	if (!jar_file_dependency.isFile())
	    throw new IllegalArgumentException("The given file is not a file : "+jar_file_dependency);
	jar_dependency=jar_file_dependency;
    }


    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.unzipFile(jar_dependency, _folder, exclude_regex, include_regex);
    }
    
    public File getFile()
    {
	return jar_dependency;
    }
    

}
