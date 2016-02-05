package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

import com.distrimind.util.FileTools;

public class DirectoryDependency extends BinaryDependency
{
    /**
     * 
     */
    private static final long serialVersionUID = 7990469461822747800L;
    
    private File directory;
    
    public DirectoryDependency(String _name, SourceDependancy _source_code, Package _subpackage, License _license, File directory)
    {
	this(_name, _source_code, _subpackage, _license, directory, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    public DirectoryDependency(String _name, SourceDependancy _source_code, Package _subpackage, License _license, File directory, String _exclude_regex, String _include_regex)
    {
	super(_name, _source_code, _subpackage, _license, _exclude_regex,
		_include_regex);
	if (directory==null)
	    throw new NullPointerException("directory");
	if (!directory.exists())
	    throw new IllegalArgumentException("The directory "+directory+" does not exists !");
	if (!directory.isDirectory())
	    throw new IllegalArgumentException("The directory "+directory+" is not a directory !");
	    
	this.directory=directory;
	
    }

    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.copyFolderToFolder(directory, _folder, false);
	
    }

}
