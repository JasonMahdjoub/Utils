package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

import com.distrimind.util.FileTools;

public class DirectorySourceDependency extends SourceDependancy
{
    /**
     * 
     */
    private static final long serialVersionUID = -230008841247197746L;
    
    
    private File directory;
    
    public DirectorySourceDependency(File directory)
    {
	this(directory, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    
    public DirectorySourceDependency(File directory, String _exclude_regex, String _include_regex)
    {
	super(_exclude_regex, _include_regex);
	if (directory==null)
	    throw new NullPointerException("directory");
	if (!directory.exists())
	    throw new IllegalArgumentException("The directory "+directory+" does not exists !");
	if (!directory.isDirectory())
	    throw new IllegalArgumentException("The directory "+directory+" is not a directory !");
	    
	this.directory=directory;
    }

    @Override
    public void copySourceToFolder(File _folder) throws IOException
    {
	FileTools.copyFolderToFolder(directory, _folder, false);
	
    }

    
}
