package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

import com.distrimind.util.FileTools;

public class JavaProjectSourceDependency extends SourceDependancy
{
    /**
     * 
     */
    private static final long serialVersionUID = 9090559231715064685L;

    private File source_directory;
    
    public JavaProjectSourceDependency(File source_directory)
    {
	this(source_directory, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    public JavaProjectSourceDependency(File source_directory, String _exclude_regex, String _include_regex)
    {
	super(_exclude_regex, _include_regex);
	if (source_directory==null)
	    throw new NullPointerException("source_directory");
	if (!source_directory.exists())
	    throw new IllegalArgumentException(source_directory.toString()+" does not exists !");
	if (!source_directory.isDirectory())
	    throw new IllegalArgumentException(source_directory.toString()+" is not a directory !");
	this.source_directory=source_directory;
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
    

}
