package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

import com.distrimind.util.FileTools;

public class ZipSourceDependancy extends SourceDependancy
{
    /**
     * 
     */
    private static final long serialVersionUID = -5705281615082697091L;
    
    private final File source_file;
    
    public ZipSourceDependancy(File _jar_file)
    {
	this(_jar_file, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    
    public ZipSourceDependancy(File _jar_file, String _exclude_regex, String _include_regex)
    {
	super(_exclude_regex, _include_regex);
	if (_jar_file==null)
	    throw new NullPointerException("_jar_file");
	if (!_jar_file.exists())
	    throw new IllegalArgumentException("The given file does not exists : "+_jar_file);
	source_file=_jar_file;
    }
    
    @Override
    public void copySourceToFolder(File _folder) throws IOException
    {
	FileTools.unzipFile(source_file, _folder, exclude_regex, include_regex);
    }

    public File getFile()
    {
	return source_file;
    }
    
}
