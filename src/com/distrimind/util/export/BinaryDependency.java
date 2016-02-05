package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

public abstract class BinaryDependency extends Dependency
{
    /**
     * 
     */
    private static final long serialVersionUID = -8201572367856505672L;
    
    private final String name;
    private final SourceDependancy sourceCode;

    private Package subpackage;
    
    protected final String exclude_regex;
    protected final String include_regex;
    private final License license;

    public BinaryDependency(String name, SourceDependancy source_code, Package _subpackage, License license, String _exclude_regex, String _include_regex)
    {
	if (name==null)
	    throw new NullPointerException("name");
	if (_subpackage==null)
	    throw new NullPointerException("_subpackage");
	this.name=name;
	this.sourceCode=source_code;
	subpackage=_subpackage;
	exclude_regex=_exclude_regex;
	include_regex=_include_regex;
	this.license=license;
    }
    
    
    public void copySourceToFolder(File _folder) throws IOException
    {
	if (sourceCode==null)
	    throw new NullPointerException("sourceCode");
	sourceCode.copySourceToFolder(_folder);
    }
    public abstract void copyBinToFolder(File _folder) throws IOException;
    
    public boolean hasSource()
    {
	return sourceCode!=null;
    }
    public SourceDependancy getSourceCode()
    {
	return sourceCode;
    }
    public String getName()
    {
	return name;
    }
    
    public Package getPackage()
    {
	return subpackage;
    }
    
    public License getLicense()
    {
	return license;
    }
    
}
