package com.distrimind.util.export;

import java.io.File;

public class JarSourceDependancy extends ZipSourceDependancy
{

    /**
     * 
     */
    private static final long serialVersionUID = -8549899601602433999L;

    public JarSourceDependancy(File _jar_file)
    {
	this(_jar_file, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    public JarSourceDependancy(File _jar_file, String _exclude_regex, String _include_regex)
    {
	super(_jar_file, _exclude_regex, _include_regex);
    }
    
}
