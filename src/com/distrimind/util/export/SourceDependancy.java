package com.distrimind.util.export;

import java.io.File;
import java.io.IOException;

public abstract class SourceDependancy extends Dependency
{
    
    /**
     * 
     */
    private static final long serialVersionUID = 8802651622337338561L;

    protected final String exclude_regex;
    protected final String include_regex;
    
    public SourceDependancy(String _exclude_regex, String _include_regex)
    {
	exclude_regex=_exclude_regex;
	include_regex=_include_regex;
    }
    
    public abstract void copySourceToFolder(File _folder) throws IOException;
    
}
