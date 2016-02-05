package com.distrimind.util.export;

import java.io.File;

public class JarDependency extends ZipDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = -4487382904467263330L;
    
    
    public JarDependency(String name, Package _subpackage, License license, File _jar_file_dependency)
    {
	this(name, new JarSourceDependancy(_jar_file_dependency, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex()), _subpackage,license, _jar_file_dependency, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    public JarDependency(String _name, SourceDependancy _source_code, Package _subpackage, License license, File _jar_file_dependency, String _exclude_regex, String _include_regex)
    {
	super(_name, _source_code, _subpackage, license,_jar_file_dependency, _exclude_regex,_include_regex);
    }

}
