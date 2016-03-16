package com.distrimind.util.export;

import java.io.File;
import java.util.ArrayList;

import javax.lang.model.SourceVersion;

import com.distrimind.util.version.Version;

public class TestSuiteSource extends JavaProjectSource
{

    /**
     * 
     */
    private static final long serialVersionUID = 5502788565610555228L;
    private TestSuite suite;
    
    TestSuiteSource(File _root_directory, File _source_directory, Package _representedPackage, License licenses[], String relativeBuildFile, String _description, Version _version, SourceVersion javaVersion, ArrayList<BinaryDependency> _dependencies, ArrayList<File> _additional_directories_and_files_to_export, TestSuite suite, File jdkDirectory, String _exclude_regex, String _include_regex)
    {
	super(_root_directory, _source_directory, _representedPackage, licenses,
		relativeBuildFile, TestSuite.class, _description, _version,javaVersion, _dependencies,
		_additional_directories_and_files_to_export, jdkDirectory, _exclude_regex,
		_include_regex);
	projectName=projectName+"-Tests";
	if (suite==null)
	    throw new NullPointerException("suite");
	this.suite=suite;
    }
    
    public TestSuite getTestSuite()
    {
	return suite;
    }
    

}
