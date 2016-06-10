/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

This software is governed by the CeCILL-C license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
 */
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
