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
import java.io.IOException;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */

public abstract class BinaryDependency extends Dependency
{
    /**
     * 
     */
    private static final long serialVersionUID = -8201572367856505672L;
    
    private String name;
    private SourceDependancy sourceCode;

    private Package subpackage;
    
    protected String exclude_regex;
    protected String include_regex;
    private License licenses[];

    public BinaryDependency()
    {
	
    }
    
    public BinaryDependency(String name, SourceDependancy source_code, Package _subpackage, License licenses[], String _exclude_regex, String _include_regex)
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
	this.licenses=licenses;
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
    
    public License[] getLicenses()
    {
	return licenses;
    }
    
    abstract String getClassPath();
    abstract String getAntSetFile();
    
    private final static String possibleLicenseFileNames[]={"COPYING,LICENSE,COPYING.TXT, LICENSE.TXT,COPYING.txt, LICENSE.txt,copying,license,copying.txt, license.txt"};
    
    
    public void exportLicences(File directory_destination) throws IOException
    {
	BinaryDependency.exportLicences(getName(), licenses, directory_destination, false);
    }
    static void exportLicences(String projetName, License[] licenses, File directory_destination, boolean isProjectLicense) throws IOException
    {
	if (!isProjectLicense)
	{
	    File license_file=new File(directory_destination, projetName+"_LICENSE");
	    for (String s : possibleLicenseFileNames)
	    {
		File f=new File(directory_destination, s);
	    
		if (f.exists() && f.isFile())
		{
		    if (licenses!=null && licenses.length>0)
		    {
			f.delete();
			break;
		    }
		    else
		    {
			f.renameTo(license_file);
			return;
		    }
		}
	    }
	}
	if (licenses!=null)
	{
	    if (licenses.length==1)
	    {
		licenses[0].generateLicenseFile(new File(directory_destination, projetName+"_LICENSE"));
		if (isProjectLicense)
		    licenses[0].generateLicenseFile(new File(directory_destination, "LICENSE"));
	    }
	    else
	    {
		for (int i=0;i<licenses.length;i++)
		{
		    licenses[0].generateLicenseFile(new File(directory_destination, projetName+"_LICENSE_"+(i+1)));
		    if (isProjectLicense)
			licenses[0].generateLicenseFile(new File(directory_destination, "LICENSE_"+(i+1)));
		}
	    }
	}
    }
    
}
