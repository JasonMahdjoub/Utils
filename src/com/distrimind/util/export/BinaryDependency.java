/*
 * MadKitGroupExtension (created by Jason MAHDJOUB (jason.mahdjoub@free.fr)) Copyright (c)
 * 2012. Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of MadKitGroupExtension.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
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
