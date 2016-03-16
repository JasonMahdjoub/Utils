/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
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
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import com.distrimind.util.FileTools;
import com.distrimind.util.properties.XMLProperties;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.2
 * @since Utils 1.0
 */
public class License extends XMLProperties
{
    
    /**
     * 
     */
    private static final long serialVersionUID = -7612318979584347160L;
    
    private PredefinedLicense predefined_license;
    private File personal_license_file;
    private String personal_license; 

    public License()
    {
	super(null);
    }

    public License(PredefinedLicense predefined_license)
    {
	super(null);
	if (predefined_license==null)
	    throw new NullPointerException("predefined_license");
	this.predefined_license=predefined_license;
	personal_license_file=null;
	personal_license=null;
    }

    public License(File personal_license_file)
    {
	super(null);
	if (personal_license_file==null)
	    throw new NullPointerException("personal_license_file");
	predefined_license=null;
	this.personal_license_file=personal_license_file;
	personal_license=null;
    }

    public License(String licence)
    {
	super(null);
	if (licence==null)
	    throw new NullPointerException("licence");
	predefined_license=null;
	personal_license_file=null;
	personal_license=licence;
    }
    
    public void generateLicenseFile(File file) throws IOException
    {
	if (predefined_license!=null)
	{
	    try(InputStream is=getClass().getResourceAsStream(predefined_license.fileName))
	    {
		try(OutputStream output=new FileOutputStream(file))
		{
		    FileTools.copy(is, output);
		}
	    }
	}
	else if (personal_license!=null)
	{
	    try(FileOutputStream output=new FileOutputStream(file))
	    {
		output.write(personal_license.getBytes());
	    }
	}
	else if (personal_license_file!=null)
	{
	    FileTools.copy(personal_license_file, file);
	}
    }
    
    public static void main(String args[]) throws IOException
    {
	License l=new License(PredefinedLicense.CeCILL_v1_1);
	l.generateLicenseFile(new File("license_test.txt"));
    }
    
    
    public static enum PredefinedLicense
    {
	CeCILL_v1_1("CeCILL_License_v1.1.txt"),
	CeCILL_v2_0("CeCILL_License_v2.0.txt"),
	CeCILL_v2_1("CeCILL_License_v2.1.txt"),
	CeCILL_B_v1_0("CeCILL-B_License_v1.0.txt"),
	CeCILL_C_v1_0("CeCILL-C_License_v1.0.txt"),
	GNU_AGPL_Licence_v3("GNU_AGPL_License_v3.txt"),
	GNU_FDL_v1_1("GNU_FDL_License_v1.1.txt"),
	GNU_FDL_v1_2("GNU_FDL_License_v1.2.txt"),
	GNU_FDL_v1_3("GNU_FDL_License_v1.3.txt"),
	GNU_GPL_v1("GNU_GPL_License_v1.txt"),
	GNU_GPL_v2("GNU_GPL_License_v2.txt"),
	GNU_GPL_v3("GNU_GPL_License_v3.txt"),
	GNU_LGPL_v2_1("GNU_LGPL_License_v2.1.txt"),
	GNU_LGPL_v3_0("GNU_LGPL_License_v3.0.txt"),
	APACHE_LICENSE_V2_0("Apache_License_v2.0.txt"),
	ECLIPSE_PUBLIC_LICENSE_V1_0("Eclipse_Public_License_v1.0.txt"),
	ECLIPSE_REDISTRIBUTION_LICENSE_V1_0("Eclipse_Redistribution_License_v1.0.txt");
	
	protected final String fileName;
	
	private PredefinedLicense(String fileName)
	{
	    this.fileName=fileName;
	}
	
    }
}
