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
import java.util.ArrayList;

import com.distrimind.util.FileTools;
import com.distrimind.util.version.Version;
/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */

public class JavaProject extends BinaryDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = 4690281901500998165L;

    private File binaries_directory;
    
    public JavaProject()
    {
	
    }
    
    public JavaProject(File binaries_directory, JavaProjectSource source)
    {
	this(binaries_directory, source, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    public JavaProject(File binaries_directory, JavaProjectSource source, String _exclude_regex, String _include_regex)
    {
	super(source.getProjectName(), source, source.getRepresentedPackage(), source.getLicenses(),_exclude_regex, _include_regex);

	if (binaries_directory==null)
	    throw new NullPointerException("source_directory");
	if (!binaries_directory.exists())
	    throw new IllegalArgumentException(binaries_directory.toString()+" does not exists !");
	if (!binaries_directory.isDirectory())
	    throw new IllegalArgumentException(binaries_directory.toString()+" is not a directory !");
	this.binaries_directory=binaries_directory;
	File f=new File(binaries_directory, source.getRelativeBuildFile());
	if (!f.exists())
	    throw new IllegalArgumentException("The build file "+f.toString()+" does not exists !");
	if (!f.isFile())
	    throw new IllegalArgumentException("The build file "+f.toString()+" is not a file !");
	
    }

    
    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.copyFolderToFolder(binaries_directory, _folder, false, this.exclude_regex, this.include_regex);
	
    }
    
    public File getBinariesDirectory()
    {
	return binaries_directory;
    }
    
    public Class<?> getMainClass()
    {
	return ((JavaProjectSource)getSourceCode()).getMainClass();
    }
    public String getDescription()
    {
	return ((JavaProjectSource)getSourceCode()).getDescription();
    }
    
    public Version getVersion()
    {
	return ((JavaProjectSource)getSourceCode()).getVersion();
    }
    
    public ArrayList<BinaryDependency> getDependencies()
    {
	return ((JavaProjectSource)getSourceCode()).getDependencies();
    }

    public ArrayList<File> getAdditionalFilesAndDirectoriesToExport()
    {
	return ((JavaProjectSource)getSourceCode()).getAdditionalFilesAndDirectoriesToExport();
    }
    @Override
    public String getClassPath()
    {
	return ((JavaProjectSource)getSourceCode()).getClassPath();
    }
    
    @Override
    public void exportLicences(File directory_destination) throws IOException
    {
	BinaryDependency.exportLicences(((JavaProjectSource)getSourceCode()).getProjectName(), getLicenses(), directory_destination, true);
    }
    @Override
    String getAntSetFile()
    {
	//return ((JavaProjectSource)getSourceCode()).getAntSetFile();
	return "<fileset dir=\""+this.binaries_directory.getAbsolutePath()+"\"></fileset>";
    }
    
}
