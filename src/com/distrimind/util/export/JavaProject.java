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
