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

import com.distrimind.util.FileTools;
/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */

public class DirectoryDependency extends BinaryDependency
{
    /**
     * 
     */
    private static final long serialVersionUID = 7990469461822747800L;
    
    private File directory;
    
    public DirectoryDependency()
    {
	
    }
    
    public DirectoryDependency(String _name, SourceDependancy _source_code, Package _subpackage, License[] _licenses, File directory)
    {
	this(_name, _source_code, _subpackage, _licenses, directory, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    public DirectoryDependency(String _name, SourceDependancy _source_code, Package _subpackage, License[] _licenses, File directory, String _exclude_regex, String _include_regex)
    {
	super(_name, _source_code, _subpackage, _licenses, _exclude_regex,
		_include_regex);
	if (directory==null)
	    throw new NullPointerException("directory");
	if (!directory.exists())
	    throw new IllegalArgumentException("The directory "+directory+" does not exists !");
	if (!directory.isDirectory())
	    throw new IllegalArgumentException("The directory "+directory+" is not a directory !");
	    
	this.directory=directory;
	
    }

    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.copyFolderToFolder(directory, _folder, false);
	
    }
    @Override
    String getClassPath()
    {
	return directory.getAbsolutePath();
    }
    @Override
    String getAntSetFile()
    {
	return "<fileset dir=\""+directory.getAbsolutePath()+"\" includes=\"**/*.class\"></fileset>";
    }

}
