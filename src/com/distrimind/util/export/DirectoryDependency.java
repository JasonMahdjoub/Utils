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
	return "<fileset dir=\""+directory.getAbsolutePath()+"\"></fileset>";
    }

}
