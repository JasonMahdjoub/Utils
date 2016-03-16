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
 * @version 1.0
 * @since Utils 1.0
 */

public class ZipSourceDependancy extends SourceDependancy
{
    /**
     * 
     */
    private static final long serialVersionUID = -5705281615082697091L;
    
    private File source_file;
    
    public ZipSourceDependancy()
    {
	
    }
    
    public ZipSourceDependancy(File _jar_file)
    {
	this(_jar_file, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex());
    }
    
    public ZipSourceDependancy(File _jar_file, String _exclude_regex, String _include_regex)
    {
	super(_exclude_regex, _include_regex);
	if (_jar_file==null)
	    throw new NullPointerException("_jar_file");
	if (!_jar_file.exists())
	    throw new IllegalArgumentException("The given file does not exists : "+_jar_file);
	source_file=_jar_file;
    }
    
    @Override
    public void copySourceToFolder(File _folder) throws IOException
    {
	FileTools.unzipFile(source_file, _folder, exclude_regex, include_regex);
    }

    public File getFile()
    {
	return source_file;
    }
    
}
