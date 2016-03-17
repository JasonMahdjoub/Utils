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
public class ZipDependency extends BinaryDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = -6230684853876461834L;

    private File jar_dependency;
    
    public ZipDependency()
    {
	
    }
    
    public ZipDependency(String name, Package _subpackage, License licenses[], File jar_file_dependency)
    {
	this(name, new ZipSourceDependancy(false, jar_file_dependency, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex()),_subpackage,licenses, jar_file_dependency, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    
    public ZipDependency(String name, SourceDependancy source_code, Package _subpackage, License[] licenses, File jar_file_dependency, String _exclude_regex, String _include_regex)
    {
	super(name, source_code, _subpackage, licenses,_exclude_regex, _include_regex);
	if (jar_file_dependency==null)
	    throw new NullPointerException("jar_file_dependency");
	if (!jar_file_dependency.exists())
	    throw new IllegalArgumentException("The given file does not exists : "+jar_file_dependency);
	if (!jar_file_dependency.isFile())
	    throw new IllegalArgumentException("The given file is not a file : "+jar_file_dependency);
	jar_dependency=jar_file_dependency;
    }


    @Override
    public void copyBinToFolder(File _folder) throws IOException
    {
	FileTools.unzipFile(jar_dependency, _folder, exclude_regex, include_regex);
    }
    
    public File getFile()
    {
	return jar_dependency;
    }

    @Override
    String getClassPath()
    {
	return jar_dependency.getAbsolutePath();
    }

    @Override
    String getAntSetFile()
    {
	return "<fileset file=\""+jar_dependency.getAbsolutePath()+"\"></fileset>";
    }
    

}
