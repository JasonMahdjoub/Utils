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
/**
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.0
 */

public class JarDependency extends ZipDependency
{

    /**
     * 
     */
    private static final long serialVersionUID = -4487382904467263330L;
    
    public JarDependency()
    {
	
    }
        
    public JarDependency(String name, Package _subpackage, License licenses [], File _jar_file_dependency)
    {
	this(name, new JarSourceDependancy(false, _jar_file_dependency, getDefaultSourceExcludeRegex(), getDefaultSourceIncludeRegex()), _subpackage,licenses, _jar_file_dependency, getDefaultBinaryExcludeRegex(), getDefaultBinaryIncludeRegex());
    }
    public JarDependency(String _name, SourceDependancy _source_code, Package _subpackage, License licenses[], File _jar_file_dependency, String _exclude_regex, String _include_regex)
    {
	super(_name, _source_code, _subpackage, licenses,_jar_file_dependency, _exclude_regex,_include_regex);
    }

}
