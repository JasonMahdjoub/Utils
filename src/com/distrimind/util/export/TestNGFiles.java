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
import java.util.ArrayList;
import java.util.Collection;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.6
 */

public class TestNGFiles extends AbstractUnitTests
{
    /**
     * 
     */
    private static final long serialVersionUID = 83704142776151122L;
    
    
    private ArrayList<TestNGFile> tests;
    
    public TestNGFiles()
    {
	
    }
    
    
    public TestNGFiles(Collection<TestNGFile> tests)
    {
	this.tests=new ArrayList<>();
	this.tests.addAll(tests);
    }


    @Override
    public boolean executeTestsFromJarFile(File _jarFile) throws Exception
    {
	for (TestNGFile t : tests)
	{
	    if (!t.executeTestsFromJarFile(_jarFile))
		return false;
	}
	return true;
    }

    @Override
    public boolean executeTestsFromSystemClassLoader() throws Exception
    {
	for (TestNGFile t : tests)
	{
	    if (!t.executeTestsFromSystemClassLoader())
		return false;
	}
	return true;
    }
    
    
}
