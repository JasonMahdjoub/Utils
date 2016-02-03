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

package com.distrimind.util.harddrive;

import java.io.File;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.util.OSValidator;

/**
 * Class giving a unique hard drive identifier, considering a folder, independently from the current OS.
 *    
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public abstract class HardDriveDetect
{
    /**
     * Default hard drive identifier
     */
    public static final String DEFAULT_HARD_DRIVE_IDENTIFIER="DEFAULT_HARD_DRIVE_IDENTIFIER";
    
    HardDriveDetect()
    {
	
    }
    
    /**
     * Returns a unique hard drive identifier considering a file
     * 
     * @param _file a file contained into the hard drive
     * @return the hard drive identifier or {@link HardDriveDetect#DEFAULT_HARD_DRIVE_IDENTIFIER} if the hard drive identifier couldn't be found. 
     */
    public abstract String getHardDriveIdentifier(File _file);
    
    private static final AtomicReference<HardDriveDetect> instance=new AtomicReference<>();
    
    /**
     * 
     * @return a unique {@link HardDriveDetect} instance
     */
    public static HardDriveDetect getInstance()
    {
	if (instance.get()==null)
	{
	    synchronized(instance)
	    {
		if (instance.get()==null)
		{
		    if (OSValidator.isLinux())
			instance.set(new LinuxHardDriveDetect());
		    else if (OSValidator.isWindows())
			instance.set(new WindowsHardDriveDetect());
		    else if (OSValidator.isMac())
			instance.set(new MacOSHardDriveDetect());
		    else
			instance.set(new DefaultHardDriveDetect());
		}
	    }
	}
	return instance.get();
    }
    
    public static void main(String args[])
    {
	System.out.println(getInstance().getHardDriveIdentifier(new File(args[0])));
    }
}
