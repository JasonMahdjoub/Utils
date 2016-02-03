/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * MadKitGroup extension was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License Lesser as published by the Free
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

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;


/**
 *    
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */

class LinuxHardDriveDetect extends UnixHardDriveDetect
{
    LinuxHardDriveDetect()
    {
	
    }
    
    @Override
    Partition scanPartitions()
    {
	return scanPartitions(2);
    }
    Partition scanPartitions(int iteration)
    {
	Partition root=new Partition();
	if (iteration<=0)
	    return root;
	
	File file=new File("/proc/mounts");
	try(FileInputStream fis=new FileInputStream(file))
	{
	    try(InputStreamReader isr=new InputStreamReader(fis))
	    {
		try(BufferedReader br=new BufferedReader(isr))
		{
		    String line=br.readLine();
		    while (line!=null)
		    {
			String values[]=line.split(" ");
			if (values.length>1)
			{
			    String id=values[0];
			    if (id.startsWith("/dev/"))
			    {
				try
				{
				    id=new File(id).getCanonicalPath();
				    char last_char=id.charAt(id.length()-1);
				    while (last_char>='0' && last_char<='9')
				    {
					id=id.substring(0, id.length()-1);
					if (id.length()>0)
					{
					    last_char=id.charAt(id.length()-1);
					}
					else
					    break;
				    }
				    if (id.length()>1)
				    {
					try
					{
					    Partition p=new Partition(new File(id), new File(values[1]));
					    root.addPartition(p);
					}
					catch(Exception e)
					{
					}
				    }
				}
				catch(IOException e)
				{
				}
			    }
			    else
			    {
				try
				{
				    Partition p=new Partition(new File(values[1]));
				    root.addPartition(p);
				}
				catch(Exception e)
				{
				}
			    }
			}
			line=br.readLine();
		    }
		}
	    }
	}
	catch (FileNotFoundException e)
	{
	}
	catch (IOException e)
	{
	    return scanPartitions(--iteration);
	}
	return root;
    }

    @Override
    long getTimeBeforeUpdate()
    {
	return 10000;
    }

}
