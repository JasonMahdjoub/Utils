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
import java.io.InputStreamReader;

/**
 *    
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class MacOSHardDriveDetect extends UnixHardDriveDetect
{

    @Override
    Partition scanPartitions()
    {
	Partition root=new Partition();
	try
	{
	    Process p=Runtime.getRuntime().exec("diskutil list");
	    try(InputStreamReader isr=new InputStreamReader(p.getInputStream()))
	    {
		try(BufferedReader input =new BufferedReader(isr))
		{
		    String current_drive=null;
		    String line;
		    
		    while ((line = input.readLine()) != null) {
			if (line.startsWith("/dev/"))
			{
			    if (new File(line).exists())
				current_drive=line;
			    else
				current_drive=null;
			}
			else if (current_drive!=null)
			{
			    String strings[]=line.split(" ");
			    if (strings.length>0)
			    {
				String lastString=strings[strings.length-1];
				int lastindex=lastString.lastIndexOf("s");
				String part="s";
				if (lastindex>0)
				{
				    boolean ok=true;
				    for (int i=lastindex+1;i<lastString.length();i++)
				    {
					char c=lastString.charAt(i);
					part+=c;
					if (c<'0' || c>'9')
					{
					    ok=false;
					}
				    }
				    if (ok)
				    {
					String currentPart=current_drive+part;
					Process p2=Runtime.getRuntime().exec("diskutil info "+currentPart);
					try(InputStreamReader isr2=new InputStreamReader(p2.getInputStream()))
					{
					    try(BufferedReader input2 =new BufferedReader(isr2))
					    {
						String line2;
						boolean mounted=false;
						    
						while ((line2 = input2.readLine()) != null) {
						    strings=line2.split(" ");
						    String s1=null;
						    String s2=null;
						    String s3=null;
						    for (int i=0;i<strings.length;i++)
						    {
							if (strings[i].length()!=0)
							{
							    if (s1==null)
								s1=strings[i];
							    else if (s2==null)
							    {
								s2=strings[i];
								if (!mounted)
								    break;
							    }
							    else if (s3==null)
							    {
								s3=strings[i];
								break;
							    }
							}
						    }
						    if(s2!=null)
						    {
							if(s1.startsWith("Mounted"))
							{
							    if (s2.equals("Yes"))
							    {
								mounted=true;
							    }
							    else
								break;
							}
							else if (mounted && s3!=null && s1.equals("Mount") && s2.startsWith("Point"))
							{
							    try
							    {
								File mount=new File(s3);
								if (mount.exists())
								{
								    Partition partition=new Partition(new File(current_drive), mount);
								    root.addPartition(partition);
								}
							    }
							    catch(Exception e)
							    {
							    }
							    break;
							}
						    }
						}
					    }
					}
				    }
				}
			    }
			}
		    }
		}
	    }
	    p.destroy();
	    return root;
	}
	catch(Exception e)
	{
	    return new Partition();
	}
    }

    @Override
    long getTimeBeforeUpdate()
    {
	return 30000;
    }

}
