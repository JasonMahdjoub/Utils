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

package com.distrimind.util.nitools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.NetworkInterface;

import com.distrimind.util.OSValidator;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0 
 *
 */
class WindowsNITools extends NITools
{
    WindowsNITools()
    {
	
    }
    
    
    @Override
    public long getNetworkInterfaceSpeed(NetworkInterface _network_interface)
    {
	try
	{
	    if (_network_interface.isLoopback())
		return -1;
	    Process p=null;
	    //TODO check compatibility with Vista and Seven
	    if (OSValidator.getOSVersion().toLowerCase().contains("vista"))
		p=Runtime.getRuntime().exec("wmic NIC where \"NetEnabled=true\" get \"InterfaceIndex,Speed\"");
	    else
		p=Runtime.getRuntime().exec("wmic NIC where NetEnabled=true get InterfaceIndex,Speed");
	    
	    long res=-1;
	    try(InputStreamReader isr=new InputStreamReader(p.getInputStream()))
	    {
		try(BufferedReader input =new BufferedReader(isr))
		{
		    String line = null;
		    boolean first=true;
		    while (res==-1 && (line = input.readLine())!=null)
		    {
			if (first)
			{
			    first=false;
			    continue;
			}
			
			String split[]=line.split(" ");
			String index=null;
			int i=0;
			for (;i<split.length-1;i++)
			{
			    if (split[i].length()>0)
			    {
				index=split[i];
				break;
			    }
			}
			if (index!=null)
			{
			    try
			    {
				if (Integer.parseInt(split[0])==_network_interface.getIndex())
				{
				    for (int j=split.length-1;j>i;j--)
				    {
					if (split[j].length()!=0)
					{
					    res=readLong(split[j]);
					    break;
					}
				    }
				}
			    }
			    catch(Exception e)
			    {
				
			    }
			}
		    }
		}
	    }
	    p.destroy();
	    return res;
	}
	catch (Exception e)
	{
	    e.printStackTrace();
	    return -1;
	}
    }
    
    

}
