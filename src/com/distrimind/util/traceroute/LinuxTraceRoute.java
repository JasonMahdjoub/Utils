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

package com.distrimind.util.traceroute;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see TraceRoute
 */
class LinuxTraceRoute extends TraceRoute
{
    LinuxTraceRoute()
    {
	
    }
    
    @Override
    public List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out_ms)
    {
	try
	{
	    ArrayList<InetAddress> res=new ArrayList<InetAddress>();
	    
	    Process p=Runtime.getRuntime().exec("mtr --raw -c 1 "+(time_out_ms<0?"":("--timeout "+time_out_ms/1000+" "))+_ia.getHostAddress());
	    
	    try(InputStreamReader isr=new InputStreamReader(p.getInputStream()))
	    {
		try(BufferedReader input =new BufferedReader(isr))
		{
		    String line=null;
		    
		    while ((line = input.readLine())!=null)
		    {
			    if (depth<0 || res.size()<depth)
			    {
				if (line.startsWith("h "))
				{
				    try
				    {
					res.add(InetAddress.getByName(line.split(" ")[2]));
				    }
				    catch(Exception e)
				    {
					res.add(null);
				    }
				}
			    }
			    else
				break;
		    }
		    
		}
	    }
	    p.destroy();
	    return res;
	    
	}
	catch (Exception e)
	{
	    e.printStackTrace();
	    return null;
	}
    }
    
    public static void main(String args[]) throws UnknownHostException
    {
	for (InetAddress ia : new LinuxTraceRoute().tracePath(InetAddress.getByName("www.google.fr"), -1, -1))
	    System.out.println(ia);
    }
}
