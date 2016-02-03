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
package com.distrimind.util.traceroute;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see TraceRoute
 */
class MacOSTraceRoute extends TraceRoute
{
    MacOSTraceRoute()
    {
	
    }
    
    @Override
    public List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out)
    {
	try
	{
	    ArrayList<InetAddress> res=new ArrayList<InetAddress>();
	    if (depth>0)
		++depth;
	    Process p=Runtime.getRuntime().exec("traceroute -n -I "+(depth<0?"":("-m "+depth+" "))+(time_out<0?"":("-w "+(time_out/1000)+" "))+_ia.getHostAddress());
	    
	    try(InputStreamReader isr=new InputStreamReader(p.getInputStream()))
	    {
		try(BufferedReader input =new BufferedReader(isr))
		{
		    String line=null;
		    
		    Pattern pattern=Pattern.compile("^[1-9][0-9]*");
		    while ((line = input.readLine())!=null)
		    {
			String split[]=line.split(" ");
			String first_string=null;
			int i=0;
			for (;i<split.length;i++)
			{
			    if (split[i].length()>0)
			    {
				first_string=split[i];
				break;
			    }
			}
			    
			if (split.length>3 && pattern.matcher(first_string).matches())
			{
			    String ip=null;
			    for (int j=i+1;j<split.length;j++)
			    {
				if (split[j].length()>0)
				{
				    ip=split[j];
				    break;
				}
			    }
			    try
			    {
				res.add(InetAddress.getByName(ip));
			    }
			    catch(Exception e)
			    {
				res.add(null);
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
	    return null;
	}
    }

    public static void main(String args[]) throws UnknownHostException
    {
	for (InetAddress ia : new MacOSTraceRoute().tracePath(InetAddress.getByName("www.google.fr"), -1, -1))
	    System.out.println(ia);
	for (InetAddress ia : new MacOSTraceRoute().tracePath(InetAddress.getByName("www.google.fr"), 2, 4000))
	    System.out.println(ia);
    }
    
}
