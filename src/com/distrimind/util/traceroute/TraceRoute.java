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

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.util.OSValidator;


/**
 * Class that enables a trace route considering an {@link InetAddress}, independently from current OS running. 
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MadKitLanEdition 1.0
 * 
 */
public abstract class TraceRoute
{

    TraceRoute()
    {
	
    }
    
    /**
     * Tracks the route packets taken from an IP network on their way to a given {@link InetAddress}.
     *  
     * @param _ia the host name to trace
     * @return a ordered list of {@link InetAddress} (the route packet).
     */
    public List<InetAddress> tracePath(InetAddress _ia)
    {
	return this.tracePath(_ia, -1, -1);
    }

    /**
     * Tracks the route packets taken from an IP network on their way to a given {@link InetAddress}.
     *  
     * @param _ia the host name to trace
     * @param depth Specifies the maximum number of hops 
     * @return a ordered list of {@link InetAddress} (the route packet).
     */
    public List<InetAddress> tracePath(InetAddress _ia, int depth)
    {
	return this.tracePath(_ia, depth, -1);
    }

    /**
     * Tracks the route packets taken from an IP network on their way to a given {@link InetAddress}.
     *  
     * @param _ia the host name to trace
     * @param depth Specifies the maximum number of hops 
     * @param time_out_ms Set the time (in milliseconds) to wait for a response to a probe. 
     * @return a ordered list of {@link InetAddress} (the route packet). Some elements can be <code>null</code> references if no reply was given by some servers.
     */
    public abstract List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out_ms);
    
    
    
    
    private static final AtomicReference<TraceRoute> instance=new AtomicReference<>();
    
    /**
     * 
     * @return a unique instance of TraceRoute
     */
    public static TraceRoute getInstance()
    {
	if (instance.get()==null)
	{
	    synchronized(instance)
	    {
		if (instance.get()==null)
		{
		    if (OSValidator.isLinux())
			instance.set(new LinuxTraceRoute());
		    else if (OSValidator.isWindows())
			instance.set(new WindowsTraceRoute());
		    else if (OSValidator.isMac())
			instance.set(new MacOSTraceRoute());
		    else
			instance.set(new DefaultTraceRoute());
		}
	    }
	}
	return instance.get();
    }
 
    public static void main(String args[]) throws UnknownHostException
    {
	for (InetAddress ia : getInstance().tracePath(InetAddress.getByName("192.168.0.14"), -1, -1))
	    System.out.println(ia);
	
    }
    
}
