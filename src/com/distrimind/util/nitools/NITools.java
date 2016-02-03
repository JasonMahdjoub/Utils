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
package com.distrimind.util.nitools;

import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.util.OSValidator;

/**
 * Class that gives tools for network interfaces, independently from current OS running.
 *     
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * 
 */
public abstract class NITools
{
    NITools()
    {
	
    }
    /**
     * Gets the speed in bytes of the given network interface 
     * @param network_interface
     * @return the speed in byte of the given network interface or -1 if the speed couldn't be got.
     */
    public abstract long getNetworkInterfaceSpeed(NetworkInterface network_interface);
    
    
    private static final AtomicReference<NITools> instance=new AtomicReference<>();
    
    /**
     * 
     * @return a unique instance of TraceRoute
     */
    public static NITools getInstance()
    {
	if (instance.get()==null)
	{
	    synchronized(instance)
	    {
		if (instance.get()==null)
		{
		    if (OSValidator.isLinux())
			instance.set(new LinuxNITools());
		    else if (OSValidator.isWindows() && !OSValidator.getOSVersion().toLowerCase().contains("windows xp"))
			instance.set(new WindowsNITools());//TODO see for Windows XP compatibility
		    else if (OSValidator.isMac())
			instance.set(new MacOSXNITools());
		    else
			instance.set(new DefaultNITools());
		}
	    }
	}
	return instance.get();
    }
    
    
    long readLong(String value)
    {
	if (value.toLowerCase().endsWith("kb/s"))
	{
	    return Long.parseLong(value.substring(0, value.length()-4))*1000L;
	}
	else if (value.toLowerCase().endsWith("mb/s"))
	{
	    return Long.parseLong(value.substring(0, value.length()-4))*1000000L;
	}
	else if(value.toLowerCase().endsWith("gb/s"))
	{
	    return Long.parseLong(value.substring(0, value.length()-4))*1000000000L;
	}
	else if(value.toLowerCase().endsWith("tb/s"))
	{
	    return Long.parseLong(value.substring(0, value.length()-4))*1000000000000L;
	}
	else
	    return Long.parseLong(value);
    }
    
    public static void main(String args[]) throws SocketException
    {
	Enumeration<NetworkInterface> e=NetworkInterface.getNetworkInterfaces();
	while (e.hasMoreElements())
	{
	    NetworkInterface ni=e.nextElement();
	    System.out.print(ni.getName()+" : ");
	    System.out.println(getInstance().getNetworkInterfaceSpeed(ni));	    
	}
	
    }
    
}
