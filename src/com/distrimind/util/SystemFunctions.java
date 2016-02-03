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

package com.distrimind.util;

import java.io.File;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.List;

import com.distrimind.util.harddrive.HardDriveDetect;
import com.distrimind.util.nitools.NITools;
import com.distrimind.util.traceroute.TraceRoute;

/**
 * Gives several system functions, independently from current OS running 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 *
 */
public class SystemFunctions
{
    /**
     * Returns a unique hard drive identifier considering a file
     * 
     * @param _file a file contained into the hard drive
     * @return the hard drive identifier or {@link HardDriveDetect#DEFAULT_HARD_DRIVE_IDENTIFIER} if the hard drive identifier couldn't be found. 
     */
    public static String getHardDriveIdentifier(File _file)
    {
	return HardDriveDetect.getInstance().getHardDriveIdentifier(_file);
    }
    
    /**
     * Tracks the route packets taken from an IP network on their way to a given {@link InetAddress}.
     *  
     * @param _ia the host name to trace
     * @return a ordered list of {@link InetAddress} (the route packet).
     */
    public static List<InetAddress> tracePath(InetAddress _ia)
    {
	return TraceRoute.getInstance().tracePath(_ia);
    }

    /**
     * Tracks the route packets taken from an IP network on their way to a given {@link InetAddress}.
     *  
     * @param _ia the host name to trace
     * @param depth Specifies the maximum number of hops 
     * @return a ordered list of {@link InetAddress} (the route packet).
     */
    public static List<InetAddress> tracePath(InetAddress _ia, int depth)
    {
	return TraceRoute.getInstance().tracePath(_ia, depth);
    }

    /**
     * Tracks the route packets taken from an IP network on their way to a given {@link InetAddress}.
     *  
     * @param _ia the host name to trace
     * @param depth Specifies the maximum number of hops 
     * @param time_out_ms Set the time (in milliseconds) to wait for a response to a probe. 
     * @return a ordered list of {@link InetAddress} (the route packet). Some elements can be <code>null</code> references if no reply was given by some servers.
     */
    public static List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out_ms)
    {
	return TraceRoute.getInstance().tracePath(_ia, depth, time_out_ms);
    }
    
    /**
     * Gets the speed in bytes of the given network interface 
     * @param network_interface
     * @return the speed in byte of the given network interface or -1 if the speed couldn't be got.
     */
    public static long getNetworkInterfaceSpeed(NetworkInterface network_interface)
    {
	return NITools.getInstance().getNetworkInterfaceSpeed(network_interface);
    }
    

}
