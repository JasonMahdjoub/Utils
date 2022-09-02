/*
Copyright or © or Copr. Jason Mahdjoub (04/02/2016)

jason.mahdjoub@distri-mind.fr

This software (Utils) is a computer program whose purpose is to give several kind of tools for developers 
(ciphers, XML readers, decentralized id generators, etc.).

This software is governed by the CeCILL-C license under French law and
abiding by the rules of distribution of free software.  You can  use, 
modify and/ or redistribute the software under the terms of the CeCILL-C
license as circulated by CEA, CNRS and INRIA at the following URL
"http://www.cecill.info". 

As a counterpart to the access to the source code and  rights to copy,
modify and redistribute granted by the license, users are provided only
with a limited warranty  and the software's author,  the holder of the
economic rights,  and the successive licensors  have only  limited
liability. 

In this respect, the user's attention is drawn to the risks associated
with loading,  using,  modifying and/or developing or reproducing the
software by the user in light of its specific status of free software,
that may mean  that it is complicated to manipulate,  and  that  also
therefore means  that it is reserved for developers  and  experienced
professionals having in-depth computer knowledge. Users are therefore
encouraged to load and test the software's suitability as regards their
requirements in conditions enabling the security of their systems and/or 
data to be ensured and,  more generally, to use and operate it in the 
same conditions as regards security. 

The fact that you are presently reading this means that you have had
knowledge of the CeCILL-C license and that you accept its terms.
 */

package com.distrimind.util;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.List;
import java.util.Set;

import com.distrimind.util.harddrive.Disk;
import com.distrimind.util.harddrive.HardDriveDetect;
import com.distrimind.util.harddrive.Partition;
import com.distrimind.util.nitools.NITools;
import com.distrimind.util.traceroute.TraceRoute;

/**
 * Gives several system functions, independently of current OS running
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 *
 */
public class SystemFunctions {
	/**
	 * Returns a partition considering a file
	 * 
	 * @param _file
	 *            a file contained into the hard drive
	 * @return the concerned partition
     * @throws IOException if a problem occur
	 */
	public static Partition getHardDrivePartition(File _file) throws IOException {
		return HardDriveDetect.getInstance().getConcernedPartition(_file);
	}

	/**
	 * Gets the detected partitions of this computer
	 * @return the detected partitions of this computer
	 * @throws IOException if a problem occur
	 */
	public static Set<Partition> getDetectedPartitions() throws IOException {
		return HardDriveDetect.getInstance().getDetectedPartitions();
	}

	/**
	 * Gets the detected disks of this computer
	 * @return the detected disks of this computer
	 * @throws IOException if a problem occur
	 */
	public static Set<Disk> getDetectedDisks() throws IOException {
		return HardDriveDetect.getInstance().getDetectedDisks();
	}


	/**
	 * Gets the speed in bytes of the given network interface
	 * 
	 * @param network_interface
	 *            the network interface to test
	 * @return the speed in byte of the given network interface or -1 if the speed
	 *         couldn't be got.
	 */
	public static long getNetworkInterfaceSpeed(NetworkInterface network_interface) {
		return NITools.getInstance().getNetworkInterfaceSpeed(network_interface);
	}

	/**
	 * Tracks the route packets taken from an IP network on their way to a given
	 * {@link InetAddress}.
	 * 
	 * @param _ia
	 *            the host name to trace
	 * @return an ordered list of {@link InetAddress} (the route packet).
	 */
	public static List<InetAddress> tracePath(InetAddress _ia) {
		return TraceRoute.getInstance().tracePath(_ia);
	}

	/**
	 * Tracks the route packets taken from an IP network on their way to a given
	 * {@link InetAddress}.
	 * 
	 * @param _ia
	 *            the host name to trace
	 * @param depth
	 *            Specifies the maximum number of hops
	 * @return an ordered list of {@link InetAddress} (the route packet).
	 */
	public static List<InetAddress> tracePath(InetAddress _ia, int depth) {
		return TraceRoute.getInstance().tracePath(_ia, depth);
	}

	/**
	 * Tracks the route packets taken from an IP network on their way to a given
	 * {@link InetAddress}.
	 * 
	 * @param _ia
	 *            the host name to trace
	 * @param depth
	 *            Specifies the maximum number of hops
	 * @param time_out_ms
	 *            Set the time (in milliseconds) to wait for a response to a probe.
	 * @return an ordered list of {@link InetAddress} (the route packet). Some
	 *         elements can be <code>null</code> references if no reply was given by
	 *         some servers.
	 */
	public static List<InetAddress> tracePath(InetAddress _ia, int depth, int time_out_ms) {
		return TraceRoute.getInstance().tracePath(_ia, depth, time_out_ms);
	}

}
