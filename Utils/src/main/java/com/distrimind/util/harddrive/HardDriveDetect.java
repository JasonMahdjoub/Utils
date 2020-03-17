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

package com.distrimind.util.harddrive;

import java.io.File;

import java.io.IOException;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.distrimind.util.OS;
import com.distrimind.util.OSVersion;


/**
 * Class giving a unique hard drive identifier, considering a folder,
 * independently from the current OS.
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public abstract class HardDriveDetect {
	/**
	 * Default hard drive identifier
	 */

	private static final AtomicReference<HardDriveDetect> instance = new AtomicReference<>();

	/**
	 * 
	 * @return a unique {@link HardDriveDetect} instance
	 */
	public static HardDriveDetect getInstance() {
		if (instance.get() == null) {
			synchronized (instance) {
				if (instance.get() == null) {
					if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.LINUX)
						instance.set(new LinuxHardDriveDetect());
					else if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.WINDOWS)
						instance.set(new WindowsHardDriveDetect());
					else if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.MAC_OS_X)
						instance.set(new MacOSHardDriveDetect());
					else if (OSVersion.getCurrentOSVersion()!=null && OSVersion.getCurrentOSVersion().getOS()==OS.ANDROID)
						instance.set(new AndroidHardDriveDetect());
					else
						instance.set(new DefaultHardDriveDetect());
				}
			}
		}
		return instance.get();
	}

	public static void main(String args[]) throws IOException {
	    for (Disk d : getInstance().getDetectedDisks())
	        System.out.println(d);
        for (Partition p : getInstance().getDetectedPartitions())
            System.out.println(p);

	}

	HardDriveDetect() {

	}

	/**
	 * Returns the concerned partition considering a file
	 * 
	 * @param _file
	 *            a file contained into the hard drive
	 * @return the concerned partition or null if the partition was not found
     * @throws IOException if a problem occurs
	 */
	public abstract Partition getConcernedPartition(File _file) throws IOException;


	abstract void scanDisksAndPartitions() throws IOException;

    private long lastUpdateUTC=Long.MIN_VALUE;
    private long delayBetweenEachUpdate=30000;

    private Set<Disk> oldDisks=new HashSet<>(), removedDisks=new HashSet<>(), addedDisks=new HashSet<>();
    private Set<Partition> oldPartitions=new HashSet<>(), removedPartitions =new HashSet<>(), addedPartitions=new HashSet<>();


	abstract Set<Disk> getDetectedDisksImpl();
	abstract Set<Partition> getDetectedPartitionsImpl();

	void update() throws IOException {
        scanDisksAndPartitions();
        Set<Disk> nd=getDetectedDisksImpl();
        addedDisks=new HashSet<>();
        removedDisks=new HashSet<>();
        for (Disk d : nd)
        {
            if (!oldDisks.contains(d)) {
                addedDisks.add(d);
                removedDisks.remove(d);
            }
        }
        for (Disk d : oldDisks)
        {
            if (!nd.contains(d)) {
                removedDisks.add(d);
                addedDisks.remove(d);
            }
        }
        Set<Partition> np=getDetectedPartitionsImpl();
        addedPartitions=new HashSet<>();
        removedPartitions =new HashSet<>();
        for (Partition p : np)
        {
            if (!oldPartitions.contains(p)) {
                addedPartitions.add(p);
                removedPartitions.remove(p);
            }
        }
        for (Partition p : oldPartitions)
        {
            if (!np.contains(p)) {
                removedPartitions.add(p);
                addedPartitions.remove(p);
            }
        }
        oldPartitions=np;
        oldDisks=nd;
    }

	void updateIfNecessary() throws IOException {
        if (lastUpdateUTC+delayBetweenEachUpdate<System.currentTimeMillis()) {

            update();
            lastUpdateUTC=System.currentTimeMillis();
        }
    }


    public Set<Disk> getDetectedDisks() throws IOException {
        synchronized(this) {
            updateIfNecessary();
            return getDetectedDisksImpl();
        }
    }

    public Set<Partition> getDetectedPartitions() throws IOException {
        synchronized(this) {
            updateIfNecessary();
            return getDetectedPartitionsImpl();
        }
    }

    public long getDelayBetweenEachUpdate() {
        return delayBetweenEachUpdate;
    }

    public void setDelayBetweenEachUpdate(long delayBetweenEachUpdate) {
        this.delayBetweenEachUpdate = delayBetweenEachUpdate;
    }

    public Set<Partition> getNewDetectedPartitions()
    {
        synchronized(this) {
            Set<Partition> res = addedPartitions;
            addedPartitions = null;
            return res;
        }
    }
    public Set<Partition> getNewRemovedPartitions()
    {
        synchronized(this) {
            Set<Partition> res = removedPartitions;
            removedPartitions = null;
            return res;
        }
    }

    public Set<Disk> getNewDetectedDisks()
    {
        synchronized(this) {
            Set<Disk> res = addedDisks;
            addedDisks = null;
            return res;
        }
    }
    public Set<Disk> getNewRemovedDisks()
    {
        synchronized(this) {
            Set<Disk> res = removedDisks;
            removedDisks = null;
            return res;
        }
    }


}
