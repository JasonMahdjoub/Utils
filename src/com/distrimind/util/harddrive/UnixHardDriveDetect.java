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
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
abstract class UnixHardDriveDetect extends HardDriveDetect
{

    static class Partition
    {
	private String hard_drive_identifier;

	private String path;

	private Partition parent = null;

	private final ArrayList<Partition> childs = new ArrayList<>();

	Partition()
	{
	    hard_drive_identifier = HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    path = "/";
	}

	Partition(File _path) throws IOException
	{
	    hard_drive_identifier = HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    path = _path.getCanonicalPath();
	}

	Partition(File _hard_drive_identifier, File _path) throws IOException
	{
	    hard_drive_identifier = _hard_drive_identifier.getCanonicalPath();
	    path = _path.getCanonicalPath();
	}

	boolean addPartition(Partition _partition)
	{
	    if (_partition.path.equals(path))
	    {
		hard_drive_identifier = _partition.hard_drive_identifier;
		path = _partition.path;
		return true;
	    }
	    else
	    {
		if (_partition.path.startsWith(path))
		{
		    for (Partition hd : childs)
		    {
			if (hd.addPartition(_partition))
			    return true;
		    }
		    childs.add(_partition);
		    _partition.parent = this;
		    return true;
		}
		else
		{
		    return false;
		}
	    }
	}

	public String getHardDriveIdentifier()
	{
	    return hard_drive_identifier;
	}

	private String getHardDriveIdentifier(String _canonical_path)
	{
	    if (_canonical_path.startsWith(path))
	    {
		for (Partition p : childs)
		{
		    String res = p.getHardDriveIdentifier(_canonical_path);
		    if (res != null)
			return res;
		}
		return hard_drive_identifier;
	    }
	    else
		return null;
	}

	public Partition getParent()
	{
	    return parent;
	}

	public String getPath()
	{
	    return path;
	}
    }

    private AtomicReference<Partition> root = new AtomicReference<>();

    private AtomicReference<Long> previous_update = new AtomicReference<>();

    UnixHardDriveDetect()
    {
	root.set(null);
	previous_update.set(new Long(System.currentTimeMillis()));
    }

    @SuppressWarnings("synthetic-access")
    @Override
    public final String getHardDriveIdentifier(File _file)
    {
	try
	{
	    String f = _file.getCanonicalPath();
	    if (root.get() == null
		    || (System.currentTimeMillis() - previous_update.get()
			    .longValue()) > getTimeBeforeUpdate())
	    {
		root.set(scanPartitions());
		previous_update.set(new Long(System.currentTimeMillis()));
	    }
	    String res = root.get().getHardDriveIdentifier(f);
	    if (res == null)
		return HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    else
		return res;
	}
	catch (IOException e)
	{
	    return null;
	}

    }

    abstract long getTimeBeforeUpdate();

    abstract Partition scanPartitions();

}
