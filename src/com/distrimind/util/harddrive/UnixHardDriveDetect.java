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
	private Partition parent=null;
	private final ArrayList<Partition> childs=new ArrayList<>();
	
	Partition()
	{
	    hard_drive_identifier=HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    path="/";
	}
	Partition(File _hard_drive_identifier, File _path) throws IOException
	{
	    hard_drive_identifier=_hard_drive_identifier.getCanonicalPath();
	    path=_path.getCanonicalPath();
	}
	Partition(File _path) throws IOException
	{
	    hard_drive_identifier=HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    path=_path.getCanonicalPath();
	}
	
	boolean addPartition(Partition _partition)
	{
	    if (_partition.path.equals(path))
	    {
		hard_drive_identifier=_partition.hard_drive_identifier;
		path=_partition.path;
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
		    _partition.parent=this;
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
	public String getPath()
	{
	    return path;
	}
	public Partition getParent()
	{
	    return parent;
	}
	private String getHardDriveIdentifier(String _canonical_path)
	{
	    if (_canonical_path.startsWith(path))
	    {
		for (Partition p : childs)
		{
		    String res=p.getHardDriveIdentifier(_canonical_path);
		    if (res!=null)
			return res;
		}
		return hard_drive_identifier;
	    }
	    else
		return null;
	}
    }
    private AtomicReference<Partition> root=new AtomicReference<>();
    private AtomicReference<Long> previous_update=new AtomicReference<>();
    
    UnixHardDriveDetect()
    {
	root.set(null);
	previous_update.set(new Long(System.currentTimeMillis()));
    }
    
    

    
    abstract Partition scanPartitions();
    abstract long getTimeBeforeUpdate();
    
    @SuppressWarnings("synthetic-access")
    @Override
    public final String getHardDriveIdentifier(File _file)
    {
	try
	{
	    String f=_file.getCanonicalPath();
	    if (root.get()==null || (System.currentTimeMillis()-previous_update.get().longValue())>getTimeBeforeUpdate())
	    {
		root.set(scanPartitions());
		previous_update.set(new Long(System.currentTimeMillis()));
	    }
	    String res=root.get().getHardDriveIdentifier(f);
	    if (res==null)
		return HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    else
		return res;
	}
	catch (IOException e)
	{
	    return null;
	}
	
    }

}
