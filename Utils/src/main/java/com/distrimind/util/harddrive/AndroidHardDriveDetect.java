package com.distrimind.util.harddrive;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import com.distrimind.util.OS;
import com.distrimind.util.OSVersion;

import java.io.*;
import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.*;

/**
 * @author Jason
 * @version 1.0
 * @since Utils 4.14.8
 */
public class AndroidHardDriveDetect extends UnixHardDriveDetect{
	private Set<Partition> partitions=new HashSet<>();
	private Set<Disk> disks=new HashSet<>();
	AndroidHardDriveDetect()
	{

	}

	@Override
	void scanDisksAndPartitions(){

		try
		{
			Disk disk=new Disk(null, 0, true, 0, "Unknown", "Root", "Root");
			disks.add(disk);
			partitions.add(new Partition(null, new File("/"), null, "Unknown", "Unknown", -1, false, "Root", 0, disk));
			File internalStorageVolume = (File)getFilesDir.invoke(context);
			{
				Object stat=constStatFs.newInstance(internalStorageVolume.getPath());
				int blockSize=(int)(long)getBlockSizeLong.invoke(stat);
				disk = new Disk(null, (long) getTotalBytes.invoke(stat), true, blockSize, "Unknown", "InternalStorage", "Internal storage");
				disks.add(disk);
				partitions.add(new Partition(null, internalStorageVolume, null,
						"Unknown", "Unknown", blockSize,
						internalStorageVolume.canWrite(),
						"Internal SD card", (long) getAvailableBytes.invoke(stat), disk));
			}

			File[] externalStorageVolumes =(File[])getExternalFilesDirs.invoke(null, context, null);
			int index=2;
			for (File f : externalStorageVolumes) {
				boolean removable=(boolean)isExternalStorageRemovable.invoke(null, f);
				if (removable && ((String)getExternalStorageState.invoke(null, f)).toLowerCase().equals("mounted"))
				{
					Object stat=constStatFs.newInstance(f.getPath());
					int blockSize=(int)(long)getBlockSizeLong.invoke(stat);
					disk=new Disk(null, (long)getTotalBytes.invoke(stat ), false, blockSize, "Unknown", "ExternalStorage"+index, "External storage "+index);
					partitions.add(new Partition(null, f, null,
							"Unknown", "Unknown", blockSize,
							f.canWrite(),
							"Internal SD card "+index, (long)getAvailableBytes.invoke(stat), disk));
					++index;
				}
			}



		} catch (InvocationTargetException | IllegalAccessException | InstantiationException ex) {
			ex.printStackTrace();
		}
	}

	@Override
	Set<Disk> getDetectedDisksImpl() {
		return disks;
	}

	@Override
	Set<Partition> getDetectedPartitionsImpl() {

		return partitions;
	}

	public static Object context=null;

	private final static Method isExternalStorageRemovable;
	private final static Method getExternalStorageState;
	private final static Method getFilesDir;
	private final static Method getExternalFilesDirs;
	private final static Method getBlockSizeLong;
	private final static Method getAvailableBytes;
	private final static Method getTotalBytes;
	private final static Constructor<?> constStatFs;
	static
	{
		Class<?> tenvironmentClass;
		Class<?> ContextClass;
		Class<?> ContextCompatClass;
		Class<?> StatFsClass;
		Method tisExternalStorageRemovable=null;
		Method tgetExternalStorageState=null;
		Method tgetFilesDir=null;
		Method tgetExternalFilesDirs=null;
		Method tgetBlockSizeLong=null;
		Method tgetAvailableBytes=null;
		Method tgetTotalBytes=null;
		Constructor<?> tconstStatFs=null;
		if (OSVersion.getCurrentOSVersion().getOS()== OS.ANDROID)
		{
			try {
				tenvironmentClass=Class.forName("android.os.Environment");
				ContextClass=Class.forName("android.content.Context");
				ContextCompatClass=Class.forName("androidx.core.content.ContextCompat");
				StatFsClass=Class.forName("android.os.StatFs");
				tconstStatFs=StatFsClass.getDeclaredConstructor(String.class);
				tisExternalStorageRemovable=tenvironmentClass.getDeclaredMethod("isExternalStorageRemovable", File.class);
				tgetExternalStorageState=tenvironmentClass.getDeclaredMethod("getExternalStorageState" , File.class);
				tgetFilesDir=ContextClass.getDeclaredMethod("getFilesDir" );
				tgetExternalFilesDirs=ContextCompatClass.getDeclaredMethod("getExternalFilesDirs", ContextClass, String.class );
				tgetBlockSizeLong=StatFsClass.getDeclaredMethod("getBlockSizeLong");
				tgetAvailableBytes=StatFsClass.getDeclaredMethod("getAvailableBytes");
				tgetTotalBytes=StatFsClass.getDeclaredMethod("getTotalBytes");

			} catch (ClassNotFoundException | NoSuchMethodException e) {
				e.printStackTrace();
				System.exit(-1);
			}
		}
		isExternalStorageRemovable=tisExternalStorageRemovable;
		getExternalStorageState=tgetExternalStorageState;
		getFilesDir=tgetFilesDir;
		getExternalFilesDirs=tgetExternalFilesDirs;
		getBlockSizeLong=tgetBlockSizeLong;
		getAvailableBytes=tgetAvailableBytes;
		getTotalBytes=tgetTotalBytes;
		constStatFs=tconstStatFs;
	}
}
