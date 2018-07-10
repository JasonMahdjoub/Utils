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

import javax.swing.filechooser.FileSystemView;
import java.io.*;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class WindowsHardDriveDetect extends HardDriveDetect {

	private HashSet<Disk> disks;
	private HashSet<Partition> partitions;




	@Override
	Set<Disk> getDetectedDisksImpl() {
		return disks;
	}

	@Override
	Set<Partition> getDetectedPartitionsImpl() {
		return partitions;
	}

	@Override
	void scanDisksAndPartitions() throws IOException {
        //FileSystemView fsv=FileSystemView.getFileSystemView();
        disks=new HashSet<>();
        partitions=new HashSet<>();
        HashMap<String, Disk> disksMap=new HashMap<>();
        HashMap<String, Partition> partitionsMap=new HashMap<>();
        File sfile=getScriptFile();
        Process p = Runtime.getRuntime().exec("cscript //NoLogo " + sfile.getPath());
        try (InputStreamReader isr = new InputStreamReader(p.getInputStream())) {
            try (BufferedReader input = new BufferedReader(isr)) {
                String line;
                while ((line = input.readLine()) != null) {
                    String tab[]=line.split(" ");
                    if (tab.length==11)
                    {
                        String driveLetter=tab[0];
                        int li=driveLetter.lastIndexOf(":");
                        if (li<0)
                            li=driveLetter.length();
                        String deviceID=driveLetter.substring(0, li);
                        if (deviceID.equals("_"))
                            continue;
                        String name=tab[1];
                        if (name.equals("_"))
                            name=null;
                        String fileSystem=tab[2];
                        if (fileSystem.equals("_"))
                            fileSystem=null;
                        long volumeSize=-1;
                        try
                        {
                            volumeSize=Long.valueOf(tab[3]);
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                        }

                        int volumeBlockSize=-1;
                        try
                        {
                            volumeBlockSize=Integer.valueOf(tab[5]);
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                        }
                        String caption=tab[6];
                        if (caption.equals("_"))
                            caption=null;
                        String diskID=tab[7];
                        if (diskID.equals("_"))
                            diskID=null;
                        long diskSize=-1;
                        try
                        {
                            diskSize=Long.valueOf(tab[8]);
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                        }
                        String interfaceType=tab[9];
                        if (interfaceType.equals("_"))
                            interfaceType=null;

                        String serialNumber=tab[10];
                        if (serialNumber.equals("_"))
                            serialNumber=null;
                        Disk disk=disksMap.get(diskID);
                        if (disk==null)
                        {
                            disk=new Disk(UUID.nameUUIDFromBytes(serialNumber.getBytes()), diskSize, true, -1, interfaceType, diskID, caption);
                            disksMap.put(diskID, disk);
                            disks.add(disk);
                        }
                        Partition partition=new Partition(null, new File(driveLetter), deviceID, fileSystem, fileSystem, volumeBlockSize, new File(driveLetter).canWrite(), name, volumeSize, disk);
                        partitions.add(partition);
                        partitionsMap.put(deviceID, partition);

                    } else if (tab.length==8)
                    {
                        int li=tab[0].lastIndexOf(":");
                        if (li<0)
                            li=tab[0].length();
                        String deviceID=tab[0].substring(0, li);
                        String driveLetter=deviceID+":";
                        String serialNumber=tab[1];
                        if (serialNumber.equals("_"))
                            serialNumber=null;
                        String fileSystem=tab[3];
                        if (fileSystem.equals("_"))
                            fileSystem=null;
                        long volumeSize=-1;
                        try
                        {
                            volumeSize=Long.valueOf(tab[4]);
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                        }
                        long freeSpace=-1;
                        try
                        {
                            freeSpace=Long.valueOf(tab[5]);
                        }
                        catch (Exception e)
                        {
                            e.printStackTrace();
                        }
                        boolean isReady=tab[6].equals("1");
                        String volumeName=tab[7];
                        if (volumeName.equals("_"))
                            volumeName=null;
                        Partition partition=partitionsMap.get(deviceID);
                        if (partition!=null)
                            continue;
                        Disk disk=new Disk(UUID.nameUUIDFromBytes(serialNumber.getBytes()), volumeSize,false, -1, null, deviceID, volumeName);
                        disksMap.put(deviceID, disk);
                        disks.add(disk);
                        partition=new Partition(null, new File(driveLetter), deviceID, fileSystem, fileSystem, -1, new File(driveLetter).canWrite(), volumeName, volumeSize, disk);
                        partitions.add(partition);
                        partitionsMap.put(deviceID, partition);



                    }

                }
            }
        }
        p.destroy();
	}
    private File scriptFile=null;
    private File getScriptFile() throws IOException {

        if (scriptFile.exists())
            return scriptFile;
        scriptFile = File.createTempFile("comdistriminddiskinfo", ".vbs");
        scriptFile.deleteOnExit();
        try (FileWriter fw = new java.io.FileWriter(scriptFile)) {
            StringBuffer sb=new StringBuffer();
            try(BufferedReader br=new BufferedReader(new InputStreamReader(WindowsHardDriveDetect.class.getResourceAsStream("diskinfo.vbs"))))
            {
                String line;
                while ((line=br.readLine())!=null)
                {
                    sb.append(line);
                    sb.append("\n");
                }
            }
            fw.write(sb.toString());

        }
        return scriptFile;


    }

	@Override
	public Partition getConcernedPartition(File _file) throws IOException {
        synchronized (this) {
            updateIfNecessary();
            String path = _file.getCanonicalPath();
            for (Partition p : partitions)
                if (path.startsWith(p.getMountPointOrLetter().getAbsolutePath()))
                    return p;
            return null;
        }
	}


}
