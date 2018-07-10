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
import java.io.File;
import java.io.IOException;
import java.util.HashSet;
import java.util.Set;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class DefaultHardDriveDetect extends HardDriveDetect {

	Set<Disk> disks;
	Set<Partition> partitions;
	DefaultHardDriveDetect() {

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

	@Override
	void scanDisksAndPartitions()  {
        disks=new HashSet<>();
        partitions=new HashSet<>();
		FileSystemView fileSystemView=FileSystemView.getFileSystemView();
		for (File f : File.listRoots())
		{
			Partition p=new Partition(null, f, f.getAbsolutePath(), fileSystemView.getSystemTypeDescription(f),
					fileSystemView.getSystemTypeDescription(f), -1, f.canWrite(), fileSystemView.getSystemTypeDescription(f), f.getTotalSpace(),
					new Disk(null, f.getTotalSpace(), true, -1, fileSystemView.getSystemTypeDescription(f), f.getAbsolutePath(), fileSystemView.getSystemDisplayName(f)));
			disks.add(p.getDisk());
			partitions.add(p);
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


}
