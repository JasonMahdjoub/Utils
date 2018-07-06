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
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
abstract class UnixHardDriveDetect extends HardDriveDetect {

	private static class UnixPartition {
		private Partition partition;

		private UnixPartition parent = null;

		private final ArrayList<UnixPartition> childs = new ArrayList<>();

		UnixPartition(Partition partition) {
			this.partition=partition;
		}

		boolean addPartition(UnixPartition _partition) {
			if (_partition.partition.equals(partition)) {
				return true;
			} else {
				if (_partition.partition.getMountPointOrLetter().getAbsolutePath().startsWith(partition.getMountPointOrLetter().getAbsolutePath())) {
					for (UnixPartition hd : childs) {
						if (hd.addPartition(_partition))
							return true;
					}
					childs.add(_partition);
					_partition.parent = this;
					return true;
				} else {
					return false;
				}
			}
		}


		private Partition getHardDriveIdentifier(String _canonical_path) {
			if (_canonical_path.startsWith(partition.getMountPointOrLetter().getAbsolutePath())) {
				for (UnixPartition p : childs) {
                    Partition res = p.getHardDriveIdentifier(_canonical_path);
					if (res != null)
						return res;
				}
				return partition;
			} else
				return null;
		}

		public UnixPartition getParent() {
			return parent;
		}


	}

	private volatile UnixPartition root;

	UnixHardDriveDetect() {
		root=null;
	}

    public Partition getConcernedPartition(File _file) throws IOException {
        synchronized (this)
        {
            updateIfNecessary();
            if (root!=null)
                return root.getHardDriveIdentifier(_file.getCanonicalPath());
            return null;
        }
    }

	@Override
    void update() throws IOException {
        super.update();
        for (Partition p : getDetectedPartitions()) {
            if (p.getMountPointOrLetter().getAbsolutePath().equals("/")) {
                root = new UnixPartition(p);
                break;
            }
        }
        for (Partition p : getDetectedPartitions()) {
            root.addPartition(new UnixPartition(p));
        }
    }





}
