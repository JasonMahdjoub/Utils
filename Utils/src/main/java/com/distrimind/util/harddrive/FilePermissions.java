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

import com.distrimind.util.OSVersion;
import com.distrimind.util.io.*;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

/**
 *
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 4.9.0
 *
 */
public class FilePermissions implements SecureExternalizable {

	private final Set<PosixFilePermission> permissions=new HashSet<>();
	private Short code=null;

	public FilePermissions(PosixFilePermission ...posixFilePermissions) {
		Collections.addAll(permissions, posixFilePermissions);
	}

	public FilePermissions(Collection<PosixFilePermission> posixFilePermissions) {
		permissions.addAll(posixFilePermissions);
	}

	private FilePermissions() {
	}

	public Set<PosixFilePermission> getPermissions() {
		return Collections.unmodifiableSet(permissions);
	}

	public boolean addPermission(PosixFilePermission p)
	{
		if (permissions.add(p)) {
			code = null;
			return true;
		}
		else
			return false;
	}

	public boolean removePermission(PosixFilePermission p)
	{
		if (permissions.remove(p)) {
			code = null;
			return true;
		}
		else
			return false;
	}
	public boolean addPermissions(PosixFilePermission ...permissions)
	{
		if (Collections.addAll(this.permissions, permissions)) {
			code = null;
			return true;
		}
		else
			return false;
	}
	public boolean addPermissions(Collection<PosixFilePermission> permissions)
	{
		if (this.permissions.addAll(permissions)) {
			code = null;
			return true;
		}
		else
			return false;
	}

	@Override
	public boolean equals(Object o) {
		if (this == o) return true;
		if (o == null || getClass() != o.getClass()) return false;
		FilePermissions that = (FilePermissions) o;
		return hashCode()==that.hashCode();
	}

	@Override
	public String toString()
	{
		return PosixFilePermissions.toString(permissions);
	}

	public static FilePermissions from(String permissions)
	{
		return new FilePermissions(PosixFilePermissions.fromString(permissions));
	}

	public static FilePermissions from(PosixFilePermission ...posixFilePermissions)
	{
		return new FilePermissions(posixFilePermissions);
	}

	public static FilePermissions from(Collection<PosixFilePermission> posixFilePermissions)
	{
		return new FilePermissions(posixFilePermissions);
	}

	public boolean containsPermission(PosixFilePermission p)
	{
		return permissions.contains(p);
	}


	private void readCode()
	{
		if ((code & 256)==256)
			permissions.add(PosixFilePermission.OWNER_READ);
		if ((code & 128)==128)
			permissions.add(PosixFilePermission.OWNER_WRITE);
		if ((code & 64)==64)
			permissions.add(PosixFilePermission.OWNER_EXECUTE);
		if ((code & 32)==32)
			permissions.add(PosixFilePermission.GROUP_READ);
		if ((code & 16)==16)
			permissions.add(PosixFilePermission.GROUP_WRITE);
		if ((code & 8)==8)
			permissions.add(PosixFilePermission.GROUP_EXECUTE);
		if ((code & 4)==4)
			permissions.add(PosixFilePermission.OTHERS_READ);
		if ((code & 2)==2)
			permissions.add(PosixFilePermission.OTHERS_WRITE);
		if ((code & 1)==1)
			permissions.add(PosixFilePermission.OTHERS_EXECUTE);
	}

	public static FilePermissions from(short code)
	{
		if (code<0 || code>511)
			throw new IllegalArgumentException();
		FilePermissions res=new FilePermissions();
		res.code=code;
		res.readCode();
		return res;
	}

	public void applyTo(File file) throws IOException {
		if (OSVersion.getCurrentOSVersion().getOS().isUnix())
			applyTo(file.toPath());
		if (!file.setReadable(containsPermission(PosixFilePermission.OWNER_READ)))
			throw new SecurityException();
		if (!file.setReadable(containsPermission(PosixFilePermission.OWNER_WRITE)))
			throw new SecurityException();
		if (!file.setReadable(containsPermission(PosixFilePermission.OWNER_EXECUTE)))
			throw new SecurityException();

	}

	public void applyTo(Path path) throws IOException {
		if (!OSVersion.getCurrentOSVersion().getOS().isUnix())
			applyTo(path.toFile());
		Files.setPosixFilePermissions(path, permissions);
	}

	public static FilePermissions from(File file) throws IOException {
		if (OSVersion.getCurrentOSVersion().getOS().isUnix())
			return from(file.toPath());
		else
		{
			FilePermissions res=new FilePermissions();
			if (file.canRead())
				res.permissions.add(PosixFilePermission.OWNER_READ);
			if (file.canWrite())
				res.permissions.add(PosixFilePermission.OWNER_WRITE);
			if (file.canExecute())
				res.permissions.add(PosixFilePermission.OWNER_EXECUTE);
			return res;
		}
	}

	public static FilePermissions from(Path path) throws IOException {
		if (!OSVersion.getCurrentOSVersion().getOS().isUnix())
			return from(path.toFile());
		else
		{
			return new FilePermissions(Files.getPosixFilePermissions(path ));
		}
	}

	public short getCode()
	{
		return (short)hashCode();
	}

	@Override
	public int hashCode()
	{
		if (code==null)
		{
			short c=0;
			for (PosixFilePermission p : permissions)
			{
				switch (p)
				{
					case OWNER_READ:
						c|=256;
						break;
					case OWNER_WRITE:
						c|=128;
						break;
					case OWNER_EXECUTE:
						c|=64;
						break;
					case GROUP_READ:
						c|=32;
						break;
					case GROUP_WRITE:
						c|=16;
						break;
					case GROUP_EXECUTE:
						c|=8;
						break;
					case OTHERS_READ:
						c|=4;
						break;
					case OTHERS_WRITE:
						c|=2;
						break;
					case OTHERS_EXECUTE:
						c|=1;
						break;
				}
			}
			code=c;
		}
		return code;
	}


	@Override
	public int getInternalSerializedSize() {
		return 2;
	}

	@Override
	public void writeExternal(SecuredObjectOutputStream out) throws IOException {
		out.writeShort(getCode());
	}

	@Override
	public void readExternal(SecuredObjectInputStream in) throws IOException {
		code=in.readShort();
		if (code<0 || code>511)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		permissions.clear();
		readCode();
	}
}
