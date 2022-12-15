/*
Copyright or © or Corp. Jason Mahdjoub (04/02/2016)

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

import com.distrimind.util.OS;
import com.distrimind.util.OSVersion;
import com.distrimind.util.io.*;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
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
	private static final Method toFileMethod;
	private static final Method getPosixFilePermissionsMethod;
	private static final LinkOption[] emptyLinkOptions=new LinkOption[0];
	static
	{
		Method m=null;
		try {
			m=Path.class.getDeclaredMethod("toFile" );
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		toFileMethod=m;
		m=null;
		try {
			m=Files.class.getDeclaredMethod("getPosixFilePermissions", Path.class, LinkOption[].class);
		} catch (NoSuchMethodException e) {
			e.printStackTrace();
			System.exit(-1);
		}
		getPosixFilePermissionsMethod=m;
	}

	private final Set<PosixFilePermission> permissions=new HashSet<>();
	private boolean permissionsFromUnixSystem;
	private Short code=null;
	private static final boolean pathMethodsCompatible=OSVersion.getCurrentOSVersion().getOS()!= OS.ANDROID || OSVersion.getCurrentOSVersion().compareTo(OSVersion.ANDROID_26_O)>=0;

	private FilePermissions(PosixFilePermission ...posixFilePermissions) {
		Collections.addAll(permissions, posixFilePermissions);
		permissionsFromUnixSystem =isOSCompatibleWithUnix();
	}

	private FilePermissions(Collection<PosixFilePermission> posixFilePermissions) {
		permissions.addAll(posixFilePermissions);
		permissionsFromUnixSystem =isOSCompatibleWithUnix();
	}



	public boolean arePermissionsFromUnixSystem() {
		return permissionsFromUnixSystem;
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
	@SuppressWarnings("UnusedReturnValue")
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
		StringBuilder sb=new StringBuilder(9);
		if (permissions.contains(PosixFilePermission.OWNER_READ))
			sb.append("r");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.OWNER_WRITE))
			sb.append("w");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.OWNER_EXECUTE))
			sb.append("x");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.GROUP_READ))
			sb.append("r");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.GROUP_WRITE))
			sb.append("w");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.GROUP_EXECUTE))
			sb.append("x");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.OTHERS_READ))
			sb.append("r");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.OTHERS_WRITE))
			sb.append("w");
		else
			sb.append("-");
		if (permissions.contains(PosixFilePermission.OTHERS_EXECUTE))
			sb.append("x");
		else
			sb.append("-");
		return sb.toString();
	}

	public static FilePermissions from(String permissions)
	{
		permissions=permissions.toLowerCase();
		FilePermissions res=new FilePermissions();
		if (permissions.length()==3)
		{
			res.permissionsFromUnixSystem=false;
			if (permissions.charAt(2)=='r')
				res.addPermissions(PosixFilePermission.OWNER_READ);
			if (permissions.charAt(1)=='w')
				res.addPermissions(PosixFilePermission.OWNER_WRITE);
			if (permissions.charAt(0)=='x')
				res.addPermissions(PosixFilePermission.OWNER_EXECUTE);
		}
		else
		{
			res.permissionsFromUnixSystem=true;
			if (permissions.charAt(8)=='r')
				res.addPermissions(PosixFilePermission.OWNER_READ);
			if (permissions.charAt(7)=='w')
				res.addPermissions(PosixFilePermission.OWNER_WRITE);
			if (permissions.charAt(6)=='x')
				res.addPermissions(PosixFilePermission.OWNER_EXECUTE);
			if (permissions.charAt(5)=='r')
				res.addPermissions(PosixFilePermission.GROUP_READ);
			if (permissions.charAt(4)=='w')
				res.addPermissions(PosixFilePermission.GROUP_WRITE);
			if (permissions.charAt(3)=='x')
				res.addPermissions(PosixFilePermission.GROUP_EXECUTE);
			if (permissions.charAt(2)=='r')
				res.addPermissions(PosixFilePermission.OTHERS_READ);
			if (permissions.charAt(1)=='w')
				res.addPermissions(PosixFilePermission.OTHERS_WRITE);
			if (permissions.charAt(0)=='x')
				res.addPermissions(PosixFilePermission.OTHERS_EXECUTE);

		}
		return res;
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
		permissionsFromUnixSystem =(code & 512)==512;
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

	public static FilePermissions from(short unixCode)
	{
		if (unixCode<0 || unixCode>1023)
			throw new IllegalArgumentException();
		FilePermissions res=new FilePermissions();
		unixCode=(short)(unixCode | 512);
		res.code=unixCode;
		res.readCode();
		return res;
	}

	public FilePermissions convertToLocalPermissions()
	{
		FilePermissions res=new FilePermissions();
		if (res.permissionsFromUnixSystem)
			res.permissions.addAll(permissions);
		else {
			for (PosixFilePermission p : permissions) {
				if ( p == PosixFilePermission.OWNER_EXECUTE || p == PosixFilePermission.OWNER_READ || p == PosixFilePermission.OWNER_WRITE)
					res.permissions.add(p);
			}
		}
		return res;
	}

	public void applyTo(File file) throws IOException {

		if (permissionsFromUnixSystem && isOSCompatibleWithUnix())
			applyTo(file.toPath());
		if (!file.setReadable(containsPermission(PosixFilePermission.OWNER_READ)))
			throw new SecurityException();
		if (!file.setReadable(containsPermission(PosixFilePermission.OWNER_WRITE)))
			throw new SecurityException();
		if (!file.setReadable(containsPermission(PosixFilePermission.OWNER_EXECUTE)))
			throw new SecurityException();

	}


	@SuppressWarnings("unchecked")
	public void applyTo(Path path) throws IOException {
		if (!permissionsFromUnixSystem || !isOSCompatibleWithUnix()) {
			applyTo(getFile(path));
			return;
		}
		Set<java.nio.file.attribute.PosixFilePermission> set=new HashSet<>();
		try {
			//noinspection unchecked
			for (java.nio.file.attribute.PosixFilePermission p : (Set< java.nio.file.attribute.PosixFilePermission >)getPosixFilePermissionsMethod.invoke(null, path, emptyLinkOptions ))
			{
				switch (p)
				{
					case OWNER_READ:
						set.add(java.nio.file.attribute.PosixFilePermission.OWNER_READ);
						break;
					case OWNER_WRITE:
						set.add(java.nio.file.attribute.PosixFilePermission.OWNER_WRITE);
						break;
					case OWNER_EXECUTE:
						set.add(java.nio.file.attribute.PosixFilePermission.OWNER_EXECUTE);
						break;
					case GROUP_READ:
						set.add(java.nio.file.attribute.PosixFilePermission.GROUP_READ);
						break;
					case GROUP_WRITE:
						set.add(java.nio.file.attribute.PosixFilePermission.GROUP_WRITE);
						break;
					case GROUP_EXECUTE:
						set.add(java.nio.file.attribute.PosixFilePermission.GROUP_EXECUTE);
						break;
					case OTHERS_READ:
						set.add(java.nio.file.attribute.PosixFilePermission.OTHERS_READ);
						break;
					case OTHERS_WRITE:
						set.add(java.nio.file.attribute.PosixFilePermission.OTHERS_WRITE);
						break;
					case OTHERS_EXECUTE:
						set.add(java.nio.file.attribute.PosixFilePermission.OTHERS_EXECUTE);
						break;
				}
			}
		} catch (IllegalAccessException | InvocationTargetException e) {
			throw new IOException(e);
		}
		Files.setPosixFilePermissions(path, set);
	}

	public static FilePermissions from(File file) throws IOException {
		if (isOSCompatibleWithUnix())
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

	public static File getFile(Path path) throws IOException {
		if (pathMethodsCompatible) {
			try {
				return (File)toFileMethod.invoke(path);
			} catch (IllegalAccessException | InvocationTargetException e) {
				throw new IOException(e);
			}
		}
		else
			return new File(path.toString());
	}

	private static boolean isOSCompatibleWithUnix()
	{
		return OSVersion.getCurrentOSVersion().getOS().isUnix()
				&&
				pathMethodsCompatible;
	}

	public static FilePermissions from(Path path) throws IOException {
		if (!isOSCompatibleWithUnix())
			return from(getFile(path));
		else
		{
			FilePermissions fp=new FilePermissions();
			for (java.nio.file.attribute.PosixFilePermission p : Files.getPosixFilePermissions(path ))
			{
				switch (p)
				{
					case OWNER_READ:
						fp.permissions.add(PosixFilePermission.OWNER_READ);
						break;
					case OWNER_WRITE:
						fp.permissions.add(PosixFilePermission.OWNER_WRITE);
						break;
					case OWNER_EXECUTE:
						fp.permissions.add(PosixFilePermission.OWNER_EXECUTE);
						break;
					case GROUP_READ:
						fp.permissions.add(PosixFilePermission.GROUP_READ);
						break;
					case GROUP_WRITE:
						fp.permissions.add(PosixFilePermission.GROUP_WRITE);
						break;
					case GROUP_EXECUTE:
						fp.permissions.add(PosixFilePermission.GROUP_EXECUTE);
						break;
					case OTHERS_READ:
						fp.permissions.add(PosixFilePermission.OTHERS_READ);
						break;
					case OTHERS_WRITE:
						fp.permissions.add(PosixFilePermission.OTHERS_WRITE);
						break;
					case OTHERS_EXECUTE:
						fp.permissions.add(PosixFilePermission.OTHERS_EXECUTE);
						break;
				}
			}
			return fp;
		}
	}

	public short getCode()
	{
		return (short)hashCode();
	}

	public short getUnixCode()
	{
		if (permissionsFromUnixSystem)
			return (short)(getCode()-512);
		else
			return getCode();
	}

	@Override
	public int hashCode()
	{
		if (code==null)
		{
			short c=(permissionsFromUnixSystem ?(short)512:0);
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
		if (code<0 || code>1023)
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
		permissions.clear();
		readCode();
	}


}
