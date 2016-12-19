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

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;

import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPFile;
import org.apache.commons.net.ftp.FTPListParseEngine;

/**
 * FileTool is a class which provides some methods used to work on Files and
 * Folders.
 * 
 */
public final class FileTools
{

    private static final int BUFFER = 2048;

    /**
     * Check if a specified file path is a folder and create a folder if it does
     * not exist.
     * 
     * @param folderPath
     *            A folder path.
     */
    public static void checkFolder(File folderPath)
    {
	if (!(folderPath.exists()))
	{
	    folderPath.mkdir();
	}
    }

    /**
     * Check if a specified file path is a folder and create a folder if it does
     * not exist.
     * 
     * @param folderPath
     *            A folder path.
     */
    public static void checkFolderRecursive(File folderPath)
    {
	if (!(folderPath.exists()))
	{
	    checkFolderRecursive(folderPath.getParentFile());
	    folderPath.mkdir();
	}
    }

    /**
     * Copy a file from a source to a destination.
     * 
     * @param source
     *            Source file path.
     * @param destination
     *            Destination file path.
     * @throws IOException
     *             when an IO exception occurs
     */
    public static void copy(File source, File destination) throws IOException
    {
	// destination.createNewFile();
	try (FileInputStream sourceFile = new FileInputStream(source))
	{
	    try (FileOutputStream destinationFile = new java.io.FileOutputStream(
		    destination))
	    {
		copy(sourceFile, destinationFile);
	    }
	}
    }

    /**
     * Copy the content of a an input stream to an output stream
     * 
     * @param source
     *            Source file path.
     * @param destination
     *            Destination file path.
     * @throws IOException
     *             if a problem occurs
     */
    public static void copy(InputStream source, OutputStream destination) throws IOException
    {
	byte buffer[] = new byte[512 * 1024];
	int nbRead;
	while ((nbRead = source.read(buffer)) != -1)
	{
	    destination.write(buffer, 0, nbRead);
	}
    }

    /**
     * Copy all files and directories from a Folder to a destination Folder.
     * 
     * @param sourceFolder
     *            Source directory.
     * @param destinationFolder
     *            Destination directory.
     * @param include_source_forder
     *            tells if the source directory must be included with the copy,
     *            and not only its content
     * @throws IOException
     *             if a problem occurs
     */
    public static void copyFolderToFolder(File sourceFolder, File destinationFolder, boolean include_source_forder) throws IOException
    {
	copyFolderToFolder(sourceFolder, destinationFolder,
		include_source_forder, null, null);
    }

    /**
     * Copy all files and directories from a Folder to a destination Folder.
     * 
     * @param sourceFolder
     *            Source directory.
     * @param destinationFolder
     *            Destination directory.
     * @param include_source_forder
     *            tells if the source directory must be included with the copy,
     *            and not only its content
     * @param _exclude_regex
     *            the regex that enables to exclude files
     * @param _include_regex
     *            the regex that enables to include files
     * @throws IOException
     *             if a problem occurs
     */
    public static void copyFolderToFolder(File sourceFolder, File destinationFolder, boolean include_source_forder, String _exclude_regex, String _include_regex) throws IOException
    {
	copyFolderToFolder(sourceFolder,
		include_source_forder ? sourceFolder.getName() : "",
		sourceFolder, destinationFolder, _exclude_regex,
		_include_regex);
    }

    /**
     * Copy all files and directories from a Folder to a destination Folder.
     * Must be called like: listAllFilesInFolder(srcFolderPath, "",
     * srcFolderPath, destFolderPath)
     * 
     * @param currentFolder
     *            Used for the recursive called.
     * @param relatedPath
     *            Used for the recursive called.
     * @param sourceFolder
     *            Source directory.
     * @param destinationFolder
     *            Destination directory.
     * @param regex_exclude
     *            the regex that enables to exclude files
     * @param regex_include
     *            the regex that enables to include files
     * @throws IOException
     *             if a problem occurs
     */
    private static void copyFolderToFolder(File currentFolder, String relatedPath, File sourceFolder, File destinationFolder, String regex_exclude, String regex_include) throws IOException
    {
	// Current Directory.

	if (currentFolder.isDirectory() && FileTools.matchString(
		currentFolder.getAbsolutePath(), regex_exclude, regex_include))
	{
	    // List all files and folder in the current directory.
	    File[] list = currentFolder.listFiles();
	    if (list != null)
	    {
		// Read the files list.
		for (int i = 0; i < list.length; i++)
		{
		    // Create current source File
		    /*
		     * File tf = new File(sourceFolder + relatedPath + "/" +
		     * list[i].getName());
		     */
		    File tf = list[i];
		    // Create current destination File
		    File pf = new File(new File(destinationFolder, relatedPath),
			    list[i].getName());
		    if (FileTools.matchString(tf.getAbsolutePath(),
			    regex_exclude, regex_include))
		    {
			if (tf.isDirectory() && !pf.exists())
			{
			    // If the file is a directory and does not exit in
			    // the
			    // destination Folder.
			    // Create the directory.
			    pf.mkdir();
			    copyFolderToFolder(tf,
				    relatedPath + "/" + tf.getName(),
				    sourceFolder, destinationFolder,
				    regex_exclude, regex_include);
			}
			else if (tf.isDirectory() && pf.exists())
			{
			    // If the file is a directory and exits in the
			    // destination Folder.
			    copyFolderToFolder(tf,
				    relatedPath + "/" + tf.getName(),
				    sourceFolder, destinationFolder,
				    regex_exclude, regex_include);
			}
			else if (tf.isFile())
			{
			    // If it is a file.
			    FileTools.checkFolderRecursive(pf.getParentFile());
			    copy(tf, pf);
			}
			else
			{
			    throw new IOException(
				    "Messages.file_problem + tf.getAbsolutePath()");
			}
		    }
		}
	    }
	}
    }

    /**
     * Delete a directory.
     * 
     * @param path
     *            A folder path.
     */
    public static void deleteDirectory(File path)
    {
	if (path.exists())
	{
	    File[] files = path.listFiles();
	    for (int i = 0; i < files.length; i++)
	    {
		if (files[i].isDirectory())
		{
		    deleteDirectory(files[i]);
		}
		else
		{
		    files[i].delete();
		}
	    }
	}
	path.delete();
    }

    public static void deleteDirectory(FTPClient ftpClient, String _directory) throws IOException
    {
	if (!_directory.endsWith("/"))
	    _directory += "/";
	FTPListParseEngine ftplpe = ftpClient.initiateListParsing(_directory);
	FTPFile files[] = ftplpe.getFiles();
	for (FTPFile f : files)
	{
	    if (!f.getName().equals(".") && !f.getName().equals(".."))
	    {
		if (f.isDirectory())
		    deleteDirectory(ftpClient, _directory + f.getName() + "/");
		else
		    ftpClient.deleteFile(_directory + f.getName());
	    }
	}
	ftpClient.removeDirectory(_directory);

    }

    private static String getRelativePath(String base, String path)
    {
	if (path.startsWith(base))
	    return path.substring(base.length());
	else
	    return null;
    }

    /**
     * 
     * @param directory
     *            the root directory
     * @return the file directory tree
     */
    public static ArrayList<File> getTree(File directory)
    {
	ArrayList<File> res = new ArrayList<File>();
	res.add(directory);
	for (File f2 : directory.listFiles())
	{
	    if (f2.isDirectory())
	    {
		res.addAll(getTree(f2));
	    }
	}
	return res;
    }

    public static boolean matchString(String s, String regex_exclude, String regex_include)
    {
	if (regex_include != null
		&& !Pattern.compile(regex_include).matcher(s).find())
	    return false;
	if (regex_exclude != null
		&& Pattern.compile(regex_exclude).matcher(s).find())
	    return false;
	return true;
    }

    /**
     * Move a file from a source to a destination. If the moving by using the
     * renameTo method does not work, it used the copy method.
     * 
     * @param source
     *            Source file path.
     * @param destination
     *            Destination file path.
     * @throws IOException
     *             when an IO exception occurs
     */
    public static void move(File source, File destination) throws IOException
    {
	// Try to use renameTo
	boolean result = source.renameTo(destination);
	if (!result)
	{
	    // Copy
	    copy(source, destination);
	}
    }

    /**
     * Remove a file in a specified root directory.
     * 
     * @param file
     *            A file path.
     * @param rootDirectory
     *            A root directory.
     * @throws IOException
     *             if a problem occurs
     */
    public static void removeFile(String file, File rootDirectory) throws IOException
    {
	// Remove a file on the local machine
	if (file == null || file.equals(""))
	{
	}
	if (!rootDirectory.isDirectory())
	{
	    throw new IOException(rootDirectory.toString());
	}
	else
	{
	    File f = new File(rootDirectory, file);
	    if (f.exists())
	    {
		f.delete();
	    }
	}
    }

    /**
     * Remove a Vector of files on the local machine.
     * 
     * @param files
     *            A vector of file paths.
     * @param projectDirectory
     *            The project Directory.
     * @throws IOException
     *             if a problem occurs
     */
    public static void removeFiles(ArrayList<String> files, File projectDirectory) throws IOException
    {
	Iterator<String> it = files.iterator();
	while (it.hasNext())
	{
	    removeFile(it.next(), projectDirectory);
	}
    }

    private static String transformToDirectory(String _dir)
    {
	if (_dir.endsWith("/"))
	    return _dir;
	else
	    return _dir + "/";
    }

    /**
     * Unzip a ZIP/Jar file into a directory
     * 
     * @param _zip_file
     *            the zip or jar file
     * @param _directory_dst
     *            the destination where the ZIP/JAR file is unzip
     * @throws IOException
     *             if a problem occurs
     */
    public static void unzipFile(File _zip_file, File _directory_dst) throws IOException
    {
	unzipFile(_zip_file, _directory_dst, null, null);
    }

    /**
     * Unzip a ZIP/Jar file into a directory
     * 
     * @param _zip_file
     *            the zip or jar file
     * @param _directory_dst
     *            the destination where the ZIP/JAR file is unzip
     * @param regex_exclude
     *            the regex that enables to exclude files
     * @param regex_include
     *            the regex that enables to include files
     * @throws IOException
     *             if a problem occurs
     */
    public static void unzipFile(File _zip_file, File _directory_dst, String regex_exclude, String regex_include) throws IOException
    {
	if (!_directory_dst.exists())
	    throw new IllegalAccessError(
		    "The directory of destination does not exists !");
	if (!_directory_dst.isDirectory())
	    throw new IllegalAccessError(
		    "The directory of destination is not a directory !");
	BufferedOutputStream dest = null;
	FileInputStream fis = new FileInputStream(_zip_file);
	ZipInputStream zis = new ZipInputStream(new BufferedInputStream(fis));
	ZipEntry entry;
	while ((entry = zis.getNextEntry()) != null)
	{
	    if (!matchString(entry.getName(), regex_exclude, regex_include))
		continue;
	    if (entry.isDirectory())
	    {
		checkFolderRecursive(new File(_directory_dst, entry.getName()));
	    }
	    else
	    {
		// System.out.println("Extracting: " +entry);
		int count;
		byte data[] = new byte[BUFFER];
		// write the files to the disk
		// System.out.println("Extracting: " +new File(_directory_dst,
		// entry.getName()));
		File f = new File(_directory_dst, entry.getName());
		checkFolderRecursive(f.getParentFile());
		FileOutputStream fos = new FileOutputStream(f);
		dest = new BufferedOutputStream(fos, BUFFER);
		while ((count = zis.read(data, 0, BUFFER)) != -1)
		{
		    dest.write(data, 0, count);
		}
		dest.flush();
		dest.close();
	    }
	}
	zis.close();

    }

    /**
     * Zip a directory and its content into a ZIP/JAR file
     * 
     * @param _directory
     *            the directory to zip
     * @param _include_directory
     *            tells if the directory must be included into the ZIP/JAR file,
     *            or if only its content must be included
     * @param _zipfile
     *            the destination ZIP/JAR file
     * @throws IOException
     *             if a problem occurs
     */
    public static void zipDirectory(File _directory, boolean _include_directory, File _zipfile) throws IOException
    {
	if (!_directory.exists())
	    throw new IllegalAccessError(
		    "The directory " + _directory + " does not exists !");
	if (!_directory.isDirectory())
	    throw new IllegalAccessError(
		    "The directory " + _directory + " is not a directory !");
	FileOutputStream dest = new FileOutputStream(_zipfile);
	ZipOutputStream out = new ZipOutputStream(
		new BufferedOutputStream(dest));

	if (_include_directory)
	{
	    String dir = _directory.getAbsolutePath();
	    int l = dir.lastIndexOf(_directory.getName());
	    String base = dir.substring(0, l);

	    ZipEntry entry = new ZipEntry(transformToDirectory(
		    getRelativePath(base, _directory.getAbsolutePath())));
	    out.putNextEntry(entry);

	    zipDirectory(out, _directory, base);
	}
	else
	{
	    String base = _directory.getAbsolutePath();
	    if (!base.endsWith("/"))
		base = base + "/";
	    zipDirectory(out, _directory, base);
	}

	out.close();
    }

    private static void zipDirectory(ZipOutputStream out, File _directory, String base_directory) throws IOException
    {
	byte data[] = new byte[BUFFER];
	for (File f : _directory.listFiles())
	{
	    // System.out.println("Adding: "+files[i]);
	    if (f.isDirectory())
	    {
		ZipEntry entry = new ZipEntry(transformToDirectory(
			getRelativePath(base_directory, f.getAbsolutePath())));
		out.putNextEntry(entry);
		zipDirectory(out, f, base_directory);
	    }
	    else
	    {
		FileInputStream fi = new FileInputStream(f);
		BufferedInputStream origin = new BufferedInputStream(fi,
			BUFFER);
		ZipEntry entry = new ZipEntry(
			getRelativePath(base_directory, f.getAbsolutePath()));
		out.putNextEntry(entry);
		int count;
		while ((count = origin.read(data, 0, BUFFER)) != -1)
		{
		    out.write(data, 0, count);
		}
		origin.close();
	    }
	}
    }

    /**
     * FileTools Constructor.
     */
    FileTools()
    {
    }
}