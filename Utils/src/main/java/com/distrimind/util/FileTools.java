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

import java.io.*;
import java.util.ArrayList;
import java.util.Objects;
import java.util.regex.Pattern;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;
import java.util.zip.ZipOutputStream;


/**
 * FileTool is a class which provides some methods used to work on Files and
 * Folders.
 * 
 */
public final class FileTools {

	public static final int BUFFER_SIZE = 128*1024;

	/**
	 * Check if a specified file path is a folder and create a folder if it does not
	 * exist.
	 * 
	 * @param folderPath
	 *            A folder path.
     * @return true if the fold exists or has been created
	 */
	public static boolean checkFolder(File folderPath) {
		if (!(folderPath.exists())) {
			return folderPath.mkdir();
		}
		return true;
	}

	/**
	 * Check if a specified file path is a folder and create the folder recursively if it does not exist.
	 *
	 * @param folderPath
	 *            A folder path.
	 *
     * @return true if the folders exists or have been created
	 */
    @SuppressWarnings("UnusedReturnValue")
	public static boolean checkFolderRecursive(File folderPath) {
		if (!(folderPath.exists())) {
			File parent=folderPath.getParentFile();
			if (parent!=null)
				checkFolderRecursive(parent);
			return folderPath.mkdir();
		}
		return false;
	}

	/**
	 * Copy a file from a source to a destination.
	 * 
	 * @param source
	 *            Source file path.
	 * @param destination
	 *            Destination file path.
	 * @param checkDestinationFolderRecursive Check if a specified destination path is in a folder that exists  and create the folder recursively if it does not exist.
	 * @throws IOException
	 *             when an IO exception occurs
	 */
	public static void copy(File source, File destination, boolean checkDestinationFolderRecursive) throws IOException {
		// destination.createNewFile();

		try (FileInputStream sourceFile = new FileInputStream(source)) {
			if (checkDestinationFolderRecursive)
				checkFolderRecursive(destination.getParentFile());
			try (FileOutputStream destinationFile = new java.io.FileOutputStream(destination)) {
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
	public static void copy(InputStream source, OutputStream destination) throws IOException {
		byte[] buffer = new byte[BUFFER_SIZE];
		int nbRead;
		while ((nbRead = source.read(buffer)) != -1) {
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
	 *            tells if the source directory must be included with the copy, and
	 *            not only its content
	 * @throws IOException
	 *             if a problem occurs
	 */
	public static void copyFolderToFolder(File sourceFolder, File destinationFolder, boolean include_source_forder)
			throws IOException {
		copyFolderToFolder(sourceFolder, destinationFolder, include_source_forder, null, null);
	}

	/**
	 * Copy all files and directories from a Folder to a destination Folder.
	 * 
	 * @param sourceFolder
	 *            Source directory.
	 * @param destinationFolder
	 *            Destination directory.
	 * @param include_source_forder
	 *            tells if the source directory must be included with the copy, and
	 *            not only its content
	 * @param _exclude_regex
	 *            the regex that enables to exclude files
	 * @param _include_regex
	 *            the regex that enables to include files
	 * @throws IOException
	 *             if a problem occurs
	 */
	public static void copyFolderToFolder(File sourceFolder, File destinationFolder, boolean include_source_forder,
			String _exclude_regex, String _include_regex) throws IOException {
		copyFolderToFolder(sourceFolder, include_source_forder ? sourceFolder.getName() : "",
				destinationFolder, _exclude_regex, _include_regex);
	}

	/**
	 * Copy all files and directories from a Folder to a destination Folder. Must be
	 * called like: listAllFilesInFolder(srcFolderPath, "", srcFolderPath,
	 * destFolderPath)
	 * 
	 * @param currentFolder
	 *            Used for the recursive called.
	 * @param relatedPath
	 *            Used for the recursive called.
	 * @param destinationFolder
	 *            Destination directory.
	 * @param regex_exclude
	 *            the regex that enables to exclude files
	 * @param regex_include
	 *            the regex that enables to include files
	 * @throws IOException
	 *             if a problem occurs
	 */
	private static void copyFolderToFolder(File currentFolder, String relatedPath,
			File destinationFolder, String regex_exclude, String regex_include) throws IOException {
		// Current Directory.

		if (currentFolder.isDirectory()
				&& FileTools.matchString(currentFolder.getAbsolutePath(), regex_exclude, regex_include)) {
			// List all files and folder in the current directory.
			File[] list = currentFolder.listFiles();
			if (list != null) {
				// Read the files list.
                for (File tf : list) {
                    // Create current source File
                    /*
                     * File tf = new File(sourceFolder + relatedPath + "/" + list[i].getName());
                     */
                    // Create current destination File
                    File pf = new File(new File(destinationFolder, relatedPath), tf.getName());
                    if (FileTools.matchString(tf.getAbsolutePath(), regex_exclude, regex_include)) {
                        if (tf.isDirectory() && !pf.exists()) {
                            // If the file is a directory and does not exit in
                            // the
                            // destination Folder.
                            // Create the directory.
                            if (pf.mkdir())
                                copyFolderToFolder(tf, relatedPath + "/" + tf.getName(), destinationFolder,
                                    regex_exclude, regex_include);
                            else
                                throw new IOException("Impossible to create folder : "+pf);
                        } else if (tf.isDirectory() && pf.exists()) {
                            // If the file is a directory and exits in the
                            // destination Folder.
                            copyFolderToFolder(tf, relatedPath + "/" + tf.getName(), destinationFolder,
                                    regex_exclude, regex_include);
                        } else if (tf.isFile()) {
                            // If it is a file.

                            copy(tf, pf, true);
                        } else {
                            throw new IOException("Messages.file_problem + tf.getAbsolutePath()");
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
     * @return true if the directory has been deleted
	 */
    @SuppressWarnings("UnusedReturnValue")
	public static boolean deleteDirectory(File path) {
		if (path.exists()) {
			File[] files = path.listFiles();
			if (files!=null) {
                for (File file : files) {
                    if (file.isDirectory()) {
                        deleteDirectory(file);
                    } else {
                        if (!file.delete())
                            return false;
                    }
                }
            }
		}
		return path.delete();
	}

	/*
	 * public static void deleteDirectory(FTPClient ftpClient, String _directory)
	 * throws IOException { if (!_directory.endsWith("/")) _directory += "/";
	 * FTPListParseEngine ftplpe = ftpClient.initiateListParsing(_directory);
	 * FTPFile files[] = ftplpe.getFiles(); for (FTPFile f : files) { if
	 * (!f.getName().equals(".") && !f.getName().equals("..")) { if
	 * (f.isDirectory()) deleteDirectory(ftpClient, _directory + f.getName() + "/");
	 * else ftpClient.deleteFile(_directory + f.getName()); } }
	 * ftpClient.removeDirectory(_directory);
	 * 
	 * }
	 */

	private static String getRelativePath(String base, String path) {
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
	public static ArrayList<File> getTree(File directory) {
		ArrayList<File> res = new ArrayList<>();
		res.add(directory);
		File[] files=directory.listFiles();
		if (files==null)
		    return res;
		for (File f2 : files) {
			if (f2.isDirectory()) {
				res.addAll(getTree(f2));
			}
		}
		return res;
	}

	public static boolean matchString(String s, String regex_exclude, String regex_include) {
		if (regex_include != null && !Pattern.compile(regex_include).matcher(s).find())
			return false;
        return regex_exclude == null || !Pattern.compile(regex_exclude).matcher(s).find();
    }

	/**
	 * Move a file from a source to a destination. If the moving by using the
	 * renameTo method does not work, it used the copy method.
	 * 
	 * @param source
	 *            Source file path.
	 * @param destination
	 *            Destination file path.
	 * @param checkDestinationFolderRecursive Check if a specified destination path is in a folder that exists  and create the folder recursively if it does not exist.
	 * @throws IOException
	 *             when an IO exception occurs
	 */
	public static void move(File source, File destination, boolean checkDestinationFolderRecursive) throws IOException {
		// Try to use renameTo
		boolean result = source.renameTo(destination);
		if (!result) {
			// Copy
			copy(source, destination, checkDestinationFolderRecursive);
			if (!source.delete())
				throw new IOException("Impossible to delete source file "+source);
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
     * @return true if the file has been removed
	 */

	@SuppressWarnings("UnusedReturnValue")
    public static boolean removeFile(String file, File rootDirectory) throws IOException {
		// Remove a file on the local machine
		if (file == null || file.equals("")) {
		    return false;
		}
		if (!rootDirectory.isDirectory()) {
			throw new IOException(rootDirectory.toString());
		} else {
			File f = new File(rootDirectory, file);
			if (f.exists()) {
				return f.delete();
			}
		}
		return false;
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
	public static void removeFiles(ArrayList<String> files, File projectDirectory) throws IOException {
        for (String file : files) {
            removeFile(file, projectDirectory);
        }
	}

	private static String transformToDirectory(String _dir) {
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
	public static void unzipFile(File _zip_file, File _directory_dst) throws IOException {
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
	public static void unzipFile(File _zip_file, File _directory_dst, String regex_exclude, String regex_include)
			throws IOException {
		if (!_directory_dst.exists())
			throw new IllegalAccessError("The directory of destination does not exists !");
		if (!_directory_dst.isDirectory())
			throw new IllegalAccessError("The directory of destination is not a directory !");
		try(FileInputStream fis = new FileInputStream(_zip_file);ZipInputStream zis = new ZipInputStream(fis)) {
			ZipEntry entry;
			byte[] data = new byte[BUFFER_SIZE];
			while ((entry = zis.getNextEntry()) != null) {
				String entryName=entry.getName();
				if (entryName.contains(".."))
					continue;
				if (!matchString(entryName, regex_exclude, regex_include))
					continue;

				if (entry.isDirectory()) {
					checkFolderRecursive(new File(_directory_dst, entryName));
				} else {
					// System.out.println("Extracting: " +entry);
					int count;

					// write the files to the disk
					// System.out.println("Extracting: " +new File(_directory_dst,
					// entry.getName()));
					File f = new File(_directory_dst, entryName);
					checkFolderRecursive(f.getParentFile());
					try (FileOutputStream fos = new FileOutputStream(f)) {
						while ((count = zis.read(data, 0, data.length)) != -1) {
							fos.write(data, 0, count);
						}
					}
				}
			}
		}

	}

	/**
	 * Zip a directory and its content into a ZIP/JAR file
	 * 
	 * @param _directory
	 *            the directory to zip
	 * @param _include_directory
	 *            tells if the directory must be included into the ZIP/JAR file, or
	 *            if only its content must be included
	 * @param _zipfile
	 *            the destination ZIP/JAR file
	 * @throws IOException
	 *             if a problem occurs
	 */
	public static void zipDirectory(File _directory, boolean _include_directory, File _zipfile) throws IOException {
		if (!_directory.exists())
			throw new IllegalAccessError("The directory " + _directory + " does not exists !");
		if (!_directory.isDirectory())
			throw new IllegalAccessError("The directory " + _directory + " is not a directory !");

		try(FileOutputStream dest = new FileOutputStream(_zipfile);ZipOutputStream out = new ZipOutputStream(dest)) {
			String dir = _directory.getAbsolutePath();
			if (_include_directory) {
				int l = dir.lastIndexOf(_directory.getName());
				String base = dir.substring(0, l);
				String relPath = getRelativePath(base, _directory.getAbsolutePath());
				if (relPath == null)
					throw new IOException();
				ZipEntry entry = new ZipEntry(transformToDirectory(relPath));
				out.putNextEntry(entry);

				zipDirectory(out, _directory, base);
			} else {
				if (!dir.endsWith("/"))
					dir = dir + "/";
				zipDirectory(out, _directory, dir);
			}
		}
	}

	@SuppressWarnings("ConstantConditions")
    private static void zipDirectory(ZipOutputStream out, File _directory, String base_directory) throws IOException {

        File[] files =_directory.listFiles();
        if (files==null)
            throw new IOException();
		byte[] data = new byte[BUFFER_SIZE];
		for (File f : files ) {
			// System.out.println("Adding: "+files[i]);
			if (f.isDirectory()) {
				ZipEntry entry = new ZipEntry(
						transformToDirectory(getRelativePath(base_directory, f.getAbsolutePath())));
				out.putNextEntry(entry);
				zipDirectory(out, f, base_directory);
			} else {

				try(FileInputStream fi = new FileInputStream(f)) {
					ZipEntry entry = new ZipEntry(getRelativePath(base_directory, f.getAbsolutePath()));
					out.putNextEntry(entry);
					int count;
					while ((count = fi.read(data, 0, data.length)) != -1) {
						out.write(data, 0, count);
					}
				}
			}
		}
	}

	/**
	 * FileTools Constructor.
	 */
	private FileTools() {
	}

	public static abstract class FileVisitor
	{
		private final boolean includeStartDirectory;
		private final boolean acceptFiles;
		private final boolean acceptDirectories;
		private final boolean visitSubDirectories;

		protected FileVisitor(boolean acceptFiles, boolean acceptDirectories, boolean includeStartDirectory, boolean visitSubDirectories) {
			if (!acceptDirectories && !acceptFiles)
				throw new IllegalArgumentException();
			if (!acceptDirectories && includeStartDirectory)
				throw new IllegalArgumentException();
			this.acceptFiles = acceptFiles;
			this.acceptDirectories = acceptDirectories;
			this.includeStartDirectory=includeStartDirectory;
			this.visitSubDirectories=visitSubDirectories;
		}

		/**
		 * A new file has been identified when this function is called
		 * @param file the file
		 * @return true if the scan can continue
		 */
		@SuppressWarnings("BooleanMethodIsAlwaysInverted")
		public abstract boolean visitFile(File file) ;

	}
	public static void walkFileTree(File directory, final FileVisitor fv)
	{
		if (directory==null)
			throw new NullPointerException();
		if (directory.isDirectory())
		{
			if (fv.includeStartDirectory)
				if (!fv.visitFile(directory))
					return;
			walkDirTree(directory, fv);
		}
		else
		{
			throw new IllegalArgumentException();
		}
	}
	private static boolean walkDirTree(File directory, final FileVisitor fv)
	{
		for (File f : Objects.requireNonNull(directory.listFiles(((fv.acceptDirectories || fv.visitSubDirectories) && fv.acceptFiles)?null:new FileFilter() {
			@Override
			public boolean accept(File pathname) {
				return ((fv.acceptDirectories || fv.visitSubDirectories) && pathname.isDirectory()) || (fv.acceptFiles && pathname.isFile());
			}
		}))) {
			if (fv.acceptFiles && f.isFile())
				if (!fv.visitFile(f))
					return false;
			else if (f.isDirectory())
			{
				if (fv.acceptDirectories)
					if (!fv.visitFile(f))
						return false;
				if (fv.visitSubDirectories)
					if (!walkDirTree(f, fv))
						return false;
			}
		}
		return true;
	}
}