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
package com.distrimind.util.export;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.ArrayList;

import org.apache.commons.net.ftp.FTP;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPFile;
import org.apache.commons.net.ftp.FTPListParseEngine;

import com.distrimind.util.FileTools;
import com.distrimind.util.properties.XMLProperties;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.3
 * @since Utils 1.0
 */

public class Exports extends XMLProperties
{
    public static class ExportProperties extends XMLProperties
    {
	/**
	 * 
	 */
	private static final long serialVersionUID = -7312414086912484454L;

	public final boolean include_dependancies;

	public final SourceCodeExportType source_code_export_type;

	public final boolean include_documentation;

	public ExportProperties(boolean _include_dependancies, SourceCodeExportType _source_code_export_type, boolean _include_documentation)
	{
	    super(null);
	    include_dependancies = _include_dependancies;
	    source_code_export_type = _source_code_export_type;
	    include_documentation = _include_documentation;
	}

    }

    public static enum SourceCodeExportType
    {
	NO_SOURCE_CODE, SOURCE_CODE_IN_SEPERATE_FILE, SOURCE_CODE_IN_JAR_FILE
    }

    /**
     * 
     */
    private static final long serialVersionUID = 2428443980388438163L;

    private static void updateFTP(FTPClient ftpClient, String _directory_dst, File _directory_src, File _current_file_transfert) throws IOException, TransfertException
    {
	ftpClient.changeWorkingDirectory("./");
	FTPListParseEngine ftplpe = ftpClient
		.initiateListParsing(_directory_dst);
	FTPFile files[] = ftplpe.getFiles();

	File current_file_transfert = _current_file_transfert;

	try
	{
	    for (File f : _directory_src.listFiles())
	    {
		if (f.isDirectory())
		{
		    if (!f.getName().equals("./") && !f.getName().equals("../"))
		    {
			if (_current_file_transfert != null)
			{
			    if (!_current_file_transfert.getCanonicalPath()
				    .startsWith(f.getCanonicalPath()))
				continue;
			    else
				_current_file_transfert = null;
			}
			boolean found = false;
			for (FTPFile ff : files)
			{
			    if (f.getName().equals(ff.getName()))
			    {
				if (ff.isFile())
				{
				    ftpClient.deleteFile(
					    _directory_dst + ff.getName());
				}
				else
				    found = true;
				break;
			    }
			}

			if (!found)
			{
			    ftpClient.changeWorkingDirectory("./");
			    if (!ftpClient.makeDirectory(
				    _directory_dst + f.getName() + "/"))
				System.err.println(
					"Impossible to create directory "
						+ _directory_dst + f.getName()
						+ "/");
			}
			updateFTP(ftpClient, _directory_dst + f.getName() + "/",
				f, _current_file_transfert);
		    }
		}
		else
		{
		    if (_current_file_transfert != null)
		    {
			if (!_current_file_transfert
				.equals(f.getCanonicalPath()))
			    continue;
			else
			    _current_file_transfert = null;
		    }
		    current_file_transfert = _current_file_transfert;
		    FTPFile found = null;
		    for (FTPFile ff : files)
		    {
			if (f.getName().equals(ff.getName()))
			{
			    if (ff.isDirectory())
			    {
				FileTools.deleteDirectory(ftpClient,
					_directory_dst + ff.getName());
			    }
			    else
				found = ff;
			    break;
			}
		    }
		    if (found == null
			    || (found.getTimestamp().getTimeInMillis()
				    - f.lastModified()) < 0
			    || found.getSize() != f.length())
		    {
			FileInputStream fis = new FileInputStream(f);
			ftpClient.setFileType(FTP.BINARY_FILE_TYPE);
			if (!ftpClient.storeFile(_directory_dst + f.getName(),
				fis))
			    System.err.println("Impossible to send file: "
				    + _directory_dst + f.getName());
			fis.close();
			for (FTPFile ff : ftplpe.getFiles())
			{
			    if (f.getName().equals(ff.getName()))
			    {
				f.setLastModified(
					ff.getTimestamp().getTimeInMillis());
				break;
			    }
			}
		    }
		}

	    }
	}
	catch (IOException e)
	{
	    throw new TransfertException(current_file_transfert, null, e);
	}
	for (FTPFile ff : files)
	{
	    if (!ff.getName().equals(".") && !ff.getName().equals(".."))
	    {
		boolean found = false;
		for (File f : _directory_src.listFiles())
		{
		    if (f.getName().equals(ff.getName())
			    && f.isDirectory() == ff.isDirectory())
		    {
			found = true;
			break;
		    }
		}
		if (!found)
		{
		    if (ff.isDirectory())
		    {
			FileTools.deleteDirectory(ftpClient,
				_directory_dst + ff.getName());
		    }
		    else
		    {
			ftpClient.deleteFile(_directory_dst + ff.getName());
		    }
		}
	    }
	}
    }

    private static void updateFTP(FTPClient ftpClient, String _directory_dst, File _directory_src, File _current_file_transfert, File _current_directory_transfert) throws IOException, TransfertException
    {
	if (_current_directory_transfert == null
		|| _directory_src.equals(_current_directory_transfert))
	{
	    try
	    {
		updateFTP(ftpClient, _directory_dst, _directory_src,
			_current_file_transfert);
	    }
	    catch (TransfertException e)
	    {
		e.current_directory_transfert = _directory_src;
		throw e;
	    }
	}
    }

    private JavaProjectSource projectSource;

    private JavaProject project = null;

    private File temporaryDirectory = null;

    private File exportDirectory = null;

    private String ftpUrl = null;

    private int ftpPort = 0;

    private ArrayList<ExportProperties> exportsSenarios = null;

    boolean concernsRootProject = true;

    private final ArrayList<File> exportFiles = new ArrayList<>();

    public Exports()
    {
	super(null);
    }

    public boolean export() throws Exception
    {
	boolean res = subExport();
	return res;
    }

    @Override
    public void finalize()
    {
	if (temporaryDirectory.exists())
	    FileTools.deleteDirectory(temporaryDirectory);
    }

    public File getBuildFile()
    {
	return projectSource
		.getBuildFilePath(projectSource.getSourceDirectory());
    }

    public File getExportDirectory()
    {
	return exportDirectory;
    }

    public ArrayList<File> getExportedFiles()
    {
	return exportFiles;
    }

    public ArrayList<ExportProperties> getExportsSenarios()
    {
	return exportsSenarios;
    }

    public int getFtpPort()
    {
	return ftpPort;
    }

    public String getFtpUrl()
    {
	return ftpUrl;
    }

    public JavaProjectSource getProject()
    {
	return projectSource;
    }

    public File getTemporaryDirectory()
    {
	return temporaryDirectory;
    }

    File getTestSuiteDirectory()
    {
	return new File(getTemporaryDirectory(), "testsuitedirectory");
    }

    File getTmpAditionalFileDirectory()
    {
	return new File(getTmpStaticExportDirectory(), "additionalFiles");
    }

    File getTmpAllBinDirectory()
    {
	return new File(getTmpStaticExportDirectory(), "allbin");
    }

    File getTmpAllSourceDirectory()
    {
	return new File(getTmpStaticExportDirectory(), "allsource");
    }

    File getTmpBinDirectory()
    {
	return new File(getTmpStaticExportDirectory(), "bin");
    }

    File getTmpDocumentationDirectory()
    {
	return new File(getTmpStaticExportDirectory(), "doc");
    }

    File getTmpSourceDirectory()
    {
	return new File(getTmpStaticExportDirectory(), "source");
    }

    File getTmpStaticExportDirectory()
    {
	return new File(temporaryDirectory, "staticdata");
    }

    boolean globalExportDependencies()
    {
	for (ExportProperties ep : this.exportsSenarios)
	{
	    if (ep.include_dependancies)
		return true;
	}
	return false;
    }

    boolean globalExportDoc()
    {
	for (ExportProperties ep : this.exportsSenarios)
	{
	    if (ep.include_documentation)
		return true;
	}
	return false;
    }

    boolean globalExportSource()
    {
	for (ExportProperties ep : this.exportsSenarios)
	{
	    if (!ep.source_code_export_type
		    .equals(SourceCodeExportType.NO_SOURCE_CODE))
		return true;
	}
	return false;
    }

    private void sendToWebSite() throws IOException
    {
	System.out.println("Enter your login :");
	byte b[] = new byte[100];
	int l = System.in.read(b);
	String login = new String(b, 0, l);
	System.out.println("Enter your password :");
	l = System.in.read(b);
	String pwd = new String(b, 0, l);

	boolean reconnect = true;
	long time = System.currentTimeMillis();
	File current_file_transfert = null;
	File current_directory_transfert = null;

	while (reconnect)
	{
	    FTPClient ftpClient = new FTPClient();
	    ftpClient.connect(InetAddress.getByName(getFtpUrl()), getFtpPort());
	    try
	    {
		if (ftpClient.isConnected())
		{
		    System.out.println("Connected to server " + getFtpUrl()
			    + " (Port: " + getFtpPort() + ") !");
		    if (ftpClient.login(login, pwd))
		    {
			ftpClient.setFileTransferMode(FTP.BINARY_FILE_TYPE);
			System.out.println("Logged as " + login + " !");
			System.out.print("Updating...");

			FTPFile files[] = ftpClient.listFiles("");
			FTPFile downloadroot = null;
			FTPFile docroot = null;

			for (FTPFile f : files)
			{
			    if (f.getName().equals("downloads"))
			    {
				downloadroot = f;
				if (docroot != null)
				    break;
			    }
			    if (f.getName().equals("doc"))
			    {
				docroot = f;
				if (downloadroot != null)
				    break;
			    }
			}
			if (downloadroot == null)
			{
			    // ftpClient.changeWorkingDirectory("/");
			    if (!ftpClient.makeDirectory("downloads"))
			    {
				System.err.println(
					"Impossible to create directory: downloads");
			    }
			}
			if (docroot == null)
			{
			    // ftpClient.changeWorkingDirectory("/");
			    if (!ftpClient.makeDirectory("doc"))
			    {
				System.err.println(
					"Impossible to create directory: doc");
			    }
			}

			updateFTP(ftpClient, "downloads/", getExportDirectory(),
				current_file_transfert,
				current_directory_transfert);
			updateFTP(ftpClient, "doc/", new File("./doc"),
				current_file_transfert,
				current_directory_transfert);
			reconnect = false;

			System.out.println("[OK]");
			if (ftpClient.logout())
			{
			    System.out.println("Logged out from " + login
				    + " succesfull !");
			}
			else
			    System.err.println(
				    "Logged out from " + login + " FAILED !");
		    }
		    else
			System.err.println(
				"Impossible to log as " + login + " !");

		    ftpClient.disconnect();
		    System.out
			    .println("Disconnected from " + getFtpUrl() + " !");
		}
		else
		{
		    System.err.println(
			    "Impossible to get a connection to the server "
				    + getFtpUrl() + " !");
		}
		reconnect = false;
	    }
	    catch (TransfertException e)
	    {
		if (System.currentTimeMillis() - time > 30000)
		{
		    System.err.println(
			    "A problem occured during the transfert...");
		    System.out.println("Reconnection in progress...");
		    try
		    {
			ftpClient.disconnect();
		    }
		    catch (Exception e2)
		    {
		    }
		    current_file_transfert = e.current_file_transfert;
		    current_directory_transfert = e.current_directory_transfert;
		    time = System.currentTimeMillis();
		}
		else
		{
		    System.err.println(
			    "A problem occured during the transfert. Transfert aborded.");
		    throw e.original_exception;
		}
	    }
	}
    }

    public void setExportDirectory(File _exportDirectory)
    {
	exportDirectory = _exportDirectory;
    }

    public void setExportsSenarios(ArrayList<ExportProperties> _exportsSenarios)
    {
	exportsSenarios = _exportsSenarios;
    }

    public void setFtpPort(int _ftpPort)
    {
	ftpPort = _ftpPort;
    }

    public void setFtpUrl(String _ftpUrl)
    {
	ftpUrl = _ftpUrl;
    }

    public void setProject(JavaProjectSource _project)
    {
	projectSource = _project;
    }

    public void setTemporaryDirectory(File _temporaryDirectory)
    {
	temporaryDirectory = _temporaryDirectory;
    }

    public boolean subExport() throws Exception
    {
	try
	{
	    if (concernsRootProject)
		System.out.println("Incrementing build number...");
	    projectSource.getVersion().loadBuildNumber(getBuildFile());
	    projectSource.getVersion().incrementBuildNumber();
	    projectSource.getVersion().saveBuildNumber(getBuildFile());

	    if (concernsRootProject)
		System.out.println("Preparing source code...");

	    // prepare source code
	    finalize();
	    FileTools.checkFolder(temporaryDirectory);
	    FileTools.checkFolderRecursive(getTmpStaticExportDirectory());
	    FileTools.checkFolderRecursive(getTmpSourceDirectory());
	    projectSource.copySourceToFolder(getTmpSourceDirectory());
	    projectSource.exportLicences(getTmpSourceDirectory());
	    projectSource.createHTMLVersionFile(getTmpSourceDirectory());

	    // prepare source code of dependencies
	    File metainf = new File(getTmpAllSourceDirectory(), "META-INF");
	    if (globalExportDependencies() && globalExportSource())
	    {
		if (concernsRootProject)
		    System.out.println(
			    "Preparing source code of dependencies...");
		FileTools.checkFolderRecursive(getTmpAllSourceDirectory());

		for (BinaryDependency d : projectSource.getDependencies())
		{
		    d.getSourceCode()
			    .copySourceToFolder(getTmpAllSourceDirectory());
		    d.exportLicences(getTmpAllSourceDirectory());
		    if (metainf.exists())
		    {
			if (metainf.isDirectory())
			    FileTools.deleteDirectory(metainf);
			else
			    metainf.delete();
		    }
		}
		FileTools.copyFolderToFolder(getTmpSourceDirectory(),
			getTmpAllSourceDirectory(), false);
	    }
	    if (concernsRootProject)
		System.out.println("Compiling code source...");
	    // prepare executable code and its dependencies
	    FileTools.checkFolderRecursive(getTmpBinDirectory());
	    if (!projectSource.compileSource(getTmpSourceDirectory(),
		    getTmpBinDirectory()))
	    {
		System.err.println("\tCompilation FAILED !");
		return false;
	    }
	    project = new JavaProject(getTmpBinDirectory(), projectSource);
	    if (!concernsRootProject)
	    {
		File allTestsXMLDirectory = new File(getTmpBinDirectory(),
			"com/distrimind/util/export");
		FileTools.checkFolderRecursive(allTestsXMLDirectory);
		File allTestsXMLFile = new File(allTestsXMLDirectory,
			"TestSuite.xml");
		TestSuiteSource testSuiteSource = (TestSuiteSource) projectSource;
		testSuiteSource.getTestSuite().save(allTestsXMLFile);
	    }
	    if (globalExportDependencies())
	    {
		if (concernsRootProject)
		    System.out.println("preparing binaries of dependencies...");

		FileTools.checkFolderRecursive(getTmpAllBinDirectory());
		metainf = new File(getTmpAllBinDirectory(), "META-INF");
		for (BinaryDependency d : projectSource.getDependencies())
		{
		    d.copyBinToFolder(getTmpAllBinDirectory());
		    d.exportLicences(getTmpAllBinDirectory());
		    if (metainf.exists())
		    {
			if (metainf.isDirectory())
			    FileTools.deleteDirectory(metainf);
			else
			    metainf.delete();
		    }

		}
		FileTools.copyFolderToFolder(getTmpBinDirectory(),
			getTmpAllBinDirectory(), false);
		projectSource.exportLicences(getTmpAllBinDirectory());
		projectSource.createHTMLVersionFile(getTmpAllBinDirectory());
		metainf = new File(getTmpAllBinDirectory(), "META-INF");
		FileTools.checkFolderRecursive(metainf);
		projectSource
			.createManifestFile(new File(metainf, "MANIFEST.MF"));
	    }
	    if (concernsRootProject)
		System.out.println(
			"preparing licences/manifest/version files...");
	    projectSource.exportLicences(getTmpBinDirectory());
	    projectSource.createHTMLVersionFile(getTmpBinDirectory());
	    metainf = new File(getTmpBinDirectory(), "META-INF");
	    FileTools.checkFolderRecursive(metainf);
	    projectSource.createManifestFile(new File(metainf, "MANIFEST.MF"));

	    // prepare additional files
	    FileTools.checkFolderRecursive(getTmpAditionalFileDirectory());

	    if (concernsRootProject)
		System.out.println("preparing additional files...");

	    for (File f : projectSource
		    .getAdditionalFilesAndDirectoriesToExport())
	    {
		if (f.exists())
		{
		    if (f.isDirectory())
		    {
			FileTools.copyFolderToFolder(f,
				getTmpAditionalFileDirectory(), true);
		    }
		    else if (f.isFile())
		    {
			File d = new File(getTmpAditionalFileDirectory(),
				f.getName());
			FileTools.copy(f, d);
		    }
		}
		else
		    throw new IllegalArgumentException(
			    "Impossible to find the additional file "
				    + f.getAbsolutePath());
	    }
	    FileTools.copyFolderToFolder(getTmpAditionalFileDirectory(),
		    getTmpBinDirectory(), false);
	    if (globalExportDependencies())
		FileTools.copyFolderToFolder(getTmpAditionalFileDirectory(),
			getTmpAllBinDirectory(), false);

	    // prepare documentation
	    if (globalExportDoc())
	    {
		if (concernsRootProject)
		    System.out.println("compiling documentation...");

		FileTools.checkFolderRecursive(getTmpDocumentationDirectory());
		if (!projectSource.compileDoc(getTmpAllSourceDirectory(),
			getTmpDocumentationDirectory()))
		{
		    System.err.println("\tDoc compilation FAILED !");
		    return false;
		}
	    }

	    // compile and run tests
	    TestSuiteSource testSuiteSource = projectSource
		    .getTestSuiteSource();
	    boolean testOK = true;
	    if (testSuiteSource != null)
	    {
		if (concernsRootProject)
		{
		    if (concernsRootProject)
			System.out.println("Compiling tests...");

		    File tmpjar = new File(getTmpStaticExportDirectory(),
			    "tmpjar.jar");
		    try
		    {
			FileTools.zipDirectory(getTmpBinDirectory(), false,
				tmpjar);
			JarDependency dependency = new JarDependency(
				project.getName(), null,
				projectSource.getRepresentedPackage(),
				projectSource.getLicenses(), tmpjar, null,
				null);

			testSuiteSource.getDependencies().add(dependency);

			Exports testSuiteExports = new Exports();
			testSuiteExports.concernsRootProject = false;
			testSuiteExports
				.setExportDirectory(getExportDirectory());
			ArrayList<ExportProperties> exportsScenarios = new ArrayList<>();
			exportsScenarios.add(new ExportProperties(true,
				SourceCodeExportType.NO_SOURCE_CODE, false));
			testSuiteExports.setExportsSenarios(exportsScenarios);
			testSuiteExports.setProject(testSuiteSource);
			testSuiteExports
				.setTemporaryDirectory(getTestSuiteDirectory());
			testSuiteExports.export();

			byte b[] = new byte[100];
			System.out.println(
				"\n**************************\n\nRun test suite ? (y[es]|n[o])");

			System.in.read(b);
			if (b[0] == 'y' || b[0] == 'Y')
			{
			    testOK = Export.execExternalProcess("java -jar "
				    + testSuiteExports.getExportedFiles().get(0)
				    + "", null, true, true) == 0;
			    if (!testOK)
				testSuiteExports.getExportedFiles().get(0)
					.delete();
			    else
				System.out.println("\nTests exported to "
					+ testSuiteExports.getExportedFiles()
						.get(0));
			}
			else
			    System.out.println(
				    "\nTests exported to " + testSuiteExports
					    .getExportedFiles().get(0));
			testSuiteSource.getDependencies().remove(dependency);
		    }
		    finally
		    {
			tmpjar.delete();
		    }
		}
	    }

	    if (testOK)
	    {
		if (concernsRootProject)
		    System.out.println("Generate export files...");

		exportFiles.clear();
		for (ExportProperties ep : exportsSenarios)
		{
		    Export e = new Export(this, ep);
		    exportFiles.add(e.export());
		}

		if (concernsRootProject && getFtpUrl() != null)
		{
		    byte b[] = new byte[100];
		    System.out.println(
			    "\n**************************\n\nUpdating Web site ? (y[es]|n[o])");

		    System.in.read(b);
		    if (b[0] == 'y' || b[0] == 'Y')
		    {
			sendToWebSite();
		    }
		}
		if (concernsRootProject)
		    System.out.println("Export SUCCEEDED !");
		return true;
	    }
	    else
	    {
		if (concernsRootProject)
		    System.err.println("Export FAILED !");
		return false;
	    }

	}
	finally
	{
	    finalize();
	}
    }

}
