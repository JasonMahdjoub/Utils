/*
 * MadKitGroupExtension (created by Jason MAHDJOUB (jason.mahdjoub@free.fr)) Copyright (c)
 * 2012. Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of MadKitGroupExtension.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free
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

package com.distrimind.util.export;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetAddress;

import org.apache.commons.net.ftp.FTP;
import org.apache.commons.net.ftp.FTPClient;
import org.apache.commons.net.ftp.FTPFile;
import org.apache.commons.net.ftp.FTPListParseEngine;

import com.distrimind.util.FileTools;
import com.distrimind.util.export.Exports.ExportProperties;
import com.distrimind.util.version.Person;
import com.distrimind.util.version.PersonDeveloper;
import com.distrimind.util.version.Version;

public class Export
{
    private final Exports exports;
    private final ExportProperties exportScenario;
    
    private final static String possibleLicenseFileNames[]={"COPYING,LICENSE,COPYING.TXT, LICENSE.TXT,COPYING.txt, LICENSE.txt,copying,license,copying.txt, license.txt"};
    
    public Export(Exports _exports, ExportProperties _exportScenario) throws NumberFormatException
    {
	this.exports=_exports;
	this.exportScenario=_exportScenario;

    }
    
    private String getManifest()
    {
	String res="Manifest-Version: 1.0\n" +
	"Description: "+exports.getProject().getDescription()+"\n"+
	"Version: "+exports.getProject().getVersion().toStringShort()+"\n"+
	"Author: ";
	boolean first=true;
	for (PersonDeveloper p : exports.getProject().getVersion().getDevelopers())
	{
	    if (first)
		first=false;
	    else
		res+=", ";
	    res+=p.getFirstName()+" "+p.getName();
	}
	res+="\nBuilt-By: ";
	first=true;
	for (Person p : exports.getProject().getVersion().getCreators())
	{
	    if (first)
		first=false;
	    else
		res+=", ";
	    res+=p;
	}
	res+="\n";
	if (exports.getProject().getMainClass()!=null)
	    res+="Main-Class: "+exports.getProject().getMainClass()+"\n";
	return res;
    }
    private void createManifestFile(File f) throws IOException
    {
	FileWriter fw=new FileWriter(f);
	BufferedWriter b=new BufferedWriter(fw);
	b.write(getManifest());
	b.flush();
	b.close();
	fw.close();
    }
    
    private void createVersionFile(File f) throws IOException
    {
	FileWriter fw=new FileWriter(f);
	BufferedWriter b=new BufferedWriter(fw);
	b.write(exports.getProject().getVersion().getHTMLCode());
	b.flush();
	b.close();
	fw.close();
    }
    
    private String getJarFileName()
    {
	return exports.getProject().getName()+"-"+
		Integer.toString(exports.getProject().getVersion().getMajor())+
		"."+
		Integer.toString(exports.getProject().getVersion().getMinor())+
		"."+
		Integer.toString(exports.getProject().getVersion().getRevision())+"-"+
		exports.getProject().getVersion().getType()+
		((exports.getProject().getVersion().getType().equals(Version.Type.Beta) || exports.getProject().getVersion().getType().equals(Version.Type.Alpha))?Integer.toString(exports.getProject().getVersion().getAlphaBetaVersion()):"")+
		(exportScenario.include_dependancies?"_withDependencies":"")+
		(exportScenario.source_code_export_type.equals(Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE)?"_withSource":"")+
		".jar";
    }
    
    private String getZipFileName()
    {
	return exports.getProject().getName()+"-"+
		Integer.toString(exports.getProject().getVersion().getMajor())+
		"."+
		Integer.toString(exports.getProject().getVersion().getMinor())+
		"."+
		Integer.toString(exports.getProject().getVersion().getRevision())+"-"+
		exports.getProject().getVersion().getType()+
		((exports.getProject().getVersion().getType().equals(Version.Type.Beta) || exports.getProject().getVersion().getType().equals(Version.Type.Alpha))?Integer.toString(exports.getProject().getVersion().getAlphaBetaVersion()):"")+
		(exportScenario.include_dependancies?"_withDependencies":"")+
		(exportScenario.source_code_export_type.equals(Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE) || exportScenario.source_code_export_type.equals(Exports.SourceCodeExportType.SOURCE_CODE_IN_SEPERATE_FILE)?"_withSource":"")+
		(exportScenario.include_documentation?"_withDocumentation":"")+
		".zip";
    }
    
    private static void execExternalProcess(String command, final boolean screen_output, final boolean screen_erroutput) throws IOException, InterruptedException
    {
	Runtime runtime = Runtime.getRuntime();
	final Process process = runtime.exec(command);

	// Consommation de la sortie standard de l'application externe dans un Thread separe
	new Thread() {
		public void run() {
			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
				String line = "";
				try {
					while((line = reader.readLine()) != null) {
						if (screen_output)
						{
						    System.out.println(line);
						}
					}
				} finally {
					reader.close();
				}
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}.start();

	// Consommation de la sortie d'erreur de l'application externe dans un Thread separe
	new Thread() {
		public void run() {
			try {
				BufferedReader reader = new BufferedReader(new InputStreamReader(process.getErrorStream()));
				String line = "";
				try {
					while((line = reader.readLine()) != null) {
						if (screen_erroutput)
						{
						    System.out.println(line);
						}
					}
				} finally {
					reader.close();
				}
			} catch(IOException ioe) {
				ioe.printStackTrace();
			}
		}
	}.start();
	process.waitFor();
    }
    
    public void export() throws Exception
    {
	
	//prepare additional files
	if (exports.getTemporaryDirectory().exists())
	{
	    FileTools.deleteDirectory(exports.getTemporaryDirectory());
	}
	exports.getTemporaryDirectory().mkdir();
	File tmpexport=new File(exports.getTemporaryDirectory(), "export");
	tmpexport.mkdir();
	for (File f : exports.getProject().getAdditionalFilesAndDirectoriesToExport())
	{
	    if (f.exists())
	    {
		if (f.isDirectory())
		{
		    FileTools.copyFolderToFolder(f, tmpexport, true);
		}
		else
		{
		    File d=new File(tmpexport, f.getName());
		    FileTools.copy(f, d);
		}
	    }
	}
	
	
	//prepare dependencies
	File tmpbin=new File(exports.getTemporaryDirectory(), "bin");
	tmpbin.mkdir();
	File tmpsrc=null;
	if (exportScenario.source_code_export_type.equals(Exports.SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE))
	{
	    tmpsrc=tmpbin;
	}
	if (exportScenario.source_code_export_type.equals(Exports.SourceCodeExportType.SOURCE_CODE_IN_SEPERATE_FILE) || exportScenario.include_documentation)
	{
	    tmpsrc=new File(exports.getTemporaryDirectory(), "src");
	    tmpsrc.mkdir();
	}
	File tmpdoc=null;
	if (exportScenario.include_documentation)
	{
	    tmpdoc=new File(tmpexport, "doc");
	    tmpdoc.mkdir();
	}

	File metainf=new File(tmpbin, "META-INF");
	File metainfsource=new File(tmpsrc, "META-INF");
	
	if (exports.getProject().getDependencies()!=null)
	{
	    for (BinaryDependency d : exports.getProject().getDependencies())
	    {
		d.copyBinToFolder(tmpbin);
		if (metainf.exists())
		{
		    if (metainf.isDirectory())
			FileTools.deleteDirectory(metainf);
		    else
			metainf.delete();
		}
		renameOrCreateLicenseFileIfPossible(d, tmpbin);
		if (tmpsrc!=null)
		{
		    d.copySourceToFolder(tmpsrc);
		    renameOrCreateLicenseFileIfPossible(d, tmpsrc);
		    if (metainfsource.exists())
		    {
			if (metainfsource.isDirectory())
			    FileTools.deleteDirectory(metainfsource);
			else
			    metainfsource.delete();
		    }
		}
	    }
	}
	//prepare project
	exports.getProject().copyBinToFolder(tmpbin);
	if (tmpsrc!=null)
	    exports.getProject().copySourceToFolder(tmpsrc);
	
	//prepare documentation
	if (exportScenario.include_documentation)
	{
	    
	    String command="javadoc -protected -link http://docs.oracle.com/javase/"+exports.getJavaVersion().ordinal()+"/docs/api/ -sourcepath "+tmpsrc.getAbsolutePath()+" -d "+tmpdoc.getAbsolutePath()+
		    " -version -author -subpackages "+exports.getProject().getPackage().getName();

	    for (BinaryDependency d : exports.getProject().getDependencies())
		command+=" -subpackages "+d.getPackage().getName();
	    
	    System.out.println("\n*************************\n\n" +
	    		"Generating documentation\n" +
	    		"\n*************************\n\n");
	    execExternalProcess(command, true, true);
	}
	
	//prepare build file
	File exportBuildFile=exports.getProject().getBuildFilePath(tmpbin);
	exports.getProject().getVersion().saveBuildNumber(exportBuildFile);
	
	//prepare manifest file
	metainf.mkdir();
	createManifestFile(new File(metainf,"MANIFEST.MF"));
	//prepare version file
	createVersionFile(new File(tmpbin, exports.getProject().getName()+"_version.html"));
	//prepare license file
	if (exports.getProject().getLicense()!=null)
	{
	    exports.getProject().getLicense().generateLicenseFile(new File(tmpexport, "LICENSE"));
	    exports.getProject().getLicense().generateLicenseFile(new File(tmpexport, exports.getProject().getName()+"_LICENSE"));
	    
	    exports.getProject().getLicense().generateLicenseFile(new File(tmpbin, "LICENSE"));
	    exports.getProject().getLicense().generateLicenseFile(new File(tmpbin, exports.getProject().getName()+"_LICENSE"));
	    if (tmpsrc!=null && tmpsrc!=tmpbin)
	    {
		exports.getProject().getLicense().generateLicenseFile(new File(tmpsrc, "LICENSE"));
		exports.getProject().getLicense().generateLicenseFile(new File(tmpsrc, exports.getProject().getName()+"_LICENSE"));
	    }
	    for (BinaryDependency bd : exports.getProject().getDependencies())
	    {
		if (bd.getLicense()!=null)
		    bd.getLicense().generateLicenseFile(new File(tmpexport, bd.getName()+"_LICENSE"));    
	    }
	}
	
	//generate binary/source jar file
	File tmpjarfile=new File(tmpexport, this.getJarFileName());
	FileTools.zipDirectory(tmpbin, false, tmpjarfile);
	
	//generate source zip file
	boolean final_export_is_zip=exportScenario.include_documentation;
	if (tmpsrc!=null && tmpsrc!=tmpbin)
	{
	    final_export_is_zip=true;
	    //generate source file
	    File tmpsourcefile=new File(tmpexport, "src.zip");
	    FileTools.zipDirectory(tmpsrc, false, tmpsourcefile);    
	}
	
	//export final file
	if (!exports.getExportDirectory().exists())
	    exports.getExportDirectory().mkdir();
	if (final_export_is_zip)
	{
	    FileTools.zipDirectory(tmpexport, false, new File(exports.getExportDirectory(), getZipFileName()));
	}
	else
	{
	    FileTools.move(tmpjarfile, new File(exports.getExportDirectory(), getJarFileName()));
	}
	
	//remove temporary files
	FileTools.deleteDirectory(exports.getTemporaryDirectory());
	
	//update website
	if (exports.getFtpUrl()!=null)
	{
	    byte b[]=new byte[100];
	    System.out.println("\n**************************\n\nUpdating Web site ? (y[es]|n[o])");
	
	    System.in.read(b);
	    if (b[0]=='y' || b[0]=='Y')
	    {
		sendToWebSite();
	    }
	}
	
    }
    
    private void renameOrCreateLicenseFileIfPossible(BinaryDependency d, File directory) throws IOException
    {
	File license_file=new File(directory, d.getName()+"_LICENSE");
	for (String s : possibleLicenseFileNames)
	{
	    File f=new File(directory, s);
	    
	    if (f.exists() && f.isFile())
	    {
		
		if (d.getLicense()!=null)
		{
		    f.delete();
		    break;
		}
		else
		{
		    f.renameTo(license_file);
		    return;
		}
	    }
	}
	if (d.getLicense()!=null)
	    d.getLicense().generateLicenseFile(license_file);

    }
    
    /*public String getMadKitClassPath()
    {
	return "lib/madkit-5.0.0.16.jar";
    }*/
    
    private static void updateFTP(FTPClient ftpClient, String _directory_dst, File _directory_src, File _current_file_transfert, File _current_directory_transfert) throws IOException, TransfertException
    {
	if (_current_directory_transfert==null || _directory_src.equals(_current_directory_transfert))
	{
	    try
	    {
		updateFTP(ftpClient, _directory_dst, _directory_src, _current_file_transfert);
	    }
	    catch(TransfertException e)
	    {
		e.current_directory_transfert=_directory_src;
		throw e;
	    }
	}
    }
    
    private static void updateFTP(FTPClient ftpClient, String _directory_dst, File _directory_src, File _current_file_transfert) throws IOException, TransfertException
    {
	ftpClient.changeWorkingDirectory("./");
	FTPListParseEngine ftplpe=ftpClient.initiateListParsing(_directory_dst);
	FTPFile files[]=ftplpe.getFiles();
	
	File current_file_transfert=_current_file_transfert;
	
	try
	{
	    for (File f : _directory_src.listFiles())
	    {
		if (f.isDirectory())
		{
		    if (!f.getName().equals("./") && !f.getName().equals("../"))
		    {
			if (_current_file_transfert!=null)
			{
			    if (!_current_file_transfert.getCanonicalPath().startsWith(f.getCanonicalPath()))
				continue;
			    else
				_current_file_transfert=null;
			}
			boolean found=false;
			for (FTPFile ff : files)
			{
			    if (f.getName().equals(ff.getName()))
			    {	
				if (ff.isFile())
				{ 
				    ftpClient.deleteFile(_directory_dst+ff.getName());
				}
				else
				    found=true;
				break;
			    }
			}
		
			if (!found)
			{
			    ftpClient.changeWorkingDirectory("./");
			    if (!ftpClient.makeDirectory(_directory_dst+f.getName()+"/"))
				System.err.println("Impossible to create directory "+_directory_dst+f.getName()+"/");
			}
			updateFTP(ftpClient, _directory_dst+f.getName()+"/", f, _current_file_transfert);
		    }
		}
		else
		{
		    if (_current_file_transfert!=null)
		    {
			if (!_current_file_transfert.equals(f.getCanonicalPath()))
			    continue;
			else
			    _current_file_transfert=null;
		    }
		    current_file_transfert=_current_file_transfert;
		    FTPFile found=null;
		    for (FTPFile ff : files)
		    {
			if (f.getName().equals(ff.getName()))
			{
			    if (ff.isDirectory())
			    {
				FileTools.deleteDirectory(ftpClient, _directory_dst+ff.getName());
			    }
			    else
				found=ff;
			    break;
			}
		    }
		    if (found==null || (found.getTimestamp().getTimeInMillis()-f.lastModified())<0 || found.getSize()!=f.length())
		    {
			FileInputStream fis=new FileInputStream(f);
			ftpClient.setFileType(FTP.BINARY_FILE_TYPE);
			if (!ftpClient.storeFile(_directory_dst+f.getName(), fis))
			    System.err.println("Impossible to send file: "+_directory_dst+f.getName());
			fis.close();
			for (FTPFile ff : ftplpe.getFiles())
			{
			    if (f.getName().equals(ff.getName()))
			    {
				f.setLastModified(ff.getTimestamp().getTimeInMillis());
				break;
			    }
			}
		    }
		}
		
	    }
	}
	catch(IOException e)
	{
	    throw new TransfertException(current_file_transfert, null, e);
	}
	for (FTPFile ff : files)
	{
	    if (!ff.getName().equals(".") && !ff.getName().equals(".."))
	    {
		boolean found=false;
		for (File f : _directory_src.listFiles())
		{
		    if (f.getName().equals(ff.getName()) && f.isDirectory()==ff.isDirectory())
		    {
			found=true;
			break;
		    }
		}
		if (!found)
		{
		    if (ff.isDirectory())
		    {
			FileTools.deleteDirectory(ftpClient, _directory_dst+ff.getName());
		    }
		    else
		    {
			ftpClient.deleteFile(_directory_dst+ff.getName());
		    }
		}
	    }
	}
    }
    
    
    private void sendToWebSite() throws IOException
    {
	System.out.println("Enter your login :");
	byte b[]=new byte[100];
	int l=System.in.read(b);
	String login=new String(b, 0, l);
	System.out.println("Enter your password :");
	l=System.in.read(b);
	String pwd=new String(b, 0, l);
	
	boolean reconnect=true;
	long time=System.currentTimeMillis();
	File current_file_transfert=null;
	File current_directory_transfert=null;
	
	while (reconnect)
	{
	    FTPClient ftpClient=new FTPClient();
	    ftpClient.connect(InetAddress.getByName(exports.getFtpUrl()), exports.getFtpPort());
	    try
	    {
		if (ftpClient.isConnected())
		{
		    System.out.println("Connected to server "+exports.getFtpUrl()+" (Port: "+exports.getFtpPort()+") !");
		    if(ftpClient.login(login, pwd))
		    {
			ftpClient.setFileTransferMode(FTP.BINARY_FILE_TYPE);
			System.out.println("Logged as "+login+" !");
			System.out.print("Updating...");
		    
		
			FTPFile files[]=ftpClient.listFiles("");
			FTPFile downloadroot=null;
			FTPFile docroot=null;
		
			for (FTPFile f : files)
			{
			    if (f.getName().equals("downloads"))
			    {
				downloadroot=f;
				if (docroot!=null)
				    break;
			    }
			    if (f.getName().equals("doc"))
			    {
				docroot=f;
				if (downloadroot!=null)
				    break;
			    }
			}
			if (downloadroot==null)
			{
			    //ftpClient.changeWorkingDirectory("/");
			    if (!ftpClient.makeDirectory("downloads"))
			    {
				System.err.println("Impossible to create directory: downloads");
			    }
			}
			if (docroot==null)
			{
			    //ftpClient.changeWorkingDirectory("/");
			    if (!ftpClient.makeDirectory("doc"))
			    {
				System.err.println("Impossible to create directory: doc");
			    }
			}
		
			updateFTP(ftpClient, "downloads/", exports.getExportDirectory(), current_file_transfert, current_directory_transfert);
			updateFTP(ftpClient, "doc/", new File("./doc"), current_file_transfert, current_directory_transfert);
			reconnect=false;
			
			System.out.println("[OK]");
			if (ftpClient.logout())
			{
			    System.out.println("Logged out from "+login+" succesfull !");		    
			}
			else
			    System.err.println("Logged out from "+login+" FAILED !");
		    }	
		    else
			System.err.println("Impossible to log as "+login+" !");
	    
	    
		    ftpClient.disconnect();
		    System.out.println("Disconnected from "+exports.getFtpUrl()+" !");
		}
		else
		{
		    System.err.println("Impossible to get a connection to the server "+exports.getFtpUrl()+" !");
		}
		reconnect=false;
	    }
	    catch(TransfertException e)
	    {
		if (System.currentTimeMillis()-time>30000)
		{
		    System.err.println("A problem occured during the transfert...");
		    System.out.println("Reconnection in progress...");
		    try
		    {
			ftpClient.disconnect();
		    }
		    catch(Exception e2)
		    {
		    }
		    current_file_transfert=e.current_file_transfert;
		    current_directory_transfert=e.current_directory_transfert;
		    time=System.currentTimeMillis();
		}
		else
		{
		    System.err.println("A problem occured during the transfert. Transfert aborded.");
		    throw e.original_exception;
		}
	    }
	}
    }
    
    
    
    
}
