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
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;

import com.distrimind.util.FileTools;
import com.distrimind.util.export.Exports.ExportProperties;
import com.distrimind.util.export.Exports.SourceCodeExportType;
import com.distrimind.util.version.Version;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.3
 * @since Utils 1.0
 */
public class Export
{
    private final Exports exports;
    private final ExportProperties exportScenario;
    
    
    
    public Export(Exports _exports, ExportProperties _exportScenario) throws NumberFormatException
    {
	this.exports=_exports;
	this.exportScenario=_exportScenario;

    }
    
    /*private String getManifest()
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
    }*/
    
    private String getJarFileName()
    {
	return exports.getProject().getProjectName()+"-"+
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
	return exports.getProject().getProjectName()+"-"+
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
    
    static int execExternalProcess(String command, File working_directory, final boolean screen_output, final boolean screen_erroutput) throws IOException, InterruptedException
    {
	Runtime runtime = Runtime.getRuntime();
	Process p=null;
	if (working_directory==null || !working_directory.exists() || !working_directory.isDirectory())
	    p = runtime.exec(command);
	else
	    p = runtime.exec(command, null, working_directory);
	final Process process = p; 
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
						    System.err.println(line);
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
	return process.exitValue();
    }
    
    public File export() throws Exception
    {
	File tmpexportZIP=new File(exports.getTemporaryDirectory(), "exportZIP");
	File tmpexportJAR=new File(exports.getTemporaryDirectory(), "exportJAR");
	if (tmpexportZIP.exists())
	    FileTools.deleteDirectory(tmpexportZIP);
	FileTools.checkFolderRecursive(tmpexportZIP);
	if (tmpexportJAR.exists())
	    FileTools.deleteDirectory(tmpexportJAR);
	FileTools.checkFolderRecursive(tmpexportJAR);
	
	
	if (exportScenario.source_code_export_type.equals(SourceCodeExportType.SOURCE_CODE_IN_JAR_FILE))
	{
	    if (exportScenario.include_dependancies)
		FileTools.copyFolderToFolder(exports.getTmpAllSourceDirectory(), tmpexportJAR, false);
	    else
		FileTools.copyFolderToFolder(exports.getTmpSourceDirectory(), tmpexportJAR, false);	
	}
	if (exportScenario.include_dependancies)
	{
	    FileTools.copyFolderToFolder(exports.getTmpAllBinDirectory(), tmpexportJAR, false);
	}
	else
	{
	    FileTools.copyFolderToFolder(exports.getTmpBinDirectory(), tmpexportJAR, false);
	}
	//generate binary/source jar file
	File tmpjarfile=new File(tmpexportZIP, this.getJarFileName());
	FileTools.zipDirectory(tmpexportJAR, false, tmpjarfile);
	File finalExportFile=null;
	if (exportScenario.include_documentation || exportScenario.source_code_export_type.equals(SourceCodeExportType.SOURCE_CODE_IN_SEPERATE_FILE))
	{
	    if (exportScenario.source_code_export_type.equals(SourceCodeExportType.SOURCE_CODE_IN_SEPERATE_FILE))
	    {
		File tmpsrcfile=new File(tmpexportZIP, "src.zip");
		if (exportScenario.include_dependancies)
		    FileTools.zipDirectory(exports.getTmpAllSourceDirectory(), false, tmpsrcfile);
		else
		    FileTools.zipDirectory(exports.getTmpSourceDirectory(), false, tmpsrcfile);
	    }
	    if (exportScenario.include_documentation)
	    {
		FileTools.copyFolderToFolder(exports.getTmpDocumentationDirectory(), tmpexportZIP, true);
	    }
	    finalExportFile=new File(exports.getExportDirectory(), getZipFileName());
	    FileTools.zipDirectory(tmpexportZIP, false, finalExportFile);
	}
	else
	{
	    finalExportFile=new File(exports.getExportDirectory(), getJarFileName());
	    FileTools.move(tmpjarfile, finalExportFile);
	}
	
	FileTools.deleteDirectory(tmpexportJAR);
	FileTools.deleteDirectory(tmpexportZIP);
	return finalExportFile;
    }
    
    /*private void renameOrCreateLicenseFileIfPossible(BinaryDependency d, File directory) throws IOException
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

    }*/
    
    /*public String getMadKitClassPath()
    {
	return "lib/madkit-5.0.0.16.jar";
    }*/
    
    
    
    
    
    
    
    
}
