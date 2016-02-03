/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
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

package com.distrimind.util.harddrive;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileWriter;
import java.io.InputStreamReader;
import java.util.HashMap;

/**
 *    
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see HardDriveDetect
 */
class WindowsHardDriveDetect extends HardDriveDetect
{

    private static class Identifier
    {
	public final String identifier;
	private final long timeToBeUpdated;
	
	public Identifier(String _identifier)
	{
	    identifier=_identifier;
	    timeToBeUpdated=System.currentTimeMillis()+duration_between_each_update;
	}
	
	public boolean hasToBeUpdated()
	{
	    return System.currentTimeMillis()-timeToBeUpdated>0;
	}
    }
    private HashMap<Character, Identifier> identifiers=new HashMap<>();
    private static final long duration_between_each_update=10000;
    
    private Identifier getIdentifier(char drive)
    {
	
	try 
	{
	    String result = "";
	    File file = File.createTempFile("realhowto",".vbs");
	    file.deleteOnExit();
	    try (FileWriter fw = new java.io.FileWriter(file))
	    {
		String vbs = "Set objFSO = CreateObject(\"Scripting.FileSystemObject\")\n"
	                  +"Set colDrives = objFSO.Drives\n"
	                  +"Set objDrive = colDrives.item(\"" + drive + "\")\n"
	                  +"Wscript.Echo objDrive.SerialNumber"; 
		fw.write(vbs);
	    }
	    Process p = Runtime.getRuntime().exec("cscript //NoLogo " + file.getPath());
	    try(InputStreamReader isr=new InputStreamReader(p.getInputStream()))
	    {
		try(BufferedReader input =new BufferedReader(isr))
		{
		    String line;
		    while ((line = input.readLine()) != null) {
			result += line;
		    }
		    
		}
	    }
	    p.destroy();
	    if (result.length()==0)
		return new Identifier(HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER);
	    return new Identifier(result.trim());
	}	
	catch(Exception e){
	    return new Identifier(HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER);
	}
    }
    
    
    @Override
    public String getHardDriveIdentifier(File _file)
    {
	synchronized(identifiers)
	{
	    try
	    {
		char drive=_file.getCanonicalPath().charAt(0);
		if (drive>='A' && drive<='Z')
		    drive=(char)(drive-('A'-'a'));
		if (!((drive>='a' && drive<='z') || (drive>='A' || drive<='Z')))
		    return HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
		Character Drive=new Character(drive);
		Identifier id=identifiers.get(Drive);
		if (id==null)
		{
		    id=getIdentifier(drive);
		    identifiers.put(Drive, id);
		}
		else if (id.hasToBeUpdated())
		{
		    id=getIdentifier(drive);
		    identifiers.put(Drive, id);
		}
		return id.identifier;
	    }
	    catch(Exception e)
	    {
		return HardDriveDetect.DEFAULT_HARD_DRIVE_IDENTIFIER;
	    }
	}
    }

}
