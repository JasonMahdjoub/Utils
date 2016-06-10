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

package com.distrimind.util.nitools;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.NetworkInterface;

import com.distrimind.util.OSValidator;

/**
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0 
 *
 */
class WindowsNITools extends NITools
{
    WindowsNITools()
    {
	
    }
    
    
    @Override
    public long getNetworkInterfaceSpeed(NetworkInterface _network_interface)
    {
	try
	{
	    if (_network_interface.isLoopback())
		return -1;
	    Process p=null;
	    //TODO check compatibility with Vista and Seven
	    if (OSValidator.getOSVersion().toLowerCase().contains("vista"))
		p=Runtime.getRuntime().exec("wmic NIC where \"NetEnabled=true\" get \"InterfaceIndex,Speed\"");
	    else
		p=Runtime.getRuntime().exec("wmic NIC where NetEnabled=true get InterfaceIndex,Speed");
	    
	    long res=-1;
	    try(InputStreamReader isr=new InputStreamReader(p.getInputStream()))
	    {
		try(BufferedReader input =new BufferedReader(isr))
		{
		    String line = null;
		    boolean first=true;
		    while (res==-1 && (line = input.readLine())!=null)
		    {
			if (first)
			{
			    first=false;
			    continue;
			}
			
			String split[]=line.split(" ");
			String index=null;
			int i=0;
			for (;i<split.length-1;i++)
			{
			    if (split[i].length()>0)
			    {
				index=split[i];
				break;
			    }
			}
			if (index!=null)
			{
			    try
			    {
				if (Integer.parseInt(split[0])==_network_interface.getIndex())
				{
				    for (int j=split.length-1;j>i;j--)
				    {
					if (split[j].length()!=0)
					{
					    res=readLong(split[j]);
					    break;
					}
				    }
				}
			    }
			    catch(Exception e)
			    {
				
			    }
			}
		    }
		}
	    }
	    p.destroy();
	    return res;
	}
	catch (Exception e)
	{
	    e.printStackTrace();
	    return -1;
	}
    }
    
    

}
