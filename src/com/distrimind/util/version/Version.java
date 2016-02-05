/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * MadKitGroup extension was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License Lesser as published by the Free
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

package com.distrimind.util.version;

import java.awt.BorderLayout;
import java.awt.Component;
import java.awt.FlowLayout;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Locale;

import javax.swing.JButton;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;

import com.distrimind.util.properties.XMLProperties;

/**
 * Represent the description of all versions of a software, including the current version
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see Description
 * @see Person
 * @see PersonDeveloper
 */
public class Version extends XMLProperties
{
    /**
     * 
     */
    private static final long serialVersionUID = -183708465780440306L;


    public enum Type
    {
	Stable,
	Alpha,
	Beta
    }
    
    
    private int m_major=0;
    private int m_minor=0;
    private int m_revision=0;
    private Type m_type=null;
    private int m_alpha_beta_version=0;
    
    private Date m_date_start_project=null;
    private Date m_date_end_project=null;
    private int m_build_number=1;
    
    private String m_program_name=null;
    
    ArrayList<Person> m_creators=new ArrayList<Person>();
    ArrayList<PersonDeveloper> m_developers=new ArrayList<PersonDeveloper>();
    ArrayList<Description> m_descriptions=new ArrayList<Description>();

    public Version()
    {
	this("", 0,0,0,Type.Alpha, 0, new Date(), new Date());
    }
    
    public Version(String _program_name, int _major, int _minor, int _revision, Type _type, int _alpha_beta_version, Date _date_start_project, Date _date_end_project)
    {
	super(null);
	m_major=_major;
	m_minor=_minor;
	m_revision=_revision;
	m_type=_type;
	m_alpha_beta_version=_alpha_beta_version;
	m_date_start_project=_date_start_project;
	m_date_end_project=_date_end_project;
	m_program_name=_program_name;
    }
    
    public int getMajor()
    {
	return m_major;
    }
    public int getMinor()
    {
	return m_minor;
    }
    public int getRevision()
    {
	return m_revision;
    }
    public Type getType()
    {
	return m_type;
    }
    
    public int getAlphaBetaVersion()
    {
	return m_alpha_beta_version;
    }
    
    public Date getProjectStartDate()
    {
	return m_date_start_project;
    }
    public Date getProjectEndDate()
    {
	return m_date_end_project;
    }
    
    public int getBuildNumber()
    {
	return m_build_number;
    }
    
    public void setBuildNumber(int _buil_number)
    {
	m_build_number=_buil_number;
    }
    
    public void addCreator(Person p)
    {
	m_creators.add(p);
    }
    public void addDeveloper(PersonDeveloper p)
    {
	m_developers.add(p);
    }
    public ArrayList<Person> getCreators()
    {
	return m_creators;
    }
    public ArrayList<PersonDeveloper> getDevelopers()
    {
	return m_developers;
    }
    
    public String getProgramName()
    {
	return m_program_name;
    }
    public void addDescription(Description _d)
    {
	m_descriptions.add(_d);
    }
    public ArrayList<Description> getDescriptions()
    {
	return m_descriptions;
    }
    
    public String toStringShort()
    {
	return Integer.toString(m_major)+"."+Integer.toString(m_minor)+"."+Integer.toString(m_revision)+" "+m_type+((m_type.equals(Type.Alpha) || m_type.equals(Type.Beta))?" "+Integer.toString(m_alpha_beta_version):"")+" (Build: "+Integer.toString(m_build_number)+")";
    }
    @Override
    public String toString()
    {
	StringBuffer s=new StringBuffer();
	s.append(m_program_name+" ");
	s.append(toStringShort());
	s.append("\n from "+DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date_start_project)+" to "+DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date_end_project));
	if (m_creators.size()>0)
	{
		s.append("\n\n");
		s.append("Creator(s) :");
		for (Person p : m_creators)
		{
		    s.append("\n\t");
		    s.append(p);
		}
	}
	if (m_developers.size()>0)
	{
		s.append("\n\n");
		s.append("Developer(s) :");
		for (PersonDeveloper p : m_developers)
		{
		    s.append("\n\t");
		    s.append(p);
		}
	}
	return s.toString();
    }
    public String getHTMLCode()
    {
	StringBuffer s=new StringBuffer();
	s.append("<html><table><tr><td><H1>");
	s.append(m_program_name+"</H1>");
	s.append(Integer.toString(m_major)+"."+Integer.toString(m_minor)+"."+Integer.toString(m_revision)+" "+m_type+((m_type.equals(Type.Alpha) || m_type.equals(Type.Beta))?" "+m_alpha_beta_version:"")+" (Build: "+m_build_number+")");
	s.append(" (from "+DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date_start_project)+" to "+DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(m_date_end_project)+")");
	s.append("</H1><BR>");
	if (m_creators.size()>0)
	{
	    	s.append("<BR><BR>");
		s.append("<H2>Creator(s) :</H2><ul>");
		for (Person p : m_creators)
		{
		    s.append("<li>");
		    s.append(p);
		    s.append("</li>");
		}
		s.append("</ul>");
	}
	if (m_developers.size()>0)
	{
	    	s.append("<BR><BR>");
		s.append("<H2>Developer(s) :</H2><ul>");
		for (PersonDeveloper p : m_developers)
		{
		    s.append("<li>");
		    s.append(p);
		    s.append("</li>");
		}
		s.append("</ul>");
	}
	if (m_descriptions.size()>0)
	{
	    s.append("<BR>");
	    for (Description d : m_descriptions)
	    {
		s.append("<BR>");
		s.append(d.getHTML());
	    }
	}
	
	s.append("</td></tr></table></html>");

	return s.toString();
    }
    
    private JFrame m_frame=null; 
    
    public JFrame getJFrame()
    {
	if (m_frame==null)
	{
        	final JFrame f=m_frame=new JFrame("About "+m_program_name);
        	f.add(new JPanel(new BorderLayout()));
        	JPanel ps=new JPanel(new FlowLayout(FlowLayout.CENTER));
        	JButton b=new JButton("Close");
        	b.addMouseListener(new MouseListener() {
        	    
        	    @Override
        	    public void mouseReleased(MouseEvent _e)
        	    {
        	    }
        	    
        	    @Override
        	    public void mousePressed(MouseEvent _e)
        	    {
        	    }
        	    
        	    @Override
        	    public void mouseExited(MouseEvent _e)
        	    {
        	    }
        	    
        	    @Override
        	    public void mouseEntered(MouseEvent _e)
        	    {
        	
        	    }
        	    
        	    @Override
        	    public void mouseClicked(MouseEvent _e)
        	    {
        		f.setVisible(false);
        		
        	    }
        	});
        	f.add(ps, BorderLayout.SOUTH);
        	ps.add(b);
        
        	JLabel j=new JLabel(this.getHTMLCode().toString());
        	j.setAlignmentY(Component.TOP_ALIGNMENT);
        	JScrollPane scrollpane=new JScrollPane(j);
        	scrollpane.getVerticalScrollBar().setUnitIncrement(15);
        	scrollpane.setAlignmentY(Component.TOP_ALIGNMENT);
        	f.add(scrollpane, BorderLayout.CENTER);
        	f.setSize(800, 600);
        	f.setResizable(false);
	}
	return m_frame;
    }
    public void screenVersion()
    {
	getJFrame().setVisible(true);
    }

    public void loadBuildNumber(File buildFile) throws NumberFormatException, IOException
    {
	//load build file
	try(FileInputStream is=new FileInputStream(buildFile))
	{
	    loadBuildNumber(is);
	}
    }

    public void loadBuildNumber(InputStream inputStream) throws NumberFormatException, IOException
    {
	try(InputStreamReader isr=new InputStreamReader(inputStream))
	{
	    try (BufferedReader bf=new BufferedReader(isr))
	    {
		setBuildNumber(Integer.parseInt(bf.readLine()));
	    }
	}
    }
    
    public void incrementBuildNumber()
    {
	this.m_build_number++;
    }
    
    public void saveBuildNumber(File buildFile) throws IOException
    {
	
	try(FileOutputStream fos=new FileOutputStream(buildFile))
	{
	    saveBuildNumber(fos);
	}
    }
    
    public void saveBuildNumber(OutputStream outputStream) throws NumberFormatException, IOException
    {
	try(OutputStreamWriter osw=new OutputStreamWriter(outputStream))
	{
	    osw.write(Integer.toString(getBuildNumber()));
	}
    }
   
    
}