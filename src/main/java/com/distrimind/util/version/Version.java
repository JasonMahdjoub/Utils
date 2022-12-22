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

package com.distrimind.util.version;

import java.io.*;
import java.text.DateFormat;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.*;

/**
 * Represent the description of all versions of a software, including the
 * current version
 * 
 * @author Jason Mahdjoub
 * @version 1.3
 * @since Utils 1.0
 * @see Description
 * @see Person
 * @see PersonDeveloper
 */
@SuppressWarnings({"FieldMayBeFinal"})
public class Version extends AbstractVersion<Version> {
	public enum Type {
		ALPHA, BETA, RELEASE_CANDIDATE, STABLE
	}


	private Date projectStartDate;

	private int buildNumber = 1;

	private String programName;

	private String shortProgramName;

	final ArrayList<Person> creators = new ArrayList<>();

	final TreeSet<PersonDeveloper> developers = new TreeSet<>();

	final TreeSet<Description> descriptions = new TreeSet<>();

	//private JFrame frame = null;

	protected Version() {
		this("", "", (short)0, (short)0, (short)0, Type.ALPHA, (short)0, new Date(), new Date());
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof Version) {
			Version d = (Version) o;

			return compareTo(d)==0 &&
					programName.equals(d.programName) &&
					shortProgramName.equals(d.shortProgramName) &&
					buildNumber==d.buildNumber;
		}
		return false;
	}
	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date_start_project the start project date (format YYYY-MM-DD, i.e. 2020-10-28)
	 * @param _date_end_project the end project date (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	public Version(String _program_name, String shortProgramName, int _major, int _minor, int _revision, Type _type,
				   int _alpha_beta_version, String _date_start_project, String _date_end_project) {
		this(_program_name, shortProgramName, toShort(_major), toShort(_minor), toShort(_revision), _type, toShort(_alpha_beta_version), _date_start_project, _date_end_project);
	}

	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date_start_project the start project date (format YYYY-MM-DD, i.e. 2020-10-28)
	 * @param _date_end_project the end project date (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	public Version(String _program_name, String shortProgramName, short _major, short _minor, short _revision, Type _type,
				   short _alpha_beta_version, String _date_start_project, String _date_end_project) {
		this(_program_name, shortProgramName, _major, _minor, _revision, _type, _alpha_beta_version, parse(_date_start_project), parse(_date_end_project));
	}
	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date_start_project the start project date
	 * @param _date_end_project the end project date
	 */
	public Version(String _program_name, String shortProgramName, int _major, int _minor, int _revision, Type _type,
				   int _alpha_beta_version, Calendar _date_start_project, Calendar _date_end_project) {
		this(_program_name, shortProgramName, toShort(_major), toShort(_minor), toShort(_revision), _type, toShort(_alpha_beta_version), _date_start_project, _date_end_project);
	}
	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date_start_project the start project date
	 * @param _date_end_project the end project date
	 */
	public Version(String _program_name, String shortProgramName, short _major, short _minor, short _revision, Type _type,
				   short _alpha_beta_version, Calendar _date_start_project, Calendar _date_end_project) {
		this(_program_name, shortProgramName, _major, _minor, _revision, _type, _alpha_beta_version, _date_start_project.getTime(), _date_end_project.getTime());
	}
	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _date_start_project the start project date (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	public Version(String _program_name, String shortProgramName, String _date_start_project) {
		this(_program_name, shortProgramName, parse(_date_start_project));
	}

	static Date parse(String date)
	{
		return Date.from(Instant.from(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss").withZone(ZoneId.systemDefault())
				.parse(date+" 00:00:00")));
	}

	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _date_start_project the start project date
	 */
	public Version(String _program_name, String shortProgramName, Calendar _date_start_project) {
		this(_program_name, shortProgramName, _date_start_project.getTime());
	}
	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _date_start_project the start project date
	 */
	public Version(String _program_name, String shortProgramName, Date _date_start_project) {
		this(_program_name, shortProgramName, (short)0, (short)0, (short)0, Type.ALPHA, (short)0, _date_start_project, new Date());
	}
	/**
	 *
	 * @param _program_name the program name
	 * @param shortProgramName the short program name
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date_start_project the start project date
	 * @param _date_end_project the end project date
	 */
	public Version(String _program_name, String shortProgramName, short _major, short _minor, short _revision, Type _type,
				   short _alpha_beta_version, Date _date_start_project, Date _date_end_project) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date_end_project);
		if (_program_name == null)
			throw new NullPointerException("_program_name");
		if (shortProgramName == null)
			throw new NullPointerException("shortProgramName");
		if (_date_start_project == null)
			throw new NullPointerException("_date_start_project");

		projectStartDate = _date_start_project;
		this.programName = _program_name;
		this.shortProgramName = shortProgramName;
	}

	public Version addCreator(Person p) {
		if (p == null)
			throw new NullPointerException("p");
		creators.add(p);
		return this;
	}

	public Version addDescription(Description d) {
		if (d == null)
			throw new NullPointerException("d");
		descriptions.add(d);
		d=descriptions.last();
		major=d.getMajor();
		minor=d.getMinor();
		revision=d.getRevision();
		type=d.getType();
		date=d.getDate();
		alphaBetaRCVersion =d.getAlphaBetaRCVersion();
		return this;
	}

	public Version addDeveloper(PersonDeveloper p) {
		if (p == null)
			throw new NullPointerException("p");
		developers.add(p);
		return this;
	}



	public int getBuildNumber() {
		return buildNumber;
	}

	public ArrayList<Person> getCreators() {
		return creators;
	}

	public TreeSet<Description> getDescriptions() {
		return descriptions;
	}

	public TreeSet<PersonDeveloper> getDevelopers() {
		return developers;
	}

	public String getFileHeadName() {
		return getShortProgramName().replace(" ", "") + "-" + getFileHeadVersion();
	}

	public String getFileHeadVersion() {
		return Integer.toString(getMajor()) + "." + Integer.toString(getMinor()) + "." + Integer.toString(getRevision())
				+ "-" + getType()
				+ ((getType().equals(Version.Type.BETA) || getType().equals(Version.Type.ALPHA))
						? Integer.toString(getAlphaBetaRCVersion())
						: "");
	}


	public String getHTMLCode() {
		StringBuilder s = new StringBuilder();
		s.append("<html><table><tr><td><H1>");
		s.append(programName).append("</H1>");
		appendVersionPart(s, buildNumber);
		s.append(" (from ").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(projectStartDate)).append(" to ").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(getProjectEndDate())).append(")");
		s.append("</H1><BR>");
		if (creators.size() > 0) {
			s.append("<BR><BR>");
			s.append("<H2>Creator(s) :</H2><ul>");
			for (Person p : creators) {
				s.append("<li>");
				s.append(p);
				s.append("</li>");
			}
			s.append("</ul>");
		}
		if (developers.size() > 0) {
			s.append("<BR><BR>");
			s.append("<H2>Developer(s) :</H2><ul>");
			for (PersonDeveloper p : developers) {
				s.append("<li>");
				s.append(p);
				s.append("</li>");
			}
			s.append("</ul>");
		}
		if (descriptions.size() > 0) {
			s.append("<BR>");
			for (Iterator<Description> it=descriptions.descendingIterator();it.hasNext();)
			{
				s.append("<BR>");
				s.append(it.next().getHTML());
			}
		}

		s.append("</td></tr></table></html>");

		return s.toString();
	}
	public String getMarkdownCode() {
		StringBuilder s = new StringBuilder();
		
		s.append(programName);
		s.append("\n");
		int nb= programName.length();
		for (int i=0;i<nb;i++)
			s.append("=");
		s.append("\n");
		appendVersionPart(s, buildNumber);
		s.append(" (from ").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(projectStartDate)).append(" to ").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(getProjectEndDate())).append(")");
		s.append("\n");
		
		
		
		if (creators.size() > 0) {
			s.append("\n");
			s.append("# Creator(s):");
			s.append("\n");
			for (Person p : creators) {
				s.append("* ");
				s.append(p);
				s.append("\n");
			}
			s.append("\n");
		}
		if (developers.size() > 0) {
			s.append("# Developer(s):");
			s.append("\n");
			for (PersonDeveloper p : developers) {
				s.append("* ");
				s.append(p);
				s.append("\n");
			}
			s.append("\n");
		}
		s.append("# Changes:");
		s.append("\n");
		if (descriptions.size() > 0) {
			for (Iterator<Description> it=descriptions.descendingIterator();it.hasNext();)
			{
				s.append("\n");
				s.append(it.next().getMarkdownCode());
			}
		}
		s.append("\n");

		return s.toString();
	}
	/*public JFrame getJFrame() {
		if (frame == null) {
			final JFrame f = frame = new JFrame("About " + programName);
			f.add(new JPanel(new BorderLayout()));
			JPanel ps = new JPanel(new FlowLayout(FlowLayout.CENTER));
			JButton b = new JButton("Close");
			b.addMouseListener(new MouseListener() {

				@Override
				public void mouseClicked(MouseEvent _e) {
					f.setVisible(false);

				}

				@Override
				public void mouseEntered(MouseEvent _e) {

				}

				@Override
				public void mouseExited(MouseEvent _e) {
				}

				@Override
				public void mousePressed(MouseEvent _e) {
				}

				@Override
				public void mouseReleased(MouseEvent _e) {
				}
			});
			f.add(ps, BorderLayout.SOUTH);
			ps.add(b);

			JLabel j = new JLabel(this.getHTMLCode());
			j.setAlignmentY(Component.TOP_ALIGNMENT);
			JScrollPane scrollPane = new JScrollPane(j);
			scrollPane.getVerticalScrollBar().setUnitIncrement(15);
			scrollPane.setAlignmentY(Component.TOP_ALIGNMENT);
			f.add(scrollPane, BorderLayout.CENTER);
			f.setSize(800, 600);
			f.setResizable(false);
		}
		return frame;
	}*/

	public String getProgramName() {
		return programName;
	}

	public Date getProjectStartDate() {
		return projectStartDate;
	}

	public Date getProjectEndDate()
	{
		return getDate();
	}


	public String getShortProgramName() {
		return shortProgramName;
	}


	public void incrementBuildNumber() {
		this.buildNumber++;
	}

	public void loadBuildNumber(File buildFile) throws NumberFormatException, IOException {
		// load build file
		try (FileInputStream is = new FileInputStream(buildFile)) {
			loadBuildNumber(is);
		}
	}

	public void loadBuildNumber(InputStream inputStream) throws NumberFormatException, IOException {
		try (InputStreamReader isr = new InputStreamReader(inputStream)) {
			try (BufferedReader bf = new BufferedReader(isr)) {
				setBuildNumber(Integer.parseInt(bf.readLine()));
			}
		}
	}

	public void saveBuildNumber(File buildFile) throws IOException {
		if (buildFile == null)
			throw new NullPointerException("buildFile");

		try (FileOutputStream fos = new FileOutputStream(buildFile)) {
			saveBuildNumber(fos);
		}
	}

	public void saveBuildNumber(OutputStream outputStream) throws NumberFormatException, IOException {
		try (OutputStreamWriter osw = new OutputStreamWriter(outputStream)) {
			osw.write(Integer.toString(getBuildNumber()));
		}
	}

	/*public void screenVersion() {
		getJFrame().setVisible(true);
	}*/

	public void setBuildNumber(int _build_number) {
		buildNumber = _build_number;
	}

	@Override
	public String toString() {
		StringBuilder s = new StringBuilder();
		s.append(programName).append(" ");
		s.append(toStringShort());
		s.append("\n from ").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(projectStartDate)).append(" to ").append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(getProjectEndDate()));
		if (creators.size() > 0) {
			s.append("\n\n");
			s.append("Creator(s) :");
			for (Person p : creators) {
				s.append("\n\t");
				s.append(p);
			}
		}
		if (developers.size() > 0) {
			s.append("\n\n");
			s.append("Developer(s) :");
			for (PersonDeveloper p : developers) {
				s.append("\n\t");
				s.append(p);
			}
		}
		return s.toString();
	}

	public String toStringShort() {
		StringBuilder s=new StringBuilder();
		appendVersionPart(s, buildNumber);
		return s.toString();
	}
	/*public static void main(String args[])
	{
		Utils.VERSION.screenVersion();
	}*/
}