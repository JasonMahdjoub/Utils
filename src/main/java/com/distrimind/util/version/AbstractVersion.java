package com.distrimind.util.version;

import com.distrimind.util.properties.MultiFormatProperties;

import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

/**
 * @author Jason Mahdjoub
 * @version 1.1
 * @since MaDKitLanEdition 5.6.0
 */
@SuppressWarnings("FieldMayBeFinal")
public abstract class AbstractVersion<V extends AbstractVersion<V>> extends MultiFormatProperties implements Comparable<V> {

	protected short major;

	protected short minor;

	protected short revision;

	protected Version.Type type;

	protected short alphaBetaRCVersion;

	protected Date date;

	protected AbstractVersion() {
		this((short)0, (short)0, (short)0, Version.Type.ALPHA, (short)0, new Date());
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	protected AbstractVersion(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, String _date) {
		this(toShort(_major), toShort(_minor), toShort(_revision), _type, toShort(_alpha_beta_version), _date);
	}
	protected static short toShort(int value)
	{
		if (value<Short.MIN_VALUE || value>Short.MAX_VALUE)
			throw new IllegalArgumentException();
		return (short)value;
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	protected AbstractVersion(int _major, int _minor, int _revision, Version.Type _type, short _alpha_beta_version, String _date) {
		this(toShort(_major), toShort(_minor), toShort(_revision), _type, _alpha_beta_version, _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	protected AbstractVersion(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, String _date) {
		this(_major, _minor, _revision, _type, _alpha_beta_version, Version.parse(_date));
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	protected AbstractVersion(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, Calendar _date) {
		this(toShort(_major), toShort(_minor), toShort(_revision), _type, toShort(_alpha_beta_version), _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	protected AbstractVersion(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, Calendar _date) {
		this(_major, _minor, _revision, _type, _alpha_beta_version, _date.getTime());
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	protected AbstractVersion(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, Date _date) {
		this(toShort(_major), toShort(_minor), toShort(_revision), _type, toShort(_alpha_beta_version), _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	protected AbstractVersion(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, Date _date) {
		super(null);
		if (_date == null)
			throw new NullPointerException("_date");
		if (_type==null)
			throw new NullPointerException();
		major = _major;
		minor = _minor;
		revision = _revision;
		type = _type;
		if (_type== Version.Type.STABLE)
			alphaBetaRCVersion =0;
		else
			alphaBetaRCVersion = _alpha_beta_version;
		date = _date;
	}

	@Override
	public int hashCode()
	{
		return major <<24+ minor <<16+ revision <<8+ (type== Version.Type.STABLE ?0: alphaBetaRCVersion);
	}


	@Override
	public abstract boolean equals(Object o) ;

	public short getAlphaBetaRCVersion() {
		return alphaBetaRCVersion;
	}

	public Date getDate() {
		return date;
	}

	protected void appendVersionPart(StringBuilder s, Integer buildNumber)
	{
		s.append(Integer.toString(getMajor()))
				.append(".")
				.append(Integer.toString(getMinor()))
				.append(".")
				.append(Integer.toString(getRevision()))
				.append(" ")
				.append(getType())
				.append(getType().equals(Version.Type.STABLE) ? "":" " + getAlphaBetaRCVersion());
		if (buildNumber!=null)
			s.append(" (Build: ").append(buildNumber).append(")");
	}

	protected StringBuilder getHTMLVersionPart() {
		StringBuilder s = new StringBuilder();
		s.append("<BR><H2>");
		appendVersionPart(s, null);
		s.append(" (")
				.append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(date))
				.append(")</H2>");

		return s;
	}

	protected StringBuilder getMarkdownVersionPartCode() {
		StringBuilder s = new StringBuilder();
		s.append("\n");
		s.append("### ");
		appendVersionPart(s, null);
		s.append(" (")
				.append(DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(date))
				.append(")");
		s.append("\n");
		return s;
	}


	public short getMajor() {
		return major;
	}

	public short getMinor() {
		return minor;
	}

	public short getRevision() {
		return revision;
	}

	public Version.Type getType() {
		return type;
	}

	@Override
	public int compareTo(@SuppressWarnings("NullableProblems") V b) {
		if (b == null)
			throw new NullPointerException("b");
		if (major>b.getMajor())
			return 1;
		else if (major<b.getMajor())
			return -1;
		else
		{
			if (minor>b.getMinor())
				return 1;
			else if (minor<b.getMinor())
				return -1;
			else
			{
				if (revision>b.getRevision())
					return 1;
				else if (revision<b.getRevision())
					return -1;
				else
				{
					int c=type.compareTo(b.getType());
					if (c!=0)
						return c;
					else
					{
						if (type== Version.Type.STABLE)
							return 0;
						else
						{
							return Short.compare(alphaBetaRCVersion, b.getAlphaBetaRCVersion());
						}
					}


				}
			}
		}
	}
}

