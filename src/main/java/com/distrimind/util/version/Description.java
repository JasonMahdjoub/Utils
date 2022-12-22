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

import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;

/**
 * Represents the description of program version
 * 
 * @author Jason Mahdjoub
 * @version 1.1
 * @since Utils 1.5
 * @see Version
 */
@SuppressWarnings("FieldMayBeFinal")
public class Description extends AbstractVersion<Description> {

	private final ArrayList<DescriptionItem> items = new ArrayList<>();

	protected Description() {
		super();
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date (format YYYY-MM-DD, i.e. 2020-10-28))
	 */
	public Description(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, String _date) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date);
	}

	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date (format YYYY-MM-DD, i.e. 2020-10-28))
	 */
	public Description(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, String _date) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	public Description(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, Calendar _date) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	public Description(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, Calendar _date) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	public Description(int _major, int _minor, int _revision, Version.Type _type, int _alpha_beta_version, Date _date) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date);
	}
	/**
	 * @param _major major version
	 * @param _minor minor version
	 * @param _revision revision
	 * @param _type version type (stable, alpha, beta)
	 * @param _alpha_beta_version if type is equal to alpha or beta, alpha/beta version
	 * @param _date the version date
	 */
	public Description(short _major, short _minor, short _revision, Version.Type _type, short _alpha_beta_version, Date _date) {
		super(_major, _minor, _revision, _type, _alpha_beta_version, _date);
	}


	
	public Description addItem(DescriptionType type, String d) {
		items.add(new DescriptionItem(type, d));
		return this;
	}

	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof Description) {
			Description d = (Description) o;

			return compareTo(d)==0 &&
					d.items.equals(items);
		}
		return false;
	}



	public String getHTML() {
		StringBuilder s = getHTMLVersionPart();

		s.append("<ul>\n");
		for (DescriptionType dt : DescriptionType.values()) {
			boolean first=true;
			for (DescriptionItem d : items) {
				if (d.getDescriptionType()==dt) {
					if (first)
					{
						s.append("\t<li>")
								.append(dt.getTitle())
								.append("\n\t\t<ul>\n");
						first=false;
					}
					s.append("\t\t\t<li>");
					s.append(d.getDescriptionItem());
					s.append("\t\t\t</li>\n");
				}
			}
			if (!first)
				s.append("\t\t</ul>\n\t</li>\n");
		}
		s.append("</ul>");
		return s.toString();
	}

	public String getMarkdownCode() {
		StringBuilder s = getMarkdownVersionPartCode();
		for (DescriptionType dt : DescriptionType.values()) {
			boolean first=true;
			for (DescriptionItem d : items) {
				if (d.getDescriptionType()==dt) {
					if (first)
					{
						s.append("#### ")
								.append(dt.getTitle())
								.append("\n");
						first=false;

					}
					s.append("* ");
					s.append(d.getDescriptionItem());
					s.append("\n");
				}
			}
		}
		
		return s.toString();
	}
	public ArrayList<DescriptionItem> getItems() {
		return items;
	}

	@Override
	public String toString() {
		return "Description{" +
				"items=" + items +
				'}';
	}
}
