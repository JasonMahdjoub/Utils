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

import java.text.DateFormat;
import java.util.Calendar;
import java.util.Date;
import java.util.Locale;

/**
 * Represents a person developing a software
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 * @see Version
 * @see Person
 */
@SuppressWarnings("FieldMayBeFinal")
public class PersonDeveloper extends Person implements Comparable<PersonDeveloper>{

	private Date developmentBeginDate;

	protected PersonDeveloper() {
		this("", "", new Date());
	}

	/**
	 *
	 * @param lastName the last name
	 * @param firstName the first name
	 * @param developmentBeginDate the date when the developer entered into the team (format YYYY-MM-DD, i.e. 2020-10-28)
	 */
	public PersonDeveloper(String lastName, String firstName, String developmentBeginDate) {
		this(lastName, firstName, Version.parse(developmentBeginDate));
	}
	/**
	 *
	 * @param lastName the last name
	 * @param firstName the first name
	 * @param developmentBeginDate the date when the developer entered into the team
	 */
	public PersonDeveloper(String lastName, String firstName, Calendar developmentBeginDate) {
		this(lastName, firstName, developmentBeginDate.getTime());
	}
	/**
	 *
	 * @param lastName the last name
	 * @param firstName the first name
	 * @param developmentBeginDate the date when the developer entered into the team
	 */
	public PersonDeveloper(String lastName, String firstName, Date developmentBeginDate) {
		super(lastName, firstName);
		if (developmentBeginDate == null)
			throw new NullPointerException("developmentBeginDate");
		this.developmentBeginDate = developmentBeginDate;
	}
	
	@Override
	public boolean equals(Object o) {
		if (o == null)
			return false;
		if (o == this)
			return true;
		if (o instanceof PersonDeveloper) {
			PersonDeveloper p = ((PersonDeveloper) o);
			return firstName.equals(p.firstName) && lastName.equals(p.lastName)
					&& developmentBeginDate.equals(p.developmentBeginDate);
		}
		return false;
	}

	public Date getDateBeginDevelopment() {
		return developmentBeginDate;
	}

	@Override
	public String toString() {
		return firstName + " " + lastName + " (Entered in the team at "
				+ DateFormat.getDateInstance(DateFormat.SHORT, Locale.FRANCE).format(developmentBeginDate) + ")";
	}

	@Override
	public int compareTo(PersonDeveloper p) {

		int c=developmentBeginDate.compareTo(p.developmentBeginDate);
		if (c==0)
		{
			c=lastName.compareTo(p.lastName);
			if (c==0)
			{
				c=firstName.compareTo(p.firstName);
			}
		}
		return c;
	}
}
