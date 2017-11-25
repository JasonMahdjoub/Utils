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
package com.distrimind.util;

//import java.io.BufferedReader;

/**
 * 
 * @author Jason Mahdjoub
 * 
 * @version 1.1
 * @since Utils 1.0
 *
 */
public class RegexTools {

	/**
	 * Return a regex part that define a character that must match to the given
	 * parameters
	 * 
	 * @param latin
	 *            the character must be a 'latin' character if true
	 * @param greek
	 *            the character must be a 'greek' character if true
	 * @param internationalChars
	 *            the character must be an international character if true (all
	 *            languages are concerned)
	 * @param punctuation
	 *            the character must be include a punctuation :
	 *            <p>!"#$%&amp;'()*+,-./:;&lt;=&gt;?@[\]^_`{|}~</p>
	 * @param spaceortab
	 *            the character must include space or tab's
	 * @param exDecimalDigit
	 *            the character must be an exadicimal number
	 * @param digit
	 *            the character must be an dicimal number
	 * @param uppperCase
	 *            the character must be an upper case character
	 * @param lowerCase
	 *            the character must be lower case character
	 * @return the compiled regex
	 */
	public static String getRegexCharMatch(boolean latin, boolean greek, boolean internationalChars,
			boolean punctuation, boolean spaceortab, boolean exDecimalDigit, boolean digit, boolean uppperCase,
			boolean lowerCase) {
		StringBuffer pattern = new StringBuffer("[");
		StringBuffer patternNot = new StringBuffer("&&[");
		if (internationalChars) {
			for (Character.UnicodeScript us : Character.UnicodeScript.values()) {
				if (us != Character.UnicodeScript.UNKNOWN && us != Character.UnicodeScript.COMMON) {
					if (us == Character.UnicodeScript.LATIN) {
						if (latin)
							pattern.append("\\p{Script=" + us + "}");
					} else if (us == Character.UnicodeScript.GREEK) {
						if (greek)
							pattern.append("\\p{Script=" + us + "}");
					} else
						pattern.append("\\p{Script=" + us + "}");

				}
			}
		} else {
			if (latin)
				pattern.append("\\p{Script=latin}");
			if (greek)
				pattern.append("\\p{script=greek}");
		}
		if (punctuation)
			pattern.append("\\p{Punct}");
		else
			patternNot.append("^\\p{Punct}");
		if (spaceortab)
			pattern.append("\\p{Blank}");
		else
			patternNot.append("^\\p{Blank}");
		if (exDecimalDigit)
			pattern.append("\\p{XDigit}");
		if (digit)
			pattern.append("\\p{Digit}");
		else if (!exDecimalDigit)
			patternNot.append("^\\p{Digit}");
		if (uppperCase && !lowerCase)
			pattern.append("\\p{Lu}");
		if (lowerCase && !uppperCase)
			patternNot.append("^\\p{Lu}");
		if (patternNot.length() > 3) {
			patternNot.append("]");
		}
		pattern.append(patternNot);
		pattern.append("]");

		return pattern.toString();

	}

	/**
	 * Returns a regex that exclude characters that can be used to make code
	 * injection, with the new additional punctuation characters to include :
	 * <p>-.:'`;()&amp;</p>
	 * 
	 * @param minChars
	 *            minimum characters number
	 * @param maxChars
	 *            maximum characters number
	 * @return the compiled regex
	 */
	public static String getRegexTextMatchWithNoInjection(int minChars, int maxChars) {
		return getRegexTextMatchWithNoInjection(minChars, maxChars, "[\\-\\.:'`;\\(\\)\\&]");
	}

	/**
	 * Returns a regex that exclude characters that can be used to make code
	 * injection.
	 * 
	 * @param minChars
	 *            minimum characters number
	 * @param maxChars
	 *            maximum characters number
	 * @param additionalCharactersToInclude
	 *            additional characters to include. The string must be surrounded
	 *            with '[]' or '()'.
	 * @return the compiled regex
	 */
	public static String getRegexTextMatchWithNoInjection(int minChars, int maxChars,
			String additionalCharactersToInclude) {
		if (additionalCharactersToInclude != null && additionalCharactersToInclude.length() != 0)
			return "^(" + RegexTools.getRegexCharMatch(true, true, true, false, true, true, true, true, true) + "|"
					+ additionalCharactersToInclude + "){" + minChars + "," + maxChars + "}$";
		else
			return "^" + RegexTools.getRegexCharMatch(true, true, true, false, true, true, true, true, true) + "{"
					+ minChars + "," + maxChars + "}$";
	}

}
