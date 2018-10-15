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

import java.math.RoundingMode;
import java.text.DecimalFormat;
import java.text.DecimalFormatSymbols;
import java.text.NumberFormat;
import java.text.ParseException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.16
 */
public class HumanReadableBytesCount {

    private static final String units[]=new String[]{"octet", "byte"};
    //private static final String pluralUnits[]=new String[]{"octets", "bytes"};
    private static final String presSI[]=new String[]{"", "kilo","mega", "giga", "tera", "peta", "exa", "zetta"};
    private static final String presBin[]=new String[]{"", "kibio","mebio", "gibio", "tebio", "pebio", "exbio", "zebio"};
    private static final String presSIShort[]=new String[]{"", "k","M", "G", "T", "P", "E", "Z"};
    private static final String presBinShort[]=new String[]{"", "K","M", "G", "T", "P", "E", "Z"};
    private static final DecimalFormatSymbols decimalFormatSymbols=((DecimalFormat)DecimalFormat.getInstance(Locale.getDefault())).getDecimalFormatSymbols();
    //private static final char decimalSeparator=decimalFormatSymbols.getDecimalSeparator();

    private static final String unitsShort[]=new String[]{"o", "B"};

    public static String convertToString(long quantityInBytes)
    {
        return convertToString(quantityInBytes, false);
    }
    public static String convertToString(long quantityInBytes, boolean longFormat)
    {
        return convertToString(quantityInBytes, longFormat, false);
    }
    public static String convertToString(long quantityInBytes, boolean longFormat, boolean si)
    {
        return convertToString(quantityInBytes, longFormat, si, Locale.getDefault().getLanguage().equals(Locale.FRANCE.getLanguage()));
    }
    public static String convertToString(long quantityInBytes, boolean longFormat, boolean si, boolean useOctet)
    {
        return convertToString(quantityInBytes, longFormat, si, useOctet, OSVersion.getCurrentOSVersion() != null && OSVersion.getCurrentOSVersion().getOS().SIPrefixAreUnderstoodAsBinaryPrefixForByteMultiples());
    }

    public static String convertToString(long quantityInBytes, boolean longFormat, boolean si, boolean useOctet, boolean siIsBin)
    {
        return convertToString(quantityInBytes, longFormat, si, useOctet, siIsBin, 2);
    }

    public static String convertToString(long quantityInBytes, boolean longFormat, boolean si, boolean useOctet, boolean siIsBin, int precision)
    {
        boolean neg=quantityInBytes<0;
        quantityInBytes=Math.abs(quantityInBytes);

        long base=(si && !siIsBin)?1000:1024;
        int exp=(int)(Math.log1p(quantityInBytes)/Math.log1p(base)+0.1);

        double val=((double)quantityInBytes)/((double)powerN(base, exp));
        if (precision==0)
            val=Math.round(val);

        String units[]=longFormat?HumanReadableBytesCount.units:unitsShort;
        String pres[]=longFormat?(si?presSI:presBin):(si?presSIShort:presBinShort);

        String pre=pres[exp]+((longFormat || exp==0 || si)?"":"i");
        String unit=(useOctet?units[0]:units[1])+((val<=1.0 || !longFormat)?"":"s");



        DecimalFormat df=new DecimalFormat();
        df.setDecimalFormatSymbols(decimalFormatSymbols);
        if (val!=Math.floor(val)) {
            df.setMaximumFractionDigits(precision);
            df.setMinimumFractionDigits(1);
        }
        else
        {
            df.setMaximumFractionDigits(0);
            df.setMinimumFractionDigits(0);
        }
        df.setRoundingMode(RoundingMode.HALF_UP);
        return String.format("%s%s %s%s", neg?"-":"", df.format(val), pre, unit);
    }
    public static long valueOf(String quantity)
    {
        return valueOf(quantity, OSVersion.getCurrentOSVersion() != null && OSVersion.getCurrentOSVersion().getOS().SIPrefixAreUnderstoodAsBinaryPrefixForByteMultiples());
    }
    public static long valueOf(String quantity, boolean siIsBin)
    {
        quantity=quantity.replace("é","e");
        Matcher m=getGlobalPattern().matcher(quantity);
        if (m.matches())
        {
            NumberFormat format=NumberFormat.getInstance(Locale.US);
            double val;
            try {
                val = (m.group("sign").equals("-")?-1.0:1.0)*(format.parse(m.group("value")).doubleValue());
            } catch (ParseException e) {
                throw new InternalError();
            }
            String preunit=m.group("preunit");
            m=getShortComposedUnitsPattern().matcher(preunit);
            if (m.matches())
            {
                boolean bit=preunit.endsWith("b");
                preunit=preunit.toLowerCase();
                String pre=preunit.length()>=2?(""+preunit.charAt(0)):"";
                boolean si=preunit.length()==2 && (preunit.charAt(1)!='i');
                long base=(si && !siIsBin)?1000:1024;
                long multiplier=-1;
                for (int i=0;i<presSIShort.length;i++)
                {
                    if (presSIShort[i].toLowerCase().equals(pre))
                    {
                        multiplier=powerN(base, i);
                    }
                }
                if (multiplier<=0)
                    throw new InternalError();
                return ((long)(val*multiplier))*(bit?8:1);
            }
            else
            {
                preunit=preunit.toLowerCase();
                if (preunit.startsWith("bit"))
                    return ((long)val)*8;
                else
                {
                    for (String s : units)
                    {
                        if (preunit.startsWith(s))
                            return (long)val;
                    }
                    boolean bit=preunit.endsWith("bit") || preunit.endsWith("bits");
                    for (int i=1;i<presBin.length;i++)
                    {
                        if (preunit.startsWith(presBin[i]))
                        {
                            return ((long)(powerN(1024, i)*val))*(bit?8:1);
                        }
                    }
                    for (int i=1;i<presSI.length;i++)
                    {
                        if (preunit.startsWith(presSI[i]))
                        {
                            long base=siIsBin?1024:1000;

                            return ((long)(powerN(base, i)*val))*(bit?8:1);
                        }
                    }
                    throw new InternalError();
                }
            }
        }
        else
            throw new IllegalArgumentException("The given quantity is not valid : "+quantity);
    }

    private static volatile String regexShortPre=null;
    private static String getRegexShortPre()
    {
        if (regexShortPre==null)
        {
            StringBuilder res=new StringBuilder("[");
            HashSet<String> hs=new HashSet<>();
            hs.addAll(Arrays.asList(presSIShort));
            hs.addAll(Arrays.asList(presBinShort));
            for (String s : hs)
            {
                res.append(s);
            }
            res.append("]");
            regexShortPre=res.toString();
        }
        return regexShortPre;
    }
    private static volatile String regexUnitsShort=null;
    private static String getRegexUnitsShort()
    {
        if (regexUnitsShort==null)
        {
            StringBuilder res=new StringBuilder("[b");
            for (String s : unitsShort)
                res.append(s);
            res.append("]");
            regexUnitsShort=res.toString();
        }
        return regexUnitsShort;
    }
    private static String getRegexShortComposedUnits()
    {
        return "(("+getRegexShortPre()+"i?)?"+getRegexUnitsShort()+")";
    }
    private static volatile String regexPre=null;
    private static String getRegexPre()
    {
        if (regexPre==null)
        {
            StringBuilder res=new StringBuilder("(");
            boolean first=true;
            for (String s : presSI) {
                if (s.length()>0){
                    if (first)
                        first=false;
                    else
                        res .append("|");
                    res.append(s);
                }
            }
            for (String s : presBin)
                if (s.length()>0)
                    res.append("|").append(s);
            res.append(")?");
            regexPre=res.toString();
        }
        return regexPre;
    }
    private static volatile String regexUnits=null;
    private static String getRegexUnits()
    {
        if (regexUnits==null)
        {
            StringBuilder res=new StringBuilder("(bit");
            for (String s : units)
                res.append("|").append(s);
            res.append(")");
            regexUnits=res.toString();
        }
        return regexUnits;
    }

    private static String getRegexComposedUnits()
    {
        return "(("+getRegexPre()+getRegexUnits()+")s?)";
    }

    private static volatile Pattern globalPattern=null, shortComposedUnitsPattern=null;


    private static Pattern getGlobalPattern()
    {
        if (globalPattern==null)
        {
            globalPattern=Pattern.compile("(?<sign>(-?))(?<value>(([0-9]+)|([0-9]*[.,][0-9]+))) ?(?<preunit>("+getRegexShortComposedUnits()+"|"+getRegexComposedUnits()+"))");
        }
        return globalPattern;
    }

    private static Pattern getShortComposedUnitsPattern()
    {
        if (shortComposedUnitsPattern==null)
        {
            shortComposedUnitsPattern=Pattern.compile(getRegexShortComposedUnits());
        }
        return shortComposedUnitsPattern;
    }




    private static long powerN(long number, int power){
        long res = 1;
        long sq = number;
        while(power > 0){
            if(power % 2 == 1){
                res *= sq;
            }
            sq = sq * sq;
            power /= 2;
        }
        return res;
    }
}
