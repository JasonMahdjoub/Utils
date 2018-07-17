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

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;


/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.17
 */
public enum OSVersion {
    WINDOWS_3_11("(win16)", OS.WINDOWS),
    WINDOWS_95("(windows 95)|(win95)|(windows_95)", OS.WINDOWS, WINDOWS_3_11),
    WINDOWS_98("(windows 98)|(win98)", OS.WINDOWS, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_NT_4_0("(windows nt 4.0)|(winnt4.0)|(winnt)|(windows nt)", OS.WINDOWS, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_ME("(windows me)", OS.WINDOWS, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_2000("(windows nt 5.0)|(windows 2000)", OS.WINDOWS, WINDOWS_ME, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_XP("(windows nt 5.1)|(windows xp)", OS.WINDOWS, WINDOWS_2000, WINDOWS_ME, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_SERVER_2003("(windows nt 5.2)", OS.WINDOWS, WINDOWS_XP, WINDOWS_2000, WINDOWS_ME, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_VISTA("(windows nt 6.0)", OS.WINDOWS, WINDOWS_SERVER_2003, WINDOWS_XP, WINDOWS_2000, WINDOWS_ME, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95,WINDOWS_3_11),
    WINDOWS_7("(windows nt 6.1)", OS.WINDOWS, WINDOWS_VISTA, WINDOWS_SERVER_2003, WINDOWS_XP, WINDOWS_2000, WINDOWS_ME, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_8("(windows nt 6.2)", OS.WINDOWS, WINDOWS_7, WINDOWS_VISTA, WINDOWS_SERVER_2003, WINDOWS_XP, WINDOWS_2000, WINDOWS_ME, WINDOWS_NT_4_0, WINDOWS_98, WINDOWS_95, WINDOWS_3_11),
    WINDOWS_10("(windows nt 10.0)", OS.WINDOWS, WINDOWS_8, WINDOWS_7, WINDOWS_VISTA, WINDOWS_SERVER_2003, WINDOWS_XP, WINDOWS_2000, WINDOWS_ME,WINDOWS_NT_4_0, WINDOWS_98,WINDOWS_95, WINDOWS_3_11),
    OPEN_BSD("openbsd", OS.OPEN_BSD),
    SUN_OS("(sunos)", OS.SUN_OS),
    LINUX( "(linux)|(x11)", OS.LINUX),
    Ubuntu( "(ubuntu)",OS.LINUX),
    IOS("(iphone)|(ipad)", OS.IOS),
    MAC_OS( "(mac_powerPC)|(macintosh)|(.*mac.*)",OS.MAC_OS),
    QNX("(qnx)",OS.QNX),
    BeOS("(beos)",OS.BEOS),
    OS_2("(os/2)", OS.OS_2),
    ANDROID("(android)",OS.ANDROID),
    SEARCH_BOT_NUHK("(nuhk)",OS.SEARCH_BOT),
    SEARCH_BOT_GOOGLEBOT("(googlebot)",OS.SEARCH_BOT),
    SEARCH_BOT_YAMMYBOT("(yammybot)",OS.SEARCH_BOT),
    SEARCH_BOT_OPENBOT("(openbot)",OS.SEARCH_BOT),
    SEARCH_BOT_SLURP("(slurp)",OS.SEARCH_BOT),
    SEARCH_BOT_MSNBOT("(msnbot)",OS.SEARCH_BOT),
    SEARCH_BOT_ASK_JEEVES_TEOMA("(ask jeeves/teoma)",OS.SEARCH_BOT),
    SEARCH_BOT_ASK_QWANT("(qwant)",OS.SEARCH_BOT);

    private final Pattern pattern;
    private final OS os;
    private final OSVersion compatibleVersions[];

    OSVersion(String pattern, OS os, OSVersion... compatibleVersions) {
        this.pattern = Pattern.compile(pattern);
        this.os = os;
        this.compatibleVersions = compatibleVersions;
    }

    public static OSVersion getFrom(String userAgent) {
        for (OSVersion version : OSVersion.values()) {
            if (version.pattern.matcher(userAgent.toLowerCase()).matches())
                return version;
        }
        return null;
    }

    public OS getOS() {
        return os;
    }

    @SuppressWarnings("unused")
    public OSVersion[] getCompatibleVersions() {
        return compatibleVersions;
    }

    private static String getAndroidVersion()
    {
        try {
            Class<?> versionClass=Class.forName("android.os.Build.VERSION");
            return (String)versionClass.getDeclaredField("RELEASE").get(null);
        } catch (ClassNotFoundException | IllegalArgumentException | IllegalAccessException | NoSuchFieldException | SecurityException e) {
            return null;
        }
    }
    static private volatile com.distrimind.util.OSVersion currentOS=null;
    static String OS_VERSION = System.getProperty("os.name") + " " + System.getProperty("os.version");

    public static OSVersion getCurrentOSVersion()
    {
        if (currentOS==null) {
            if (OS.isAndroid()) {
                currentOS=OSVersion.getFrom(getAndroidVersion());
            }
            else {
                for (OS os : OS.values()) {
                    if (os.pattern.matcher(OS.OSName).matches()) {


                        currentOS=OSVersion.getFrom(OS_VERSION);
                        break;
                    }
                }
            }
        }
        return currentOS;
    }

    @SuppressWarnings("unused")
    public List<OSVersion> getLowerVersions()
    {
        List<OSVersion> res=new ArrayList<>();
        for (OSVersion v : OSVersion.values())
            if (v.getOS()==this.getOS())
                if (v.ordinal()<this.ordinal())
                    res.add(v);
        return res;
    }

    @SuppressWarnings("unused")
    public List<OSVersion> getLowerOrEqualsVersions()
    {
        List<OSVersion> res=new ArrayList<>();
        for (OSVersion v : OSVersion.values())
            if (v.getOS()==this.getOS())
                if (v.ordinal()<=this.ordinal())
                    res.add(v);
        return res;
    }

    @SuppressWarnings("unused")
    public List<OSVersion> getGreaterVersions()
    {
        List<OSVersion> res=new ArrayList<>();
        for (OSVersion v : OSVersion.values())
            if (v.getOS()==this.getOS())
                if (v.ordinal()>this.ordinal())
                    res.add(v);
        return res;
    }

    @SuppressWarnings("unused")
    public List<OSVersion> getGreaterOrEqualVersions()
    {
        List<OSVersion> res=new ArrayList<>();
        for (OSVersion v : OSVersion.values())
            if (v.getOS()==this.getOS())
                if (v.ordinal()>=this.ordinal())
                    res.add(v);
        return res;
    }
}
