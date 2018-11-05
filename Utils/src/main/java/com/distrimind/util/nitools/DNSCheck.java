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

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attributes;
import javax.naming.directory.InitialDirContext;
import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.21
 */
public class DNSCheck {


    public static boolean isFree(String domainName)
    {

        try
        {
            InetAddress inetAddress;
            // get Internet Address of this host name
            inetAddress = InetAddress.getByName(domainName);
            // get the default initial Directory Context
            InitialDirContext iDirC = new InitialDirContext();
            // get the DNS records for inetAddress
            Attributes attributes = iDirC.getAttributes("dns:/" + inetAddress.getHostName());
            // get an enumeration of the attributes and print them out
            NamingEnumeration<?> attributeEnumeration = attributes.getAll();
            if (attributeEnumeration.hasMore())
            {
                attributeEnumeration.close();
                return false;
            }
            attributeEnumeration.close();
            return false;
        }
        catch (UnknownHostException exception)
        {
            return true;
        }
        catch (NamingException exception)
        {
            return false;
        }

    }

    public static boolean isUsed(String domainName)
    {
        return !isFree(domainName);
    }
    public static String getEmailFromDomain(String email)
    {
        return email.substring(email.lastIndexOf("@"));
    }
    public static boolean isFreeDomainFromEmail(String email)
    {
        return isFree(getEmailFromDomain(email));
    }
    public static boolean isUsedDomainFromEmail(String email)
    {
        return !isFreeDomainFromEmail(email);
    }


}
