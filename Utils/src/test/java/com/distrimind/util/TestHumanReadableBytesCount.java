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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.16
 */

public class TestHumanReadableBytesCount {
    @Test(dataProvider = "dataForConvertingToString")
    public void testConvertToString(long quantityInBytes, boolean longFormat, boolean si, boolean useOctet, boolean siIsBin, int precision, String result)
    {
        Assert.assertEquals(HumanReadableBytesCount.convertToString(quantityInBytes, longFormat, si, useOctet, siIsBin, precision).replace(',', '.'), result);
        if (precision>=2) {
            long v=HumanReadableBytesCount.valueOf(result, siIsBin);
            Assert.assertTrue(quantityInBytes==0?v==quantityInBytes:((double)Math.abs(v-quantityInBytes))/((double)quantityInBytes)<0.004, "expected : "+quantityInBytes+", found : "+v);
            result=result.replace("octet", "bit").replace("byte", "bit");
            if (result.endsWith("o"))
                result=result.substring(0, result.length()-1)+"b";
            if (result.endsWith("B"))
                result=result.substring(0, result.length()-1)+"b";
            quantityInBytes*=8;
            v=HumanReadableBytesCount.valueOf(result, siIsBin);
            Assert.assertTrue(quantityInBytes==0?v==quantityInBytes:((double)Math.abs(v-quantityInBytes))/((double)quantityInBytes)<0.004, "expected : "+result+", found : "+v);

        }
    }

    @DataProvider(name = "dataForConvertingToString", parallel = true)
    public Object[][] getDataForConvertingToString()
    {
        return new Object[][]{
                {0, true, true, true, false, 2, "0 octet"},
                {1, true, true, true, false, 2, "1 octet"},
                {50, true, true, true, false, 2, "50 octets"},
                {1000, true, true, true, false, 2, "1 kilooctet"},
                {1540, true, true, true, false, 2, "1.54 kilooctets"},
                {1000000, true, true, true, false, 2, "1 megaoctet"},
                {1540000, true, true, true, false, 2, "1.54 megaoctets"},
                {1000000000, true, true, true, false, 2, "1 gigaoctet"},
                {1540000000, true, true, true, false, 2, "1.54 gigaoctets"},
                {1000000000000L, true, true, true, false, 2, "1 teraoctet"},
                {1540000000000L, true, true, true, false, 2, "1.54 teraoctets"},
                {1000000000000000L, true, true, true, false, 2, "1 petaoctet"},
                {1540000000000000L, true, true, true, false, 2, "1.54 petaoctets"},
                {1000000000000000000L, true, true, true, false, 2, "1 exaoctet"},
                {1540000000000000000L, true, true, true, false, 2, "1.54 exaoctets"},
                {0, true, true, false, false, 2, "0 byte"},
                {1, true, true, false, false, 2, "1 byte"},
                {50, true, true, false, false, 2, "50 bytes"},
                {1000, true, true, false, false, 2, "1 kilobyte"},
                {1540, true, true, false, false, 2, "1.54 kilobytes"},
                {1000000, true, true, false, false, 2, "1 megabyte"},
                {1540000, true, true, false, false, 2, "1.54 megabytes"},
                {1000000000, true, true, false, false, 2, "1 gigabyte"},
                {1540000000, true, true, false, false, 2, "1.54 gigabytes"},
                {1000000000000L, true, true, false, false, 2, "1 terabyte"},
                {1540000000000L, true, true, false, false, 2, "1.54 terabytes"},
                {1000000000000000L, true, true, false, false, 2, "1 petabyte"},
                {1540000000000000L, true, true, false, false, 2, "1.54 petabytes"},
                {1000000000000000000L, true, true, false, false, 2, "1 exabyte"},
                {1540000000000000000L, true, true, false, false, 2, "1.54 exabytes"},
                {0, true, true, true, false, 0, "0 octet"},
                {1, true, true, true, false, 0, "1 octet"},
                {50, true, true, true, false, 0, "50 octets"},
                {1000, true, true, true, false, 0, "1 kilooctet"},
                {1540, true, true, true, false, 0, "2 kilooctets"},
                {1000000, true, true, true, false, 0, "1 megaoctet"},
                {1540000, true, true, true, false, 0, "2 megaoctets"},
                {1000000000, true, true, true, false, 0, "1 gigaoctet"},
                {1540000000, true, true, true, false, 0, "2 gigaoctets"},
                {1000000000000L, true, true, true, false, 0, "1 teraoctet"},
                {1540000000000L, true, true, true, false, 0, "2 teraoctets"},
                {1000000000000000L, true, true, true, false, 0, "1 petaoctet"},
                {1540000000000000L, true, true, true, false, 0, "2 petaoctets"},
                {1000000000000000000L, true, true, true, false, 0, "1 exaoctet"},
                {1540000000000000000L, true, true, true, false, 0, "2 exaoctets"},
                {0, false, true, true, false, 2, "0 o"},
                {1, false, true, true, false, 2, "1 o"},
                {50, false, true, true, false, 2, "50 o"},
                {1000, false, true, true, false, 2, "1 ko"},
                {1540, false, true, true, false, 2, "1.54 ko"},
                {1000000, false, true, true, false, 2, "1 Mo"},
                {1540000, false, true, true, false, 2, "1.54 Mo"},
                {1000000000, false, true, true, false, 2, "1 Go"},
                {1540000000, false, true, true, false, 2, "1.54 Go"},
                {1000000000000L, false, true, true, false, 2, "1 To"},
                {1540000000000L, false, true, true, false, 2, "1.54 To"},
                {1000000000000000L, false, true, true, false, 2, "1 Po"},
                {1540000000000000L, false, true, true, false, 2, "1.54 Po"},
                {1000000000000000000L, false, true, true, false, 2, "1 Eo"},
                {1540000000000000000L, false, true, true, false, 2, "1.54 Eo"},
                {0, false, true, false, false, 2, "0 B"},
                {1, false, true, false, false, 2, "1 B"},
                {50, false, true, false, false, 2, "50 B"},
                {1000, false, true, false, false, 2, "1 kB"},
                {1540, false, true, false, false, 2, "1.54 kB"},
                {1000000, false, true, false, false, 2, "1 MB"},
                {1540000, false, true, false, false, 2, "1.54 MB"},
                {1000000000, false, true, false, false, 2, "1 GB"},
                {1540000000, false, true, false, false, 2, "1.54 GB"},
                {1000000000000L, false, true, false, false, 2, "1 TB"},
                {1540000000000L, false, true, false, false, 2, "1.54 TB"},
                {1000000000000000L, false, true, false, false, 2, "1 PB"},
                {1540000000000000L, false, true, false, false, 2, "1.54 PB"},
                {1000000000000000000L, false, true, false, false, 2, "1 EB"},
                {1540000000000000000L, false, true, false, false, 2, "1.54 EB"},
                {0, true, false, true, false, 2, "0 octet"},
                {1, true, false, true, false, 2, "1 octet"},
                {50, true, false, true, false, 2, "50 octets"},
                {1024, true, false, true, false, 2, "1 kibiooctet"},
                {1024+540, true, false, true, false, 2, "1.53 kibiooctets"},
                {1048576, true, false, true, false, 2, "1 mebiooctet"},
                {1048576L+540L*1024L, true, false, true, false, 2, "1.53 mebiooctets"},
                {1073741824, true, false, true, false, 2, "1 gibiooctet"},
                {1073741824L+540L*1024L*1024L, true, false, true, false, 2, "1.53 gibiooctets"},
                {1099511627776L, true, false, true, false, 2, "1 tebiooctet"},
                {1099511627776L+540L*1024L*1024L*1024L, true, false, true, false, 2, "1.53 tebiooctets"},
                {1125899906842624L, true, false, true, false, 2, "1 pebiooctet"},
                {1125899906842624L+540L*1024L*1024L*1024L*1024L, true, false, true, false, 2, "1.53 pebiooctets"},
                {0, true, true, true, true, 2, "0 octet"},
                {1, true, true, true, true, 2, "1 octet"},
                {50, true, true, true, true, 2, "50 octets"},
                {1024, true, true, true, true, 2, "1 kilooctet"},
                {1024+540L, true, true, true, true, 2, "1.53 kilooctets"},
                {1048576, true, true, true, true, 2, "1 megaoctet"},
                {1048576+540L*1024L, true, true, true, true, 2, "1.53 megaoctets"},
                {1073741824, true, true, true, true, 2, "1 gigaoctet"},
                {1073741824+540L*1024L*1024L, true, true, true, true, 2, "1.53 gigaoctets"},
                {1099511627776L, true, true, true, true, 2, "1 teraoctet"},
                {1099511627776L+540L*1024L*1024L*1024L, true, true, true, true, 2, "1.53 teraoctets"},
                {1125899906842624L, true, true, true, true, 2, "1 petaoctet"},
                {1125899906842624L+540L*1024L*1024L*1024L*1024L, true, true, true, true, 2, "1.53 petaoctets"},
                {0, false, false, true, false, 2, "0 o"},
                {1, false, false, true, false, 2, "1 o"},
                {50, false, false, true, false, 2, "50 o"},
                {1024, false, false, true, false, 2, "1 Kio"},
                {1024+540, false, false, true, false, 2, "1.53 Kio"},
                {1048576, false, false, true, false, 2, "1 Mio"},
                {1048576+540L*1024L, false, false, true, false, 2, "1.53 Mio"},
                {1073741824, false, false, true, false, 2, "1 Gio"},
                {1073741824+540L*1024L*1024L, false, false, true, false, 2, "1.53 Gio"},
                {1099511627776L, false, false, true, false, 2, "1 Tio"},
                {1099511627776L+540L*1024L*1024L*1024L, false, false, true, false, 2, "1.53 Tio"},
                {1125899906842624L, false, false, true, false, 2, "1 Pio"},
                {1125899906842624L+540L*1024L*1024L*1024L*1024L, false, false, true, false, 2, "1.53 Pio"},
                {0, true, false, false, false, 2, "0 byte"},
                {1, true, false, false, false, 2, "1 byte"},
                {50, true, false, false, false, 2, "50 bytes"},
                {1024, true, false, false, false, 2, "1 kibiobyte"},
                {1024+540, true, false, false, false, 2, "1.53 kibiobytes"},
                {1048576, true, false, false, false, 2, "1 mebiobyte"},
                {1048576+540L*1024L, true, false, false, false, 2, "1.53 mebiobytes"},
                {1073741824, true, false, false, false, 2, "1 gibiobyte"},
                {1073741824+540L*1024L*1024L, true, false, false, false, 2, "1.53 gibiobytes"},
                {1099511627776L, true, false, false, false, 2, "1 tebiobyte"},
                {1099511627776L+540L*1024L*1024L*1024L, true, false, false, false, 2, "1.53 tebiobytes"},
                {1125899906842624L, true, false, false, false, 2, "1 pebiobyte"},
                {1125899906842624L+540L*1024L*1024L*1024L*1024L, true, false, false, false, 2, "1.53 pebiobytes"},
                {0, false, false, false, false, 2, "0 B"},
                {1, false, false, false, false, 2, "1 B"},
                {50, false, false, false, false, 2, "50 B"},
                {1024, false, false, false, false, 2, "1 KiB"},
                {1024+540, false, false, false, false, 2, "1.53 KiB"},
                {1048576, false, false, false, false, 2, "1 MiB"},
                {1048576+540L*1024L, false, false, false, false, 2, "1.53 MiB"},
                {1073741824, false, false, false, false, 2, "1 GiB"},
                {1073741824+540L*1024L*1024L, false, false, false, false, 2, "1.53 GiB"},
                {1099511627776L, false, false, false, false, 2, "1 TiB"},
                {1099511627776L+540L*1024L*1024L*1024L, false, false, false, false, 2, "1.53 TiB"},
                {1125899906842624L, false, false, false, false, 2, "1 PiB"},
                {1125899906842624L+540L*1024L*1024L*1024L*1024L, false, false, false, false, 2, "1.53 PiB"}

        };
    }
}
