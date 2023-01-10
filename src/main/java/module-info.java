/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java language 

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
module com.distrimind.util {
	requires com.distrimind.bouncycastle.core;
	requires com.distrimind.bouncycastle.prov;
	requires com.distrimind.bcfips;
	requires java.naming;
	requires java.xml;
	requires org.yaml.snakeyaml;
	//requires java.logging;
	requires static java.desktop;
	requires java.management;
	exports com.distrimind.util;
	exports com.distrimind.util.io;
	exports com.distrimind.util.crypto;
	exports com.distrimind.util.concurrent;
	exports com.distrimind.util.version;
	exports com.distrimind.util.properties;
	exports com.distrimind.util.systeminfo;
	exports com.distrimind.util.data_buffers;
	exports com.distrimind.util.harddrive;
	exports com.distrimind.util.nitools;
	exports com.distrimind.util.progress_monitors;
	exports com.distrimind.util.sizeof;
	exports com.distrimind.util.traceroute;
}