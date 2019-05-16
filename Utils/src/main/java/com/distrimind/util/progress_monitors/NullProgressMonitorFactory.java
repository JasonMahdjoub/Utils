package com.distrimind.util.progress_monitors;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

jason.mahdjoub@distri-mind.fr

This software (Object Oriented Database (OOD)) is a computer program 
whose purpose is to manage a local database with the object paradigm 
and the java langage 

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

import javax.swing.*;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.29.0
 */
public class NullProgressMonitorFactory extends ProgressMonitorFactory{
	@Override
	public ProgressMonitor getProgressMonitor(Object parentComponent, Object message, String note, int min, int max) {
		return new ProgressMonitor(null, message, note, min, max ){
			@Override
			public void setProgress(int nv) {

			}
		};
	}

	static final Field progressMonitorField;
	static
	{
		Field tmpProgressMonitorField=null;
		try {
			tmpProgressMonitorField=ProgressMonitorInputStream.class.getDeclaredField("monitor");
			tmpProgressMonitorField.setAccessible(true);
		} catch (NoSuchFieldException e) {
			e.printStackTrace();
			System.exit(-1);
		}

		progressMonitorField=tmpProgressMonitorField;
	}

	@Override
	public ProgressMonitorInputStream getProgressMonitorInputStream(Object parentComponent, Object message, InputStream inputStream) {
		ProgressMonitorInputStream res=new ProgressMonitorInputStream(null, message, inputStream);
		int size=0;
		try {
			size=inputStream.available();
		} catch (IOException ignored) {

		}
		try {
			progressMonitorField.set(res, getProgressMonitor(null, null, null, 0, size));
		} catch (IllegalAccessException e) {
			e.printStackTrace();
		}
		return res;
	}
}
