package com.distrimind.util.progress_monitors;
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

import com.distrimind.util.OSVersion;

import java.io.FilterInputStream;
import java.io.InputStream;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.29.0
 */
public abstract class ProgressMonitorFactory {
	/**
	 * Constructs a graphic object that shows progress, typically by filling
	 * in a rectangular bar as the process nears completion.
	 * <p>
	 *
	 * @param message a descriptive message that will be shown
	 *        to the user to indicate what operation is being monitored.
	 *        This does not change as the operation progresses.
	 * @param note a short note describing the state of the
	 *        operation.  As the operation progresses, you can call
	 *        setNote to change the note displayed.  This is used,
	 *        for example, in operations that iterate through a
	 *        list of files to show the name of the file being processes.
	 *        If note is initially null, there will be no note line
	 *        in the dialog box and setNote will be ineffective
	 * @param min the lower bound of the range
	 * @param max the upper bound of the range
	 * @return the progress monitor
	 */
	public ProgressMonitorDM getProgressMonitor( Object message,
													   String note,
													   int min,
													   int max)
	{
		return getProgressMonitor(null, message, note, min, max);
	}

	/**
	 * Constructs a graphic object that shows progress, typically by filling
	 * in a rectangular bar as the process nears completion.
	 *
	 * @param parentComponent the parent component for the dialog box
	 * @param message a descriptive message that will be shown
	 *        to the user to indicate what operation is being monitored.
	 *        This does not change as the operation progresses.
	 * @param note a short note describing the state of the
	 *        operation.  As the operation progresses, you can call
	 *        setNote to change the note displayed.  This is used,
	 *        for example, in operations that iterate through a
	 *        list of files to show the name of the file being processes.
	 *        If note is initially null, there will be no note line
	 *        in the dialog box and setNote will be ineffective
	 * @param min the lower bound of the range
	 * @param max the upper bound of the range
	 * @return the progress monitor
	 */
	public abstract ProgressMonitorDM getProgressMonitor(Object parentComponent,
													   Object message,
													   String note,
													   int min,
													   int max);

	/**
	 * Constructs a graphic object that shows progress, typically by filling
	 * in a rectangular bar as the process nears completion.
	 *
	 * @param parentComponent the parent component for the dialog box
	 * @param parameters see {@link ProgressMonitorParameters}
	 * @return the progress monitor
	 * */
	public ProgressMonitorDM getProgressMonitor(Object parentComponent, ProgressMonitorParameters parameters)
	{
		ProgressMonitorDM res=getProgressMonitor(parentComponent, parameters.getMessage(), parameters.getNote(), parameters.getMin(), parameters.getMax());
		if (res.getMillisToPopup()>=0)
		{
			res.setMillisToPopup(parameters.getMillisToPopup());
		}
		if (res.getMillisToDecideToPopup()>=0)
		{
			res.setMillisToDecideToPopup(parameters.getMillisToDecideToPopup());
		}
		return res;
	}
	/**
	 * Constructs a graphic object that shows progress, typically by filling
	 * in a rectangular bar as the process nears completion.
	 * <p>
	 *
	 * @param parameters see {@link ProgressMonitorParameters}
	 * @return the progress monitor
	 */
	public ProgressMonitorDM getProgressMonitor(ProgressMonitorParameters parameters)
	{
		return getProgressMonitor(null, parameters);
	}

	/**
	 * Constructs an object to monitor the progress of an input stream.
	 *
	 * @param message a descriptive message that will be shown
	 *        to the user to indicate what operation is being monitored.
	 *        This does not change as the operation progresses.
	 * @param inputStream The input stream to be monitored.
	 * @return the progress monitor
	 */
	public FilterInputStream getProgressMonitorInputStream( final Object message,
																			 final InputStream inputStream)
	{
		return getProgressMonitorInputStream(null, message, inputStream);
	}

	/**
	 * Constructs an object to monitor the progress of an input stream.
	 *
	 * @param parentComponent The component triggering the operation
	 * 	                         being monitored.
	 * @param message a descriptive message that will be shown
	 *        to the user to indicate what operation is being monitored.
	 *        This does not change as the operation progresses.
	 * @param inputStream The input stream to be monitored.
	 * @return the progress monitor
	 */
	public abstract FilterInputStream getProgressMonitorInputStream(final Object parentComponent,
																	final Object message,
																	final InputStream inputStream);



	private static ProgressMonitorFactory defaultProgressMonitorFactory;

	public static ProgressMonitorFactory getDefaultProgressMonitorFactory()
	{
		synchronized (ProgressMonitorFactory.class)
		{
			if (defaultProgressMonitorFactory==null)
			{
				switch (OSVersion.getCurrentOSVersion().getOS())
				{
					case WINDOWS:
					case LINUX:
					case MAC_OS_X:
						defaultProgressMonitorFactory=new SwingProgressMonitorFactory();
						break;
					default:
						defaultProgressMonitorFactory=new NullProgressMonitorFactory();
						//TODO add progress monitor for Android
				}
			}
			return defaultProgressMonitorFactory;
		}
	}

	public static void setDefaultProgressMonitorFactory(ProgressMonitorFactory progressMonitorFactory)
	{
		if (progressMonitorFactory==null)
			throw new NullPointerException();
		synchronized (ProgressMonitorFactory.class) {
			defaultProgressMonitorFactory = progressMonitorFactory;
		}
	}

	public static void main(String [] args) throws InterruptedException {
		ProgressMonitorFactory pmf=getDefaultProgressMonitorFactory();
		ProgressMonitorParameters pmp=new ProgressMonitorParameters("test message", "test note", 0, 100);
		pmp.setMillisToDecideToPopup(1000);
		pmp.setMillisToPopup(0);
		ProgressMonitorDM pm=pmf.getProgressMonitor(pmp);
		for (int i=0;i<=100;i++) {
			pm.setProgress(i);
			Thread.sleep(100);
		}


	}
}
