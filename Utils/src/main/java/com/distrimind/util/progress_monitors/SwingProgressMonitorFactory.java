package com.distrimind.util.progress_monitors;
/*
Copyright or © or Copr. Jason Mahdjoub (01/04/2013)

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

import javax.swing.*;
import java.awt.*;
import java.io.InputStream;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.29.0
 */
public class SwingProgressMonitorFactory extends ProgressMonitorFactory {
	@Override
	public ProgressMonitorDM getProgressMonitor(Object parentComponent,
												Object message,
												String note,
												int min,
												int max) {
		return getProgressMonitor((Component)parentComponent, message, note, min, max);
	}

	public ProgressMonitorDM getProgressMonitor(Component parentComponent,
												Object message,
												String note,
												int min,
												int max) {

		return getProgressMonitor(new ProgressMonitor(parentComponent, message, note, min, max));
	}

	private ProgressMonitorDM getProgressMonitor(final ProgressMonitor pm)
	{
		return new ProgressMonitorDM() {
			@Override
			public void setProgress(int nv) {
				pm.setProgress(nv);
			}

			@Override
			public void close() {
				pm.close();
			}

			@Override
			public int getMinimum() {
				return pm.getMinimum();
			}

			@Override
			public void setMinimum(int m) {
				pm.setMinimum(m);
			}

			@Override
			public int getMaximum() {
				return pm.getMaximum();
			}

			@Override
			public void setMaximum(int m) {
				pm.setMaximum(m);
			}

			@Override
			public boolean isCanceled() {
				return pm.isCanceled();
			}

			@Override
			public void setMillisToDecideToPopup(int millisToDecideToPopup) {
				pm.setMillisToDecideToPopup(millisToDecideToPopup);
			}

			@Override
			public int getMillisToDecideToPopup() {
				return pm.getMillisToDecideToPopup();
			}

			@Override
			public void setMillisToPopup(int millisToPopup) {
				pm.setMillisToPopup(millisToPopup);
			}

			@Override
			public int getMillisToPopup() {
				return pm.getMillisToPopup();
			}

			@Override
			public void setNote(String note) {
				pm.setNote(note);
			}

			@Override
			public String getNote() {
				return pm.getNote();
			}
		};
	}

	public ProgressMonitorDM getProgressMonitor(Component parentComponent, ProgressMonitorParameters parameters) {

		return getProgressMonitor(new ProgressMonitor(parentComponent, parameters.getMessage(), parameters.getNote(), parameters.getMin(), parameters.getMax()));
	}

	@Override
	public ProgressMonitorInputStream getProgressMonitorInputStream(final Object parentComponent,
																	final Object message,
																	final InputStream inputStream)
	{
		return getProgressMonitorInputStream((Component)parentComponent, message, inputStream);
	}


	public ProgressMonitorInputStream getProgressMonitorInputStream(final Component parentComponent,
																	final Object message,
																	final InputStream inputStream)
	{
		return new ProgressMonitorInputStream(parentComponent, message, inputStream);
	}
}
