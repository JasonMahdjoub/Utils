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

import com.distrimind.util.properties.MultiFormatProperties;


/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 3.29.0
 */
public class ProgressMonitorParameters extends MultiFormatProperties {

	/**
	 * Specifies the message
	 */
	private String message=null;

	/**
	 * Specifies the additional note that is displayed along with the progress message.
	 */
	private String note=null;
	/**
	 * Specifies the minimum value.
	 */
	private int min=0;
	/**
	 * Specifies the maximum value.
	 */
	private int max=0;
	/**
	 * Specifies the amount of time to wait before deciding whether to pop up a progress monitor.
	 */
	private int millisToDecideToPopup=-1;
	/**
	 * Specifies the amount of time it will take for the popup to appear.
	 */
	private int millisToPopup=-1;


	public ProgressMonitorParameters() {
		super(null);
	}

	/**
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
	 */
	public ProgressMonitorParameters(String message, String note, int min, int max) {
		super(null);
		this.message = message;
		this.note = note;
		this.min = min;
		this.max = max;
	}


	public String getMessage() {
		return message;
	}

	public String getNote() {
		return note;
	}

	public int getMin() {
		return min;
	}

	public int getMax() {
		return max;
	}

	public void setMessage(String message) {
		this.message = message;
	}

	public void setNote(String note) {
		this.note = note;
	}

	public void setMin(int min) {
		this.min = min;
	}

	public void setMax(int max) {
		this.max = max;
	}

	public int getMillisToDecideToPopup() {
		return millisToDecideToPopup;
	}

	public void setMillisToDecideToPopup(int millisToDecideToPopup) {
		this.millisToDecideToPopup = millisToDecideToPopup;
	}

	public int getMillisToPopup() {
		return millisToPopup;
	}

	public void setMillisToPopup(int millisToPopup) {
		this.millisToPopup = millisToPopup;
	}
}
