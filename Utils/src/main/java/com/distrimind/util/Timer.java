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

/**
 * Represents a timer
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public final class Timer {
	private long m_previous_time;

	private boolean m_stoped = true;

	private boolean m_paused = false;

	private long m_previous_pause_time;

	public Timer() {
	}

	public Timer(boolean _start) {
		if (_start)
			play();
	}

	public long getDeltaMili() {
		if (m_stoped)
			return 0;
		long res;
		if (m_paused)
			res = m_previous_pause_time - m_previous_time;
		else
			res = System.currentTimeMillis() - m_previous_time;
		m_previous_time += res;
		return res;
	}

	public double getDeltaMilid() {
		return (double)getDeltaMili();
	}

	public float getDeltaMilif() {
		return (float)getDeltaMili();
	}

	public long getMili() {
		if (m_stoped)
			return 0;
		if (m_paused)
			return m_previous_pause_time - m_previous_time;
		else
			return System.currentTimeMillis() - m_previous_time;
	}

	public double getMilid() {
		return (double)getMili();
	}

	public float getMilif() {
		return (float)getMili();
	}

	public boolean isPaused() {
		return m_paused;
	}

	public boolean isStoped() {
		return m_stoped;
	}

	public void pause() {
		if (!m_paused && !m_stoped) {
			m_paused = true;
			m_previous_pause_time = System.currentTimeMillis();
		}
	}

	public void play() {
		if (m_stoped) {
			m_stoped = false;
			m_previous_time = System.currentTimeMillis();
		} else if (m_paused) {
			m_previous_time += System.currentTimeMillis() - m_previous_pause_time;
			m_paused = false;
		}
	}

	public void reset() {
		if (m_paused) {
			m_previous_time = m_previous_pause_time;
		} else {
			m_previous_time = System.currentTimeMillis();
		}
	}

	public void setMilli(long ms) {
		if (!m_stoped) {
			if (m_paused) {
				m_previous_time = m_previous_pause_time - ms;
			} else {
				m_previous_time = System.currentTimeMillis() - ms;
			}
		}

	}

	public void stop() {
		m_stoped = true;
		m_paused = false;
	}

}
