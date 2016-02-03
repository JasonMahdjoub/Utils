/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * MadKitGroup extension was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License Lesser as published by the Free
 * Software Foundation; either version 3.0 of the License.
 * 
 * This software is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public License for more
 * details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with this software; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA, or see the FSF
 * site: http://www.fsf.org.
 */

package com.distrimind.util;

/**
 * Represents a timer
 * 
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public final class Timer
{
    private long m_previous_time;
    private boolean m_stoped=true;
    private boolean m_paused=false;
    private long m_previous_pause_time;
    
    public Timer()
    {
    }
    
    public Timer(boolean _start)
    {
	if (_start) play();
    }
    
    public void setMilli(long ms)
    {
	if (!m_stoped)
	{
	    if (m_paused)
	    {
		m_previous_time=m_previous_pause_time-ms;
	    }
	    else
	    {
		m_previous_time=System.currentTimeMillis()-ms;
	    }
	}
	    
    }
    
    public void play()
    {
	if (m_stoped)
	{
	    m_stoped=false;
	    m_previous_time=System.currentTimeMillis();
	}
	else if (m_paused)
	{
	    m_previous_time+=System.currentTimeMillis()-m_previous_pause_time;
	    m_paused=false;
	}
    }
    
    public void stop()
    {
	m_stoped=true;
	m_paused=false;
    }
    public void pause()
    {
	if (!m_paused && !m_stoped)
	{
	    m_paused=true;
	    m_previous_pause_time=System.currentTimeMillis();
	}
    }
    public void reset()
    {
	if (m_paused)
	{
	    m_previous_time=m_previous_pause_time;
	}
	else
	{
	    m_previous_time=System.currentTimeMillis();
	}
    }
    public boolean isPaused()
    {
	return m_paused;
    }
    public boolean isStoped()
    {
	return m_stoped;
    }
    
    
    public long getMili()
    {
	if (m_stoped) return 0;
	if (m_paused) return m_previous_pause_time-m_previous_time;
	else return System.currentTimeMillis()-m_previous_time;
    }
    public float getMilif()
    {
	if (m_stoped) return 0;
	if (m_paused) return m_previous_pause_time-m_previous_time;
	else return System.currentTimeMillis()-m_previous_time;
    }
    public double getMilid()
    {
	if (m_stoped) return 0;
	if (m_paused) return m_previous_pause_time-m_previous_time;
	else return System.currentTimeMillis()-m_previous_time;
    }
    
    public long getDeltaMili()
    {
	if (m_stoped) return 0;
	long res;
	if (m_paused) 
	    res=m_previous_pause_time-m_previous_time;
	else 
	    res=System.currentTimeMillis()-m_previous_time;
	m_previous_time+=res;
	return res;
    }
    public float getDeltaMilif()
    {
	if (m_stoped) return 0.0f;
	float res;
	if (m_paused) 
	    res=m_previous_pause_time-m_previous_time;
	else 
	    res=System.currentTimeMillis()-m_previous_time;
	m_previous_time+=res;
	return res;
    }
    
    public double getDeltaMilid()
    {
	if (m_stoped) return 0.0f;
	float res;
	if (m_paused) 
	    res=m_previous_pause_time-m_previous_time;
	else 
	    res=System.currentTimeMillis()-m_previous_time;
	m_previous_time+=res;
	return res;
    }
    
    
    
}
