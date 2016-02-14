/*
 * Utils is created and developped by Jason MAHDJOUB (jason.mahdjoub@distri-mind.fr) at 2016.
 * Utils was developped by Jason Mahdjoub. 
 * Individual contributors are indicated by the @authors tag.
 * 
 * This file is part of Utils.
 * 
 * This is free software; you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
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

import java.util.HashMap;
import java.util.Map;

/**
 * 
 * @author Jakob Jenkov
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0
 */
public class ReadWriteLock{

    private final Map<Thread, Integer> readingThreads = new HashMap<Thread, Integer>();
    private int writeRequests=0;
    
     private int writeAccesses    = 0;
     private Thread writingThread = null;

     //private ReentrantLock lock=new ReentrantLock(true);
     //private Condition cannotContinue=lock.newCondition();

     public void tryLockRead() throws InterruptedException{
	 this.tryLockRead(-1);
     }
    public void tryLockRead(long timeout_ms) throws InterruptedException{
	
	      synchronized(this)
	      {
		  Thread callingThread = Thread.currentThread();
		  while(! canGrantReadAccess(callingThread)){
		      
			if (timeout_ms<0)
			    wait();
			else
			    wait(timeout_ms);

		  }

		  readingThreads.put(callingThread, new Integer((getReadAccessCount(callingThread) + 1)));
	      }
	    }
    
    public void lockRead(){
	while(true)
	{
	    try
	    {
		this.tryLockRead();
		return;
	    }
	    catch(InterruptedException e)
	    {
	    }
	}
    }
    
    public ReadLock getAutoCloseableReadLock()
    {
	return new ReadLock();
    }
    
    public WriteLock getAutoCloseableWriteLock()
    {
	return new WriteLock();
    }
    
    public abstract class Lock implements AutoCloseable
    {
	@Override
	public abstract void close();
    }
    public class ReadLock extends Lock
    {
	protected ReadLock()
	{
	    ReadWriteLock.this.lockRead();
	}
	
	@Override
	public void close()
	{
	    ReadWriteLock.this.unlockRead();
	}
    }
    
    public class WriteLock extends Lock
    {
	protected WriteLock()
	{
	    ReadWriteLock.this.lockWrite();
	}
	
	@Override
	public void close()
	{
	    ReadWriteLock.this.unlockWrite();
	}
    }

    private boolean canGrantReadAccess(Thread callingThread){
      if( isWriter(callingThread) ) return true;
      if( hasWriter()             ) return false;
      if( isReader(callingThread) ) return true;
      if( hasWriteRequests()      ) return false;
      return true;
    }


    public void unlockRead(){
	synchronized(this)
	{
	    
	    Thread callingThread = Thread.currentThread();
	    if(!isReader(callingThread)){
		throw new IllegalMonitorStateException("Calling Thread does not" +
			" hold a read lock on this ReadWriteLock");
	    }
	    int accessCount = getReadAccessCount(callingThread);
	    if(accessCount == 1)
	    {
		readingThreads.remove(callingThread); 
	    }
	    else 
	    { 
		readingThreads.put(callingThread, new Integer((accessCount -1))); 
	    }
	    notifyAll();
	}
    }

    public int tryLockWrite() throws InterruptedException{
	return this.tryLockWrite(-1);
    }
    public int tryLockWrite(long timeout_ms) throws InterruptedException{
	synchronized(this)
	{
	    Thread callingThread = Thread.currentThread();
	    try
	    {
		++writeRequests;
		while(! canGrantWriteAccess(callingThread)){
		    if (timeout_ms<0)
			wait();
		    else
			wait(timeout_ms);
		}
		--writeRequests;
		writingThread = callingThread;
		return ++writeAccesses;
	    }
	    catch(InterruptedException e)
	    {
		--writeRequests;
		notifyAll();
		throw e;
	    }
	}
    }

    @Override
    public String toString()
    {
	synchronized(this)
	{
	    return "Locker["+(writingThread==null?(writeAccesses+" Write"):(writeAccesses+" x "+writingThread.toString()))+","+(readingThreads.size()==0?"NoReads":(readingThreads.size()+" Reads"))+"]";
	}
    }
    
    public int lockWrite(){
	while(true)
	{
	    try
	    {
		return this.tryLockWrite();
		
	    }
	    catch(InterruptedException e)
	    {
	    }
	}
    }

    public void unlockWrite(){
	synchronized(this)
	{
	    if(!isWriter(Thread.currentThread())){
		throw new IllegalMonitorStateException("Calling Thread does not hold the write lock on this ReadWriteLock");
	    }
	    writeAccesses--;
	    if(writeAccesses == 0){
		writingThread = null;
	    }
	    if (writeAccesses<0)
		throw new IllegalMonitorStateException("The number of  unlock is greater than the number of locks");
	    
	    notifyAll();
	}
	    
    }
    public void unlockWriteAndLockRead()
    {
	synchronized(this)
	{
	    unlockWrite();
	    lockRead();
	}
    }
    public void unlockReadAndLockWrite()
    {
	synchronized(this)
	{
	    unlockRead();
	    lockWrite();
	}
    }

    private boolean canGrantWriteAccess(Thread callingThread){
      if (isWriter(callingThread)) return true;
      if(isOnlyReader(callingThread) && writingThread==null)    return true;
      if(hasReaders()) return false;
      if(writingThread == null)          return true;
      return false;
    }
    

    private int getReadAccessCount(Thread callingThread){
      Integer accessCount = readingThreads.get(callingThread);
      if(accessCount == null) 
	  return 0;
      return accessCount.intValue();
    }


    private boolean hasReaders(){
      return readingThreads.size() > 0;
    }

    private boolean isReader(Thread callingThread){
      return readingThreads.get(callingThread) != null;
    }

    private boolean isOnlyReader(Thread callingThread){
      return readingThreads.size() == 1 &&
             readingThreads.get(callingThread) != null;
    }

    private boolean hasWriter(){
      return writingThread != null;
    }

    private boolean isWriter(Thread callingThread){
      return writingThread == callingThread;
    }

    private boolean hasWriteRequests(){
        return this.writeRequests > 0;
    }

  }
