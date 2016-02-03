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

import java.io.File;
import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;

/**
 * This class represents a unique identifier.
 * Uniqueness is guaranteed over the network. 
 * The 'reinforced' class denomination means that uniqueness is also guaranteed between different instances of MadKit into the same computer.   
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.0 
 */
public class RenforcedDecentralizedIDGenerator extends AbstractDecentralizedIDGenerator
{
    /**
     * 
     */
    private static final long serialVersionUID = 4279383128706805738L;

    public RenforcedDecentralizedIDGenerator()
    {
	super();
    }
    
    
    @Override
    protected short getNewSequence()
    {
	synchronized (AbstractDecentralizedIDGenerator.class) {
	    short tmp = 0;
	    try (RandomAccessFile raf=new RandomAccessFile(new File(System.getProperty("java.io.tmpdir"), "RDIDG_MDK"), "rw"); final FileChannel channel = raf.getChannel();final FileLock lock = channel.lock();) {
		final ByteBuffer b = ByteBuffer.allocate(2);
		channel.read(b, 0);
		tmp=((short) (b.getShort(0) + 1));
		b.putShort(0, tmp).rewind();
		channel.write(b, 0);
	    } catch (IOException e) {
		e.printStackTrace();
		tmp = (short) System.nanoTime();
	    }
	    return tmp;
	}
    }

}
