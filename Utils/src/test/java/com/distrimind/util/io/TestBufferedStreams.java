package com.distrimind.util.io;
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

import org.testng.Assert;
import org.testng.annotations.Test;

import java.io.IOException;
import java.util.Random;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 1.30.0
 */
public class TestBufferedStreams {

	@Test(invocationCount = 16, threadPoolSize = 16)
	public void testBufferedInputStream() throws IOException {
		Random rand=new Random(System.currentTimeMillis());
		byte[] tab=new byte[25000000];
		rand.nextBytes(tab);
		RandomByteArrayInputStream ris=new RandomByteArrayInputStream(tab);
		BufferedRandomInputStream inputStream=new BufferedRandomInputStream(new RandomByteArrayInputStream(tab));

		testBufferedInputStream(rand, inputStream, 9000, ris);
	}

	@SuppressWarnings("ResultOfMethodCallIgnored")
	private void testBufferedInputStream(Random rand, BufferedRandomInputStream inputStream, int maxCycles, RandomInputStream ris) throws IOException {

		Assert.assertEquals(inputStream.length(), ris.length());
		for (int i=0;i<maxCycles;i++)
		{
			if (i%(maxCycles/100)==0)
				System.out.println(((i*100)/maxCycles));
			Assert.assertEquals(inputStream.available(), ris.available());
			if (rand.nextDouble()<0.1) {
				if (rand.nextDouble()<0.5) {
					long pos = (long) (Math.random() * inputStream.length());
					inputStream.seek(pos);
					ris.seek(pos);
				}
				else
				{
					long skip=(long)(Math.random()*Math.min(16000, inputStream.available()));
					if (rand.nextDouble()<0.5) {
						inputStream.skip(skip);
						ris.skip(skip);
					}
					else
					{
						inputStream.skipBytes((int)skip);
						ris.skipBytes((int)skip);
					}
				}
			}
			Assert.assertEquals(inputStream.currentPosition(), ris.currentPosition());
			if (inputStream.available()>0) {
				if (rand.nextDouble() < 0.5) {
					Assert.assertEquals(inputStream.read(), ris.read());
				}
				else
				{
					byte[] bytes;
					byte[] bytes2;
					if (rand.nextDouble()<0.5)
					{
						bytes=new byte[(int)(Math.random()*inputStream.available())];
						bytes2=new byte[bytes.length];
						if (rand.nextDouble() < 0.5) {
							inputStream.readNBytes(bytes, 0, bytes.length);
							ris.readNBytes(bytes2, 0, bytes2.length);
						} else {
							inputStream.readFully(bytes);
							ris.readFully(bytes2);

						}
					}
					else
					{
						bytes=inputStream.readNBytes((int)(Math.random()*inputStream.available()));
						bytes2=ris.readNBytes(bytes.length);
					}


					Assert.assertEquals(bytes, bytes2);

				}
			}

		}
	}

	@Test(dependsOnMethods = "testBufferedInputStream", invocationCount = 200, threadPoolSize = 16)
	public void testBufferedOutputStream() throws IOException {
		RandomByteArrayOutputStream dest=new RandomByteArrayOutputStream();
		BufferedRandomOutputStream outputStream=new BufferedRandomOutputStream(dest);
		RandomByteArrayOutputStream dest2=new RandomByteArrayOutputStream();
		int maxCycles=50000;
		Random rand=new Random(System.currentTimeMillis());
		for (int i=0;i<maxCycles;i++)
		{
			if (i%(maxCycles/100)==0)
				System.out.println(((i*100)/maxCycles));
			if (outputStream.length()>100 && rand.nextDouble()<0.1)
			{
				if (rand.nextDouble()<0.2)
				{
					if (rand.nextDouble()<0.5) {
						outputStream.setLength(outputStream.length()*4/5);
						dest2.setLength(dest2.length()*4/5);
					}
					else
					{
						outputStream.ensureLength(outputStream.length()*4/5);
						dest2.ensureLength(dest2.length()*4/5);
					}
				}
				else
				{
					long pos=(long)(Math.random()*outputStream.length());
					outputStream.seek(pos);
					dest2.seek(pos);
				}
			}
			Assert.assertEquals(outputStream.currentPosition(), dest2.currentPosition());
			if (rand.nextDouble()>0.5)
			{
				int v=rand.nextInt();
				outputStream.write(v);
				dest2.write(v);
			}
			else
			{
				byte[] bytes=new byte[(int)(20+Math.random()*20000)];
				rand.nextBytes(bytes);
				outputStream.write(bytes);
				dest2.write(bytes);
			}
			if (rand.nextDouble()<0.05) {

				StringBuilder s= new StringBuilder("test");
				while(Math.random()<0.3)
					s.append("0");
				outputStream.writeUTF(s.toString());
				dest2.writeUTF(s.toString());
			}
			if (rand.nextDouble()<0.05)
				outputStream.flush();
			Assert.assertEquals(outputStream.length(),dest2.length() );
		}

		outputStream.flush();
		dest2.flush();
		Assert.assertEquals(outputStream.length(),dest2.length() );
		Assert.assertEquals(dest.length(),dest2.length() );
		BufferedRandomInputStream inputStream=(BufferedRandomInputStream)outputStream.getRandomInputStream();
		RandomInputStream ris=dest2.getRandomInputStream();

		Assert.assertEquals(inputStream.length(), outputStream.length());
		testBufferedInputStream(rand, inputStream, maxCycles, ris);
	}

}
