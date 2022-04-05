package com.distrimind.util;
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

import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.util.concurrent.atomic.AtomicReference;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.23.0
 */
public class TestCleanable {
	static class Finalizer extends Cleanable.Cleaner {
		final AtomicReference<Long> ref = new AtomicReference<>(null);

		@Override
		public void performCleanup() {
			ref.set(System.currentTimeMillis());
			System.out.println(this + " : free " + ref.get());
		}
		@Override
		public String toString() {
			return "Finalizer["+Integer.toHexString(hashCode())+", hasSub="+(getNext()!=null)+"]";
		}
	}

	public static class Example implements Cleanable {


		final Finalizer f;

		public Example(boolean useSeveralFinalizers) {
			f = new Finalizer();
			registerCleaner(f);
			if (useSeveralFinalizers)
				registerCleaner(new Finalizer());
		}

		@Override
		public String toString() {
			return "Example["+Integer.toHexString(hashCode())+", hasSub="+(f.getNext()!=null)+"]";
		}
	}

	@DataProvider
	public Object[][] data()
	{
		return new Object[][]{
				{true, true, false},
				{true, false, false},
				{false, true, false},
				{false, false, false},
				{true, true, true},
				{true, false, true},
				{false, true, true},
				{false, false, true},
		};
	}
	@Test(dataProvider = "data")
	public void testCleanableAPI(boolean manuallyClean, boolean useThread, boolean useSeveralFinalizers) throws InterruptedException {

		Reference<Boolean> threadOK=new Reference<>(false);
		Runnable r=() -> {
			Example e = new Example(useSeveralFinalizers);
			AtomicReference<Long> ref = e.f.ref;
			AtomicReference<Long> ref2 ;
			if (useSeveralFinalizers)
				ref2=((Finalizer)e.f.getNext()).ref;
			else
			{
				ref2=null;
				Assert.assertNull(e.f.getNext());
			}
			System.out.println(e);
			Assert.assertFalse(e.isCleaned());
			if (manuallyClean) {
				e.clean();
				Assert.assertTrue(e.isCleaned());
			}
			//noinspection UnusedAssignment
			e = null;
			System.runFinalization();
			System.gc();


			try {
				Thread.sleep(1000);
			} catch (InterruptedException ex) {
				ex.printStackTrace();
			}
			System.runFinalization();
			System.gc();

			Assert.assertNotNull(ref.get());
			if (useSeveralFinalizers) {
				Assert.assertNotNull(ref2.get());
			}

			threadOK.set(true);
		};
		if (useThread)
		{
			Thread t=new Thread(r);
			t.start();
			t.join();

		}
		else
			r.run();
		Assert.assertTrue(threadOK.get());
		Assert.assertFalse(CleanerTools.doesCleanersContainsThisClass(Finalizer.class));
	}
}
