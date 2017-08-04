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
package com.distrimind.util.sizeof;

import java.util.ArrayList;

public class Main {
	static class bidule {
		public int truc[] = new int[1];
	}

	static class truc {
		@SuppressWarnings("unused")
		private int a = 0;

		private ArrayList<Float> v = new ArrayList<Float>();

		truc() {
			for (int i = 0; i < 10; i++) {
				v.add(new Float(0));
			}
		}
	}

	static class truc1 {
		@SuppressWarnings("unused")
		private int a = 0;

		@DontComputeSize(depth = 1)
		private ArrayList<Float> v = new ArrayList<Float>();

		truc1() {
			for (int i = 0; i < 10; i++) {
				v.add(new Float(0));
			}
		}
	}

	static class truc2 {
		@SuppressWarnings("unused")
		private int a = 0;

		@DontComputeSize(depth = 2)
		private ArrayList<Float> v = new ArrayList<Float>();

		truc2() {
			for (int i = 0; i < 10; i++) {
				v.add(new Float(0));
			}
		}
	}

	static class truc3 {
		@SuppressWarnings("unused")
		private int a = 0;

		@DontComputeSizeForInnerCollectionElements
		private ArrayList<Float> v = new ArrayList<Float>();

		truc3() {
			for (int i = 0; i < 10; i++) {
				v.add(new Float(0));
			}
		}

	}

	public static void main(String args[]) throws SecurityException {
		truc t = new truc();
		truc1 t1 = new truc1();
		truc2 t2 = new truc2();
		truc3 t3 = new truc3();
		System.out.println(ObjectSizer.sizeOf(t));
		System.out.println(ObjectSizer.sizeOf(t1));
		System.out.println(ObjectSizer.sizeOf(t2));
		System.out.println(ObjectSizer.sizeOf(t3));
		System.out.println(ObjectSizer.sizeOf(2));
	}

}
