package com.distrimind.util.io;
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

import com.distrimind.util.crypto.AbstractSecureRandom;
import com.distrimind.util.crypto.EncryptionProfileProvider;

import java.util.ArrayList;
import java.util.Iterator;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.13.0
 */
public class ProfileProviderTree {
	public static class EPV
	{
		private EncryptionProfileProvider encryptionProfileProvider;
		private final AbstractSecureRandom random;

		public EPV(EncryptionProfileProvider encryptionProfileProvider, AbstractSecureRandom random) {
			if (encryptionProfileProvider==null)
				throw new NullPointerException();
			if (random==null)
				throw new NullPointerException();
			this.encryptionProfileProvider = encryptionProfileProvider;
			this.random = random;
		}

		public EncryptionProfileProvider getEncryptionProfileProvider() {
			return encryptionProfileProvider;
		}

		public AbstractSecureRandom getSecureRandom() {
			return random;
		}
	}
	private static class Node
	{
		private final Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz;
		private final EPV encryptionProfileProvider;
		private ArrayList<Node> childs=null;

		Node(Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz, EncryptionProfileProvider encryptionProfileProvider, AbstractSecureRandom random) {
			if (clazz==null)
				throw new NullPointerException();
			if (encryptionProfileProvider==null && clazz!=SecureExternalizableWithEncryptionProfileProvider.class)
				throw new NullPointerException();
			if (encryptionProfileProvider!=null && random==null)
				throw new NullPointerException();
			this.clazz = clazz;
			this.encryptionProfileProvider=encryptionProfileProvider==null?null:new EPV(encryptionProfileProvider, random);
		}

		void put(Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz, EncryptionProfileProvider encryptionProfileProvider, AbstractSecureRandom random)
		{
			if (clazz==null)
				throw new NullPointerException();
			if (encryptionProfileProvider!=null && random==null)
				throw new NullPointerException();
			if (clazz==this.clazz)
				this.encryptionProfileProvider.encryptionProfileProvider=encryptionProfileProvider;
			else if (this.clazz.isAssignableFrom(clazz))
			{
				if (childs==null)
				{
					if (encryptionProfileProvider!=null)
						childs=new ArrayList<>();
				}
				else
				{
					for (Iterator<Node> it = childs.iterator(); it.hasNext();)
					{
						Node n=it.next();
						if (encryptionProfileProvider==null && n.clazz==clazz)
						{
							it.remove();
						}
						else if (n.clazz.isAssignableFrom(clazz))
						{
							n.put(clazz, encryptionProfileProvider, random);
							return;
						}
					}
				}
				if (encryptionProfileProvider!=null) {
					for (int i = 0; i < childs.size(); i++) {
						Node n = childs.get(i);
						if (clazz.isAssignableFrom(n.clazz)) {
							Node nn = new Node(clazz, encryptionProfileProvider, random);
							nn.childs = new ArrayList<>();
							nn.childs.add(n);
							childs.set(i, nn);
							return;
						}
					}
					childs.add(new Node(clazz, encryptionProfileProvider, random));
				}
			}
			else
				throw new IllegalAccessError();
		}
		EPV getEncryptionProfileProvider(Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz)
		{
			if (clazz==null)
				throw new NullPointerException();
			if (clazz==this.clazz)
				return this.encryptionProfileProvider;
			else if (this.clazz.isAssignableFrom(clazz))
			{
				if (childs!=null)
				{
					for (Node n : childs)
					{
						if (n.clazz.isAssignableFrom(clazz))
						{
							return n.getEncryptionProfileProvider(clazz);
						}
					}
				}
				return encryptionProfileProvider;
			}
			else
				throw new IllegalAccessError();
		}
	}

	private static final Node root=new Node(SecureExternalizableWithEncryptionProfileProvider.class, null, null);
	public static void putEncryptionProfileProvider(Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz, EncryptionProfileProvider encryptionProfileProvider, AbstractSecureRandom random)
	{
		synchronized (ProfileProviderTree.class) {
			if (encryptionProfileProvider == null)
				throw new NullPointerException();
			root.put(clazz, encryptionProfileProvider, random);
		}
	}
	public static void removeEncryptionProfileProvider(Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz)
	{
		synchronized (ProfileProviderTree.class) {
			root.put(clazz, null, null);
		}
	}
	public static EPV getEncryptionProfileProvider(Class<? extends SecureExternalizableWithEncryptionProfileProvider> clazz)
	{
		synchronized (ProfileProviderTree.class) {
			return root.getEncryptionProfileProvider(clazz);
		}
	}

}
