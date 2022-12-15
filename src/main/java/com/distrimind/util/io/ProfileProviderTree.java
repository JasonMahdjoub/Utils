package com.distrimind.util.io;
/*
Copyright or © or Corp. Jason Mahdjoub (01/04/2013)

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

import java.util.*;
import java.util.function.Function;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since Utils 5.13.0
 */
public class ProfileProviderTree {
	public static class EPV
	{
		private final EncryptionProfileProvider encryptionProfileProvider;
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
		private final Class<? extends SecureExternalizableThatUseEncryptionProfileProvider> clazz;
		private Function<SecureExternalizableThatUseEncryptionProfileProvider, EPV> functionThatGivesEncryptionProfileProvider;
		private List<Node> childs=null;


		Node() {
			this.clazz = SecureExternalizableThatUseEncryptionProfileProvider.class;
			this.functionThatGivesEncryptionProfileProvider=null;
		}
		Node(Class<? extends SecureExternalizableWithEncryptionEncoder> clazz, Function<SecureExternalizableThatUseEncryptionProfileProvider, EPV> functionThatGivesEncryptionProfileProvider) {
			if (clazz==null)
				throw new NullPointerException();
			if (functionThatGivesEncryptionProfileProvider==null)
				throw new NullPointerException();


			this.clazz = clazz;
			this.functionThatGivesEncryptionProfileProvider=functionThatGivesEncryptionProfileProvider;
		}

		void put(Class<? extends SecureExternalizableWithEncryptionEncoder> clazz, Function<SecureExternalizableThatUseEncryptionProfileProvider, EPV> functionThatGivesEncryptionProfileProvider)
		{
			if (clazz==null)
				throw new NullPointerException();
			if (functionThatGivesEncryptionProfileProvider==null)
				throw new NullPointerException();
			if (clazz==this.clazz) {
				this.functionThatGivesEncryptionProfileProvider=functionThatGivesEncryptionProfileProvider;
			}
			else if (this.clazz.isAssignableFrom(clazz))
			{
				if (childs==null)
				{
					childs=new ArrayList<>();
				}
				else
				{
					for (Node n : childs)
					{
						if (n.clazz.isAssignableFrom(clazz))
						{
							n.put(clazz, functionThatGivesEncryptionProfileProvider);
							return;
						}
					}
				}
				for (int i = 0; i < childs.size(); i++) {
					Node n = childs.get(i);
					if (clazz.isAssignableFrom(n.clazz)) {
						Node nn = new Node(clazz, functionThatGivesEncryptionProfileProvider);
						nn.childs = new ArrayList<>();
						nn.childs.add(n);
						childs.set(i, nn);
						return;
					}
				}
				childs.add(new Node(clazz, functionThatGivesEncryptionProfileProvider));
			}
			else
				throw new IllegalAccessError();
		}
		boolean remove(Class<? extends SecureExternalizableWithEncryptionEncoder> clazz)
		{
			if (clazz==null)
				throw new NullPointerException();
			if (functionThatGivesEncryptionProfileProvider==null)
				throw new NullPointerException();
			if (clazz==this.clazz) {
				throw new IllegalArgumentException();
			}
			else if (this.clazz.isAssignableFrom(clazz))
			{
				if (childs==null)
				{
					return false;
				}
				else
				{
					for (Iterator<Node> it=childs.iterator();it.hasNext();)
					{
						Node n=it.next();
						if (n.clazz==clazz)
							it.remove();
						else if (n.clazz.isAssignableFrom(clazz))
						{
							return n.remove(clazz);
						}
					}
				}
				return false;
			}
			else
				throw new IllegalAccessError();
		}
		EPV getEncryptionProfileProvider(SecureExternalizableThatUseEncryptionProfileProvider externalizable)
		{
			if (externalizable==null)
				throw new NullPointerException();
			Class<? extends SecureExternalizableThatUseEncryptionProfileProvider> clazz=externalizable.getClass();
			if (clazz==this.clazz) {
				return this.functionThatGivesEncryptionProfileProvider.apply(externalizable);
			}
			else if (this.clazz.isAssignableFrom(clazz))
			{
				if (childs!=null)
				{
					for (Node n : childs)
					{
						if (n.clazz.isAssignableFrom(clazz))
						{
							return n.getEncryptionProfileProvider(externalizable);
						}
					}
				}
				return this.functionThatGivesEncryptionProfileProvider.apply(externalizable);
			}
			else
				throw new IllegalAccessError();
		}
	}

	private static final Node root=new Node();
	public static void putEncryptionProfileProvider(Class<? extends SecureExternalizableWithEncryptionEncoder> clazz, Function<SecureExternalizableThatUseEncryptionProfileProvider, EPV> functionThatGivesEncryptionProfileProvider)
	{
		synchronized (ProfileProviderTree.class) {
			root.put(clazz, functionThatGivesEncryptionProfileProvider);
		}
	}
	public static boolean removeEncryptionProfileProvider(Class<? extends SecureExternalizableWithEncryptionEncoder> clazz)
	{
		synchronized (ProfileProviderTree.class) {
			return root.remove(clazz);
		}
	}
	public static EPV getEncryptionProfileProvider(SecureExternalizableThatUseEncryptionProfileProvider externalizable)
	{
		synchronized (ProfileProviderTree.class) {
			return root.getEncryptionProfileProvider(externalizable);
		}
	}

}
