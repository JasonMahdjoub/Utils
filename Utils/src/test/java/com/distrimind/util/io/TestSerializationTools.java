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

import com.distrimind.util.DecentralizedIDGenerator;
import com.distrimind.util.RenforcedDecentralizedIDGenerator;
import com.distrimind.util.SecuredDecentralizedID;
import com.distrimind.util.crypto.*;
import com.distrimind.util.harddrive.FilePermissions;
import org.testng.Assert;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.*;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since OOD 5.7.0
 */
public class TestSerializationTools {
	interface SpecificWriter
	{
		void write(RandomOutputStream out, Object o, boolean nullSupport, int maxSize) throws IOException;

	}
	interface SpecificReader
	{
		Object read(RandomInputStream in, boolean nullSupport, int maxSize) throws IOException, ClassNotFoundException;

	}
	interface SpecificSizeComputer
	{
		int getInternalSize(Object o, int maxSize);

	}
	@DataProvider(name="dataProvider")
	public Object[][] dataProvider() throws NoSuchProviderException, NoSuchAlgorithmException, IOException {
		ArrayList<Object[]> lp=new ArrayList<>();
		for (boolean nullSupport : new boolean[]{true, false}) {

			lp.add(new Object[]{
				nullSupport,
				Arrays.asList(Arrays.asList("s1", "s2"),
						Arrays.asList("s3", "s4", "s5"),
						new LinkedList<>(Arrays.asList("s6", "s6")),
						new HashSet<>(Arrays.asList("s7", "s8"))),
					true,
				(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeCollection((Collection<?>)o, nullSupport1, maxSize),
				(SpecificReader) SecuredObjectInputStream::readCollection,
				(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Collection<?>)v, m)
			});

			Map<String, Integer> map=new HashMap<>();
			map.put("k1", 1);
			map.put("k2", 2);
			map.put("k3", 3);
			Map<String, Integer> map2=new HashMap<>();
			map2.put("k4", 4);
			map2.put("k5", 5);
			map2.put("k6", 6);
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(map, map2),
					true,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeMap((Map<?,?>)o, nullSupport1, maxSize),
					(SpecificReader) SecuredObjectInputStream::readMap,
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Map<?,?>)v, m)

			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(new Object[]{"s1", "s2"},
							new Object[]{"s3", "s3"}),
					true,
					(SpecificWriter) SecuredObjectOutputStream::writeObject,
					(SpecificReader) SecuredObjectInputStream::readObject,
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Object[])v, m)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(new byte[]{(byte)142, 41},
							new byte[]{57, 45}),
					true,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeBytesArray((byte[])o, nullSupport1, maxSize),
					(SpecificReader) SecuredObjectInputStream::readBytesArray,
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((byte[])v, m)
			});

			/*lp.add(new Object[]{
					nullSupport,
					Arrays.asList(new byte[][]{
									{(byte)142, 41},
									{57, 45}
								}
								),
					true,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.write2DBytesArray((byte[][])o, nullSupport1, true, maxSize, 1000),
					(SpecificReader) (in, supportNull1, maxSize) -> in.read2DBytesArray(nullSupport, true, maxSize, 1000 )
			});*/
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList("string1",
							"string2"),
					true,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeString((String)o, nullSupport1, maxSize),
					(SpecificReader) SecuredObjectInputStream::readString,
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((String)v, m)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList("string1".toCharArray(),
							"string2".toCharArray()),
					true,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeChars((char[])o, nullSupport1, maxSize),
					(SpecificReader) SecuredObjectInputStream::readChars,
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((char[])v, m)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(BigDecimal.valueOf(5L),
							BigDecimal.valueOf(15.6)),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeBigDecimal((BigDecimal)o, nullSupport1),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readBigDecimal(supportNull1),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((BigDecimal)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(BigInteger.valueOf(5L),
							BigInteger.valueOf(15)),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeBigInteger((BigInteger)o, nullSupport1),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readBigInteger(supportNull1),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((BigInteger) v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(FilePermissions.from("rwx"),
							FilePermissions.from("r-x")),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeObject(o, nullSupport1),
					(SpecificReader) SecuredObjectInputStream::readObject,
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((FilePermissions)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(SymmetricEncryptionType.DEFAULT.getKeyGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKey(),
							ASymmetricAuthenticatedSignatureType.DEFAULT.getKeyPairGenerator(SecureRandomType.DEFAULT.getInstance(null)).generateKeyPair(),
							SymmetricEncryptionType.AES_CTR,
							ASymmetricAuthenticatedSignatureType.BC_FIPS_SHA256withRSA,
							InetAddress.getByName("192.168.0.14"),
							InetAddress.getByName("192.168.0.15"),
							new InetSocketAddress(InetAddress.getByName( "192.168.0.16"), 200),
							new DecentralizedIDGenerator(),
							new RenforcedDecentralizedIDGenerator(),
							new SecuredDecentralizedID(new DecentralizedIDGenerator(), SecureRandomType.DEFAULT.getInstance(null)),
							new HybridASymmetricAuthenticatedSignatureType(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA2_512_256),
							new HybridASymmetricEncryptionType(ASymmetricEncryptionType.RSA_OAEPWithSHA256AndMGF1Padding, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256),
							new HybridASymmetricAuthenticatedSignatureType(ASymmetricAuthenticatedSignatureType.BC_FIPS_Ed448, ASymmetricAuthenticatedSignatureType.BCPQC_SPHINCS256_SHA2_512_256).generateKeyPair(SecureRandomType.DEFAULT.getInstance(null)),
							new HybridASymmetricEncryptionType(ASymmetricEncryptionType.RSA_OAEPWithSHA256AndMGF1Padding, ASymmetricEncryptionType.BCPQC_MCELIECE_FUJISAKI_CCA2_SHA256).generateKeyPair(SecureRandomType.DEFAULT.getInstance(null))
					),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeObject(o, nullSupport1),
					(SpecificReader) SecuredObjectInputStream::readObject,
					(SpecificSizeComputer) SerializationTools::getInternalSize
			});

			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(3L,
							4L),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeLong((Long)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readLong(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Long)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList((short)5,
							(short)6),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeShort((Short)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readShort(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Short)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList((byte)7,
							(byte)8),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeByte((Byte)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readByte(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Byte)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(9,
							10),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeInt((Integer)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readInt(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Integer)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(1.5,
							2.5),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeDouble((Double)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readDouble(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Double)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(1.5f,
							2.5f),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeFloat((Float)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readFloat(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Float)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList('a',
							'b'),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeChar((Character)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readChar(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Character)v)
			});
			lp.add(new Object[]{
					nullSupport,
					Arrays.asList(true,
							false),
					false,
					(SpecificWriter) (out, o, nullSupport1, maxSize) -> out.writeBoolean((Boolean)o),
					(SpecificReader) (in, supportNull1, maxSize) -> in.readBoolean(),
					(SpecificSizeComputer)	(v, m)->SerializationTools.getInternalSize((Boolean)v)
			});
		}
		Object[][] res=new Object[lp.size()][3];
		for (int i=0;i<res.length;i++)
			res[i]=lp.get(i);
		return res;
	}
	private void write(RandomOutputStream out, SpecificSizeComputer specificSizeComputer, boolean nullSupport, Object o, SpecificWriter specificWriter, int sizeMax) throws IOException {
		Assert.assertTrue(SerializationTools.isSerializable(o));
		long p=out.currentPosition();
		long cs=specificSizeComputer.getInternalSize(o, sizeMax);
		specificWriter.write(out, o, nullSupport, sizeMax);
		long l=out.currentPosition()-p;
		Assert.assertTrue(l<=cs, "l="+l+", cs="+cs+" o.class="+o.getClass());
		Assert.assertTrue(l>=cs-1, "l="+l+", cs="+cs+" o.class="+o.getClass());
		p=out.currentPosition();
		cs=SerializationTools.getInternalSize(o, sizeMax);
		out.writeObject(o, nullSupport, sizeMax);
		l=out.currentPosition()-p;
		Assert.assertTrue(l<=cs);
		Assert.assertTrue(l>=cs-SerializationTools.getObjectCodeSizeBytes()-1);

	}
	@Test(dataProvider = "dataProvider")
	public void testSerialization(boolean nullSupport, List<Object> objectsToTests, boolean areCollections, SpecificWriter specificWriter, SpecificReader specificReader, SpecificSizeComputer specificSizeComputer) throws ClassNotFoundException {
		try(RandomByteArrayOutputStream out=new RandomByteArrayOutputStream()) {

			try {
				if ((!(objectsToTests.get(0) instanceof Number) && !(objectsToTests.get(0) instanceof Character)  && !(objectsToTests.get(0) instanceof Boolean)) || (objectsToTests.get(0) instanceof BigDecimal) || (objectsToTests.get(0) instanceof BigInteger)) {
					specificWriter.write(out, null, nullSupport, 1000);
					Assert.assertTrue(nullSupport);
				}
				out.writeObject(null, nullSupport);
				Assert.assertTrue(nullSupport);
				out.flush();
			}
			catch (IOException e)
			{
				Assert.assertFalse(nullSupport);
			}
			try {

				for (Object o : objectsToTests)
				{
					Assert.assertTrue(SerializationTools.isSerializable(o), "o.class="+o.getClass());
					write(out, specificSizeComputer, nullSupport, o, specificWriter, 100);
					write(out, specificSizeComputer, nullSupport, o, specificWriter, 1000);
					write(out, specificSizeComputer, nullSupport, o, specificWriter, 1<<22);
					write(out, specificSizeComputer, nullSupport, o, specificWriter, Integer.MAX_VALUE/2);
				}
				if (areCollections) {
					try {
						specificWriter.write(out, objectsToTests.get(0), nullSupport, 1);
						Assert.fail();
					}
					catch (IllegalArgumentException ignored)
					{

					}
					specificWriter.write(out, objectsToTests.get(0), nullSupport, 100);
				}

				out.flush();
				try(RandomByteArrayInputStream in=new RandomByteArrayInputStream(out.getBytes()))
				{
					if (nullSupport) {
						if ((!(objectsToTests.get(0) instanceof Number) && !(objectsToTests.get(0) instanceof Character) && !(objectsToTests.get(0) instanceof Boolean)) || (objectsToTests.get(0) instanceof BigDecimal) || (objectsToTests.get(0) instanceof BigInteger))
							Assert.assertNull(specificReader.read(in, true, 1000));
						Assert.assertNull(in.readObject(true, 1000));
					}
					for (Object o : objectsToTests)
					{
						Assert.assertEquals(specificReader.read(in, nullSupport, 100), o);
						Assert.assertEquals(in.readObject(nullSupport, 100), o);
						Assert.assertEquals(specificReader.read(in, nullSupport, 1000), o);
						Assert.assertEquals(in.readObject(nullSupport, 1000), o);
						Assert.assertEquals(specificReader.read(in, nullSupport, 1<<22), o);
						Assert.assertEquals(in.readObject(nullSupport, 1<<22), o);
						Assert.assertEquals(specificReader.read(in, nullSupport, Integer.MAX_VALUE/2), o);
						Assert.assertEquals(in.readObject(nullSupport, Integer.MAX_VALUE/2), o);
					}
					if (areCollections) {
						try {
							specificReader.read(in, nullSupport, 1);
							Assert.fail();
						} catch (MessageExternalizationException ignored) {

						}
					}
				}

			} catch (IOException e) {
				Assert.fail("", e);
			}

		}
	}
}
