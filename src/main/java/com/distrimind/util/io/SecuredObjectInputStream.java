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


import com.distrimind.util.AbstractDecentralizedID;
import com.distrimind.util.FileTools;
import com.distrimind.util.crypto.*;
import com.distrimind.util.data_buffers.WrappedData;
import com.distrimind.util.data_buffers.WrappedString;

import java.io.*;
import java.math.BigDecimal;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.util.Collection;
import java.util.Date;
import java.util.Map;
import java.util.Objects;

/**
 * @author Jason Mahdjoub
 * @version 2.3
 * @since Utils 4.4.0
 */
public abstract class SecuredObjectInputStream extends InputStream implements DataInput  {
	private static final int DEFAULT_BUFFER_SIZE = FileTools.BUFFER_SIZE;
	//private static final int MAX_BUFFER_SIZE = Integer.MAX_VALUE - 8;

	private SerializationTools.ObjectResolver objectResolver=new SerializationTools.ObjectResolver();

	private byte[] transferBuffer1=null, transferBuffer2=null;

	// public void skipBytes(int _nb) throws InputStreamException;
	/**
	 * Returns the current position in this stream.
	 *
	 * @return the offset from the beginning of the stream, in bytes, at which the
	 *         next read or write occurs.
	 * @exception IOException
	 *                if an I/O error occurs.
	 */
	public abstract long currentPosition() throws IOException;

	@Override
	public final boolean readBoolean() throws IOException {
		int ch = read();
		if (ch < 0)
			throw new EOFException();
		return (ch != 0);
	}

	@Override
	public final byte readByte() throws IOException {
		int ch = read();
		if (ch < 0)
			throw new EOFException();
		return (byte)(ch);
	}

	@Override
	public final int readUnsignedByte() throws IOException {
		int ch = read();
		if (ch < 0)
			throw new EOFException();
		return ch;
	}


	@Override
	public final short readShort() throws IOException {
		int ch1 = read();
		int ch2 = read();
		if ((ch1 | ch2) < 0)
			throw new EOFException();
		return (short)((ch1 << 8) + (ch2));
	}
	public final int readUnsignedInt8Bits() throws IOException {
		return readUnsignedByte();
	}
	public final int readUnsignedInt16Bits() throws IOException {
		return readUnsignedShort();
	}
	@Override
	public final int readUnsignedShort() throws IOException {
		int ch1 = read();
		int ch2 = read();
		if ((ch1 | ch2) < 0)
			throw new EOFException();
		return (ch1 << 8) + (ch2);
	}

	public final int readUnsignedInt24Bits() throws IOException {
		int ch1 = read();
		int ch2 = read();
		int ch3 = read();
		if ((ch1 | ch2 | ch3) < 0)
			throw new EOFException();
		return (ch1 << 16) + (ch2 << 8) + (ch3);
	}
	public long readUnsignedInt(int valueSizeInBytes) throws IOException {
		if (valueSizeInBytes<1)
			return -1;
		else if (valueSizeInBytes<=8) {
			int i=valueSizeInBytes-1;
			long res=0;
			int decal=0;
			while(--i>0)
			{
				if (decal==0)
					res += (read() & 0xFFL);
				else
					res+=(read() & 0xFFL) << decal;
				decal+=8;
			}
			return res;
		}
		else
			throw new IllegalArgumentException();
	}

	@Override
	public final char readChar() throws IOException {
		int ch1 = read();
		int ch2 = read();
		if ((ch1 | ch2) < 0)
			throw new EOFException();
		return (char)((ch1 << 8) + (ch2));
	}

	@Override
	public final int readInt() throws IOException {
		int ch1 = read();
		int ch2 = read();
		int ch3 = read();
		int ch4 = read();
		if ((ch1 | ch2 | ch3 | ch4) < 0)
			throw new EOFException();
		return ((ch1 << 24) + (ch2 << 16) + (ch3 << 8) + (ch4));
	}

	private final byte[] readBuffer = new byte[8];


	@Override
	public final long readLong() throws IOException {
		readFully(readBuffer, 0, 8);
		return (((long)readBuffer[0] << 56) +
				((long)(readBuffer[1] & 255) << 48) +
				((long)(readBuffer[2] & 255) << 40) +
				((long)(readBuffer[3] & 255) << 32) +
				((long)(readBuffer[4] & 255) << 24) +
				((readBuffer[5] & 255) << 16) +
				((readBuffer[6] & 255) <<  8) +
				((readBuffer[7] & 255)));
	}

	@Override
	public final float readFloat() throws IOException {
		return Float.intBitsToFloat(readInt());
	}

	@Override
	public final double readDouble() throws IOException {
		return Double.longBitsToDouble(readLong());
	}

	@Deprecated
	@Override
	public final String readUTF() throws IOException {
		throw new IOException(new IllegalAccessError());
	}



	@Override
	public abstract int available() throws IOException;

	byte[] readFully(int len) throws IOException
	{
		if (len < 0) {
			throw new IllegalArgumentException("len < 0");
		}
		byte[] res=new byte[len];
		readFully(res);
		return res;
	}

	public byte[] readNBytes(int len) throws IOException {
		return readFully(Math.min(len, available()));
		/*List<byte[]> bufs = null;
		byte[] result = null;
		int total = 0;
		int remaining = len;
		int n;
		do {
			byte[] buf = new byte[Math.min(remaining, DEFAULT_BUFFER_SIZE)];
			int nread = 0;

			// read to EOF which may read more or less than buffer size
			while ((n = read(buf, nread,
					Math.min(buf.length - nread, remaining))) > 0) {
				nread += n;
				remaining -= n;
			}

			if (nread > 0) {
				if (MAX_BUFFER_SIZE - total < nread) {
					throw new OutOfMemoryError("Required array size too large");
				}
				total += nread;
				if (result == null) {
					result = buf;
				} else {
					if (bufs == null) {
						bufs = new ArrayList<>();
						bufs.add(result);
					}
					bufs.add(buf);
				}
			}
			// if the last call to read returned -1 or the number of bytes
			// requested have been read then break
		} while (n >= 0 && remaining > 0);

		if (bufs == null) {
			if (result == null) {
				return new byte[0];
			}
			return result.length == total ?
					result : Arrays.copyOf(result, total);
		}

		result = new byte[total];
		int offset = 0;
		remaining = total;
		for (byte[] b : bufs) {
			int count = Math.min(b.length, remaining);
			System.arraycopy(b, 0, result, offset, count);
			offset += count;
			remaining -= count;
		}

		return result;*/
	}



	public byte[] readAllBytes() throws IOException {
		return readNBytes(Integer.MAX_VALUE);
	}
	public long transferTo(OutputStream out) throws IOException {
		return transferTo(out, -1);
	}
	public long transferTo(OutputStream out, long maxLength) throws IOException {
		if (maxLength==0)
			return 0;
		Objects.requireNonNull(out, "out");
		long transferred = 0;
		if (transferBuffer1==null)
			transferBuffer1 = new byte[DEFAULT_BUFFER_SIZE];
		if (transferBuffer2==null)
			transferBuffer2 = new byte[DEFAULT_BUFFER_SIZE];

		byte[] buffer=transferBuffer1;
		int read;

		while ((read = this.read(buffer, 0, maxLength>=0?(int)Math.min(maxLength, DEFAULT_BUFFER_SIZE):DEFAULT_BUFFER_SIZE)) >= 0) {
			if (read==0)
				continue;
			out.write(buffer, 0, read);
			transferred += read;
			if (maxLength>=0) {
				maxLength -= read;
				if (maxLength == 0)
					break;
			}
			if (buffer==transferBuffer1)
				buffer=transferBuffer2;
			else
				buffer=transferBuffer1;
		}
		return transferred;
	}

	public int readNBytes(byte[] b, int off, int len) throws IOException {
		int n = 0;
		while (n < len) {
			int count = read(b, off + n, len - n);
			if (count < 0)
				break;
			n += count;
		}
		return n;
	}

	public byte[][] read2DBytesArray(boolean nullAcceptedForLevel1, boolean nullAcceptedForLevel2, int maxLevel1SizeInByte, int maxLevel2SizeInByte) throws IOException {
		return SerializationTools.readBytes2D(this, maxLevel1SizeInByte, maxLevel2SizeInByte, nullAcceptedForLevel1, nullAcceptedForLevel2);
	}

	public byte[] readBytesArray(boolean nullAccepted, int maxSizeInBytes) throws IOException {
		return SerializationTools.readBytes(this, nullAccepted, maxSizeInBytes);
	}
	public int readBytesArray(byte[] array, boolean nullAccepted) throws IOException {
		return SerializationTools.readBytes(this, nullAccepted, array, 0, array.length);
	}

	public int readBytesArray(byte[] array, int offset, boolean nullAccepted, int maxSizeBytes) throws IOException {
		return SerializationTools.readBytes(this, nullAccepted, array, offset, maxSizeBytes);
	}

	public char[] readChars(boolean nullAccepted, int maxCharsNumber) throws IOException {
		return SerializationTools.readChars(this, (int)Math.min(2L*maxCharsNumber, Integer.MAX_VALUE), nullAccepted);
	}
	public File readFile(boolean nullAccepted) throws IOException {
		return readFile(nullAccepted, SerializationTools.DEFAULT_MAX_FILE_NAME_LENGTH);
	}
	public File readFile(boolean nullAccepted, int maxCharsNumber) throws IOException {
		return SerializationTools.readFile(this, (int)Math.min(2L*maxCharsNumber, Integer.MAX_VALUE), nullAccepted);
	}
	/*public Path readPath(boolean nullAccepted) throws IOException {
		return readPath(nullAccepted, SerializationTools.DEFAULT_MAX_FILE_NAME_LENGTH);
	}
	public Path readPath(boolean nullAccepted, int maxCharsNumber) throws IOException {
		return SerializationTools.readPath(this, (int)Math.min(2L*maxCharsNumber, Integer.MAX_VALUE), nullAccepted);
	}*/
	public String readString(boolean nullAccepted, int maxCharsNumber) throws IOException {
		return SerializationTools.readString(this, (int)Math.min(2L*maxCharsNumber, Integer.MAX_VALUE), nullAccepted);
	}
	public BigInteger readBigInteger(boolean nullAccepted) throws IOException {
		return SerializationTools.readBigInteger(this, nullAccepted);
	}
	public BigDecimal readBigDecimal(boolean nullAccepted) throws IOException {
		return SerializationTools.readBigDecimal(this, nullAccepted);
	}

	public <T, C extends Collection<T>> C readCollection(boolean nullAccepted, int globalMaxSizeInBytes, Class<T> elementsClass) throws IOException, ClassNotFoundException {
		return readCollection(nullAccepted, globalMaxSizeInBytes, true, elementsClass);
	}

	public <K, V, M extends Map<K, V>> M readMap(boolean nullAccepted, int globalMaxSizeInBytes, Class<K> keysClass, Class<V> valuesClass) throws IOException, ClassNotFoundException {
		return readMap(nullAccepted, globalMaxSizeInBytes, true, true, keysClass, valuesClass);

	}

	@SuppressWarnings("unchecked")
	public <T, C extends Collection<T>> C readCollection(boolean nullAccepted, int globalMaxSizeInBytes, boolean supportNullCollectionElements, Class<T> elementsClass) throws IOException, ClassNotFoundException {
		try {
			C res=(C)SerializationTools.readCollection(this, globalMaxSizeInBytes, nullAccepted, supportNullCollectionElements);
			if (res==null)
				return null;
			for (T e : res)
			{
				if (e!=null && !elementsClass.isAssignableFrom(e.getClass()))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			return res;

		}
		catch (ClassCastException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	@SuppressWarnings("unchecked")
	public <K, V, M extends Map<K, V>> M readMap(boolean nullAccepted, int globalMaxSizeInBytes, boolean supportNullMapKey, boolean supportNullMapValue, Class<K> keysClass, Class<V> valuesClass) throws IOException, ClassNotFoundException {
		try {
			M res=(M)SerializationTools.readMap(this, globalMaxSizeInBytes, nullAccepted, supportNullMapKey, supportNullMapValue);
			if (res==null)
				return null;
			for (Map.Entry<K, V> e : res.entrySet())
			{
				if (e.getKey()!=null && !keysClass.isAssignableFrom(e.getKey().getClass()))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
				if (e.getValue()!=null && !valuesClass.isAssignableFrom(e.getValue().getClass()))
					throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN);
			}
			return res;

		}
		catch (ClassCastException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	public WrappedEncryptedASymmetricPrivateKey readWrappedEncryptedASymmetricPrivateKey(boolean nullAccepted) throws IOException{
		return readWrappedData(nullAccepted, WrappedEncryptedASymmetricPrivateKey.MAX_SIZE_IN_BYTES_OF_KEY);
	}
	public WrappedEncryptedSymmetricSecretKey readWrappedEncryptedSymmetricSecretKey(boolean nullAccepted) throws IOException{
		return readWrappedData(nullAccepted, WrappedEncryptedSymmetricSecretKey.MAX_SIZE_IN_BYTES_OF_KEY);
	}
	public WrappedHashedPassword readWrappedHashedPassword(boolean nullAccepted) throws IOException{
		return readWrappedData(nullAccepted, WrappedHashedPassword.MAX_SIZE_IN_BYTES_OF_DATA);
	}
	@SuppressWarnings("unchecked")
	public <T extends WrappedData> T readWrappedData(boolean nullAccepted, int maxSizeInBytes) throws IOException{
		try {
			return (T)SerializationTools.readWrappedData(this, nullAccepted, maxSizeInBytes);
		}
		catch (ClassCastException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	public WrappedEncryptedASymmetricPrivateKeyString readWrappedEncryptedASymmetricPrivateKeyString(boolean nullAccepted) throws IOException{
		return readWrappedString(false, WrappedEncryptedASymmetricPrivateKeyString.MAX_CHARS_NUMBER);
	}
	public WrappedEncryptedSymmetricSecretKeyString readWrappedEncryptedSymmetricSecretKeyString(boolean nullAccepted) throws IOException{
		return readWrappedString(false, WrappedEncryptedSymmetricSecretKeyString.MAX_CHARS_NUMBER);
	}
	public WrappedHashedPasswordString readWrappedHashedPasswordString(boolean nullAccepted) throws IOException{
		return readWrappedString(false, WrappedHashedPasswordString.MAX_CHARS_NUMBER);
	}
	public WrappedPassword readWrappedPassword(boolean nullAccepted) throws IOException{
		return readWrappedString(false, WrappedPassword.MAX_CHARS_NUMBER);
	}
	@SuppressWarnings("unchecked")
	public <T extends WrappedString> T readWrappedString(boolean nullAccepted, int maxSizeInBytes) throws IOException{
		try {
			return (T)SerializationTools.readWrappedString(this, maxSizeInBytes, nullAccepted);
		}
		catch (ClassCastException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	public <T> T readObject(boolean nullAccepted) throws IOException, ClassNotFoundException {
		return readObject(nullAccepted, -1);
	}
	@SuppressWarnings("unchecked")
	public <T> T readObject(boolean nullAccepted, int maxSizeInBytes) throws IOException, ClassNotFoundException {
		try {
			return (T)SerializationTools.readObject(this, maxSizeInBytes, nullAccepted);
		}
		catch (ClassCastException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	public <TK> TK readObject(boolean nullAccepted, Class<TK> classType) throws IOException, ClassNotFoundException {
		return readObject(nullAccepted, -1, classType);
	}

	public <TK> TK readObject(boolean nullAccepted, int maxSizeInBytes, Class<TK> classType) throws IOException, ClassNotFoundException {
		if (classType==null)
			throw new NullPointerException();
		Object e=readObject(nullAccepted, maxSizeInBytes);
		return checkType(e, classType);
	}
	@SuppressWarnings("unchecked")
	private <TK> TK checkType(Object e, Class<TK> classType) throws MessageExternalizationException {
		if (e==null)
		{
			return null;
		}
		if (!classType.isAssignableFrom(e.getClass()))
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, "found : "+e.getClass());
		try {
			return (TK) e;
		}
		catch (ClassCastException e2)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e2);
		}
	}


	public Date readDate(boolean nullAccepted) throws IOException {
		return SerializationTools.readDate(this, nullAccepted);
	}
	public AbstractDecentralizedID readDecentralizedID(boolean nullAccepted) throws IOException {
		return SerializationTools.readDecentralizedID(this, nullAccepted);
	}
	public <TK extends AbstractDecentralizedID> TK readDecentralizedID(boolean nullAccepted, Class<TK> classType) throws IOException {
		return checkType(readDecentralizedID(nullAccepted), classType);
	}
	public InetAddress readInetAddress(boolean nullAccepted) throws IOException {
		return SerializationTools.readInetAddress(this, nullAccepted);
	}
	public InetSocketAddress readInetSocketAddress(boolean nullAccepted) throws IOException {
		return SerializationTools.readInetSocketAddress(this, nullAccepted);
	}
	public AbstractKey readKey(boolean nullAccepted) throws IOException {
		return SerializationTools.readKey(this, nullAccepted);
	}
	public <TK extends AbstractKey> TK readKey(boolean nullAccepted, Class<TK> classType) throws IOException {
		return checkType(readKey(nullAccepted), classType);
	}
	public <TK extends AbstractKeyPair<?, ?>> TK readKeyPair(boolean nullAccepted, Class<TK> classType) throws IOException {
		return checkType(readKeyPair(nullAccepted), classType);
	}
	public AbstractKeyPair<?, ?> readKeyPair(boolean nullAccepted) throws IOException {
		return SerializationTools.readKeyPair(this, nullAccepted);
	}
	public <TK extends Enum<?>> TK readEnum(boolean nullAccepted, Class<TK> classType) throws IOException, ClassNotFoundException {
		return checkType(readEnum(nullAccepted), classType);
	}
	@SuppressWarnings("unchecked")
	public <TK extends Enum<?>> TK readEnum(boolean nullAccepted) throws IOException, ClassNotFoundException {
		try {
			return (TK)SerializationTools.readEnum(this, nullAccepted);
		}
		catch (ClassCastException e)
		{
			throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, e);
		}
	}
	public Class<?> readClass(boolean nullAccepted) throws IOException, ClassNotFoundException {
		return readClass(nullAccepted, Object.class);
	}
	public <CR> Class<? extends CR> readClass(boolean nullAccepted, Class<CR> rootClass) throws IOException, ClassNotFoundException {
		return SerializationTools.readClass(this, nullAccepted, rootClass);
	}


	public SerializationTools.ObjectResolver getObjectResolver() {
		return objectResolver;
	}

	public void setObjectResolver(SerializationTools.ObjectResolver objectResolver) {
		if (objectResolver==null)
			throw new NullPointerException();
		this.objectResolver = objectResolver;
	}


}
