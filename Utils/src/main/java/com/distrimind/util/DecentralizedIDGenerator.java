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
package com.distrimind.util;

import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * This class represents a unique identifier. Uniqueness is guaranteed over the
 * network.
 * 
 * @author Jason Mahdjoub
 * @version 2.0
 * @since Utils 1.0
 */
public class DecentralizedIDGenerator extends AbstractDecentralizedIDGenerator {
	/**
	 * 
	 */
	private static final long serialVersionUID = 5093130008197172104L;

	private static final AtomicInteger sequencer = new AtomicInteger(0);

	static final String ToStringHead = "DecentralizedID";

	public static DecentralizedIDGenerator valueOf(String value) {
		AbstractDecentralizedID res = AbstractDecentralizedID.valueOf(value);
		if (res instanceof DecentralizedIDGenerator) {
			return (DecentralizedIDGenerator) res;
		} else
			throw new IllegalArgumentException("Invalid format : " + value);
	}

	public DecentralizedIDGenerator() {
		super();
	}
	
	public DecentralizedIDGenerator(boolean useShortMacAddressAndRandomNumber) {
		super(useShortMacAddressAndRandomNumber);
	}

	DecentralizedIDGenerator(long timestamp, long work_id_sequence) {
		super(timestamp, work_id_sequence);
	}

	@Override
	protected short getNewSequence() {
		return (short) sequencer.incrementAndGet();
	}

	@Override
	byte getType() {
		return AbstractDecentralizedID.DECENTRALIZED_ID_GENERATOR_TYPE;
	}

	@Override
	public String toString() {
		return ToStringHead + "[" + getTimeStamp() + ";" + getWorkerID() + ";" + getSequenceID() + "]";
	}

	public UUID getUUID()
	{
		return new UUID(getWorkerIDAndSequence(), getTimeStamp());
	}
}
