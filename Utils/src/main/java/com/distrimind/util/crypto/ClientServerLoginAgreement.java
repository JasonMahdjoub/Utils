package com.distrimind.util.crypto;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.16.0
 */
public abstract class ClientServerLoginAgreement extends Agreement{
	protected ClientServerLoginAgreement(int stepsNumberForReception, int stepsNumberForSend) {
		super(stepsNumberForReception, stepsNumberForSend);
	}
}
