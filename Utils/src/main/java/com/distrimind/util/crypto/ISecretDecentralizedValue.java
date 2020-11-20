package com.distrimind.util.crypto;

import com.distrimind.util.data_buffers.WrappedSecretData;
import com.distrimind.util.data_buffers.WrappedSecretString;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 5.10.0
 */
public interface ISecretDecentralizedValue {
	WrappedSecretData encode();
	WrappedSecretString encodeString();
}
