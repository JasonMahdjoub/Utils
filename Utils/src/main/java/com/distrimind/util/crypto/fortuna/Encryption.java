package com.distrimind.util.crypto.fortuna;

import com.distrimind.util.crypto.CodeProvider;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

class Encryption {
    private final Cipher cipher;
    private final int maxKeySize;

    public Encryption() {
        try {
            this.cipher = Cipher.getInstance("AES/ECB/NoPadding", CodeProvider.SunJCE.getCompatibleProvider());
            maxKeySize=Cipher.getMaxAllowedKeyLength("AES");
        } catch (NoSuchAlgorithmException | NoSuchProviderException | NoSuchPaddingException e) {
            throw new IllegalStateException(e);
        }

    }

    void setKey(byte[] key)  {

        try {
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, 0, Math.min(key.length, maxKeySize), "AES") );
        } catch (InvalidKeyException e) {
            throw new IllegalStateException(e);
        }
    }

    byte[] encrypt(byte[] data) {
        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            throw new IllegalStateException(e);


        }
    }
}
