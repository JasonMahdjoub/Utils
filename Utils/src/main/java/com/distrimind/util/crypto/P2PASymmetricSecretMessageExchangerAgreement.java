package com.distrimind.util.crypto;

import gnu.vm.jgnu.security.InvalidAlgorithmParameterException;
import gnu.vm.jgnu.security.InvalidKeyException;
import gnu.vm.jgnu.security.NoSuchAlgorithmException;
import gnu.vm.jgnu.security.NoSuchProviderException;
import gnu.vm.jgnu.security.spec.InvalidKeySpecException;
import gnu.vm.jgnux.crypto.NoSuchPaddingException;
import org.bouncycastle.crypto.CryptoException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 3.24
 */
public class P2PASymmetricSecretMessageExchangerAgreement extends P2PLoginAgreement {

    private P2PASymmetricSecretMessageExchanger p2PASymmetricSecretMessageExchanger;

    private boolean valid=true;
    private final byte[] salt;
    private final int offset_salt;
    private final int length_salt;
    private byte[] bytesPassword;
    private int offset_password;
    private int length_password;
    private boolean passwordIsKey;
    private char[] charPassword;

    P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                        ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt, byte[] bytesPassword, int offset_password, int length_password,
                                                        boolean passwordIsKey) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        this(secureRandom, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt);
        if (bytesPassword==null)
            throw new NullPointerException();
        if (bytesPassword.length==0)
            throw new IllegalArgumentException();

        this.bytesPassword=bytesPassword;
        this.offset_password=offset_password;
        this.length_password=length_password;
        this.passwordIsKey=passwordIsKey;
        this.charPassword=null;
    }
    P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                        ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt, char[] charPassword) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        this(secureRandom, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt);
        if (charPassword==null)
            throw new NullPointerException();
        if (charPassword.length==0)
            throw new IllegalArgumentException();
        this.bytesPassword=null;
        this.passwordIsKey=false;
        this.charPassword=charPassword;
    }
    /*P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                        ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt, String password) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        this(secureRandom, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, password.toCharArray());
    }*/
    private P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                        ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        super(2, 2);
        this.p2PASymmetricSecretMessageExchanger = new P2PASymmetricSecretMessageExchanger(secureRandom, messageDigestType, passwordHashType, myPublicKey);
        this.salt=salt;
        this.offset_salt=offset_salt;
        this.length_salt=len_salt;
    }

    @Override
    protected boolean isAgreementProcessValidImpl() {
        return valid;
    }

    @Override
    protected byte[] getDataToSend(int stepNumber) throws Exception{
        if (!valid)
            throw new CryptoException();

        try {
            switch (stepNumber) {
                case 0:
                    return p2PASymmetricSecretMessageExchanger.encodeMyPublicKey();
                case 1:
                    if (bytesPassword != null)
                        return p2PASymmetricSecretMessageExchanger.encode(bytesPassword, offset_password, length_password, salt, offset_salt, length_salt, passwordIsKey);
                    else
                        return p2PASymmetricSecretMessageExchanger.encode(charPassword, salt, offset_salt, length_salt);
                default:
                    valid = false;
                    throw new IllegalAccessError();
            }
        }
        catch(Exception e)
        {
            valid=false;
            throw e;
        }
    }

    @Override
    protected void receiveData(int stepNumber, byte[] data) throws CryptoException {
        if (!valid)
            throw new CryptoException();


        if (data==null || data.length==0)
        {
            valid=false;
            throw new CryptoException();
        }
        try {
            switch (stepNumber) {
                case 0:
                    p2PASymmetricSecretMessageExchanger.setDistantPublicKey(data);
                    break;
                case 1:
                    if (bytesPassword != null)
                        valid = p2PASymmetricSecretMessageExchanger.verifyDistantMessage(bytesPassword, offset_password, length_password, salt, offset_salt, length_salt, data, 0, data.length, passwordIsKey);
                    else
                        valid = p2PASymmetricSecretMessageExchanger.verifyDistantMessage(charPassword, salt, offset_salt, length_salt, data, 0, data.length);
                    break;
                default:
                    valid = false;
                    throw new IllegalAccessError();
            }
        }
        catch(Exception e)
        {
            valid=false;
            throw new CryptoException("",e);
        }
    }
}
