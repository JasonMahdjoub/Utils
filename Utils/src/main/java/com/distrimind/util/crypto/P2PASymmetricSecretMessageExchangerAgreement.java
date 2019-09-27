package com.distrimind.util.crypto;

import org.bouncycastle.crypto.CryptoException;

import javax.crypto.NoSuchPaddingException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since MaDKitLanEdition 3.24
 */
public class P2PASymmetricSecretMessageExchangerAgreement extends P2PLoginAgreement {

    private P2PASymmetricSecretMessageExchanger p2PASymmetricSecretMessageExchanger;



    private boolean valid=true;
    private final byte[] salt;
    private final int offset_salt;
    private final int length_salt;
    private byte[] bytesPassword;
    private boolean passwordIsKey;
    private char[] charPassword;

    @Override
    public boolean isPostQuantumAgreement() {
        return p2PASymmetricSecretMessageExchanger.getDistantPublicKey().isPostQuantumKey();
    }

    @Override
    public void zeroize() {
        if (bytesPassword!=null)
            Arrays.fill(bytesPassword, (byte)0);
        if (charPassword!=null)
            Arrays.fill(charPassword, (char)0);
        bytesPassword=null;
        charPassword=null;
    }



    P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                        ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt, byte[] bytesPassword, int offset_password, int length_password,
                                                        boolean passwordIsKey) throws NoSuchPaddingException, InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        this(secureRandom, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt);
        if (bytesPassword==null)
            throw new NullPointerException();
        if (bytesPassword.length==0)
            throw new IllegalArgumentException();

        this.bytesPassword=Arrays.copyOfRange(bytesPassword, offset_password, length_password+offset_password);
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
        this.charPassword=charPassword.clone();
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
                        return p2PASymmetricSecretMessageExchanger.encode(bytesPassword, 0,bytesPassword.length, salt, offset_salt, length_salt, passwordIsKey);
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
                        valid = p2PASymmetricSecretMessageExchanger.verifyDistantMessage(bytesPassword, 0, bytesPassword.length, salt, offset_salt, length_salt, data, 0, data.length, passwordIsKey);
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
