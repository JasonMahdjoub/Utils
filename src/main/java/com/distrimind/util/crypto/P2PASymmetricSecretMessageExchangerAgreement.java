package com.distrimind.util.crypto;

import com.distrimind.bouncycastle.crypto.CryptoException;
import com.distrimind.util.io.Integrity;
import com.distrimind.util.io.MessageExternalizationException;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.util.Arrays;

/**
 * @author Jason Mahdjoub
 * @version 2.0
 * @since MaDKitLanEdition 3.24
 */
public class P2PASymmetricSecretMessageExchangerAgreement extends P2PLoginAgreement {

    private final P2PASymmetricSecretMessageExchanger p2PASymmetricSecretMessageExchanger;

    private static final class Finalizer extends Cleaner
    {
        private byte[] bytesPassword;
        private char[] charPassword;
        @Override
        protected void performCleanup() {
            if (bytesPassword!=null)
                Arrays.fill(bytesPassword, (byte)0);
            if (charPassword!=null)
                Arrays.fill(charPassword, (char)0);
            bytesPassword=null;
            charPassword=null;
        }
    }

    private boolean valid=true;
    private final byte[] salt;
    private final int offset_salt;
    private final int length_salt;
    private boolean passwordIsKey;
    private final Finalizer finalizer;


    @Override
    public boolean isPostQuantumAgreement() {
        return p2PASymmetricSecretMessageExchanger.getDistantPublicKey().isPostQuantumKey();
    }



    P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                 ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt, byte[] bytesPassword, int offset_password, int length_password,
                                                 boolean passwordIsKey) throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
        this(secureRandom, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt);
        if (bytesPassword==null)
            throw new NullPointerException();
        if (bytesPassword.length==0)
            throw new IllegalArgumentException();

        this.finalizer.bytesPassword=Arrays.copyOfRange(bytesPassword, offset_password, length_password+offset_password);
        this.passwordIsKey=passwordIsKey;
        this.finalizer.charPassword=null;
    }
    P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                 ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt, char[] charPassword) throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
        this(secureRandom, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt);
        if (charPassword==null)
            throw new NullPointerException();
        if (charPassword.length==0)
            throw new IllegalArgumentException();
        this.finalizer.bytesPassword=null;
        this.passwordIsKey=false;
        this.finalizer.charPassword=charPassword.clone();
    }
    private P2PASymmetricSecretMessageExchangerAgreement(AbstractSecureRandom secureRandom, MessageDigestType messageDigestType, PasswordHashType passwordHashType,
                                                         ASymmetricPublicKey myPublicKey, byte[] salt, int offset_salt, int len_salt) throws NoSuchAlgorithmException, NoSuchProviderException, MessageExternalizationException {
        super(2, 2);
        finalizer=new Finalizer();
        this.p2PASymmetricSecretMessageExchanger = new P2PASymmetricSecretMessageExchanger(secureRandom, messageDigestType, passwordHashType, myPublicKey);
        this.salt=salt;
        this.offset_salt=offset_salt;
        this.length_salt=len_salt;
        registerCleaner(finalizer);
    }

    @Override
    protected boolean isAgreementProcessValidImpl() {
        return valid;
    }

    @Override
    protected byte[] getDataToSend(int stepNumber) throws IOException {
        if (!valid)
            throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());

        try {
            switch (stepNumber) {
                case 0:
                    return p2PASymmetricSecretMessageExchanger.encodeMyPublicKey().getBytes().clone();
                case 1:
                    if (finalizer.bytesPassword != null)
                        return p2PASymmetricSecretMessageExchanger.encode(finalizer.bytesPassword, 0,finalizer.bytesPassword.length, salt, offset_salt, length_salt, passwordIsKey);
                    else
                        return p2PASymmetricSecretMessageExchanger.encode(finalizer.charPassword, salt, offset_salt, length_salt);
                default:
                    valid = false;
                    throw new IllegalAccessError();
            }
        }
        catch(Exception e)
        {
            valid=false;
            throw new MessageExternalizationException(Integrity.FAIL, e);
        }
    }

    @Override
    protected void receiveData(int stepNumber, byte[] data) throws IOException {
        if (!valid)
            throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());


        if (data==null || data.length==0)
        {
            valid=false;
            throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException());
        }
        try {
            switch (stepNumber) {
                case 0:
                    p2PASymmetricSecretMessageExchanger.setDistantPublicKey(data);
                    break;
                case 1:
                    if (finalizer.bytesPassword != null)
                        valid = p2PASymmetricSecretMessageExchanger.verifyDistantMessage(finalizer.bytesPassword, 0, finalizer.bytesPassword.length, salt, offset_salt, length_salt, data, 0, data.length, passwordIsKey);
                    else
                        valid = p2PASymmetricSecretMessageExchanger.verifyDistantMessage(finalizer.charPassword, salt, offset_salt, length_salt, data, 0, data.length);
                    break;
                default:
                    valid = false;
                    throw new IllegalAccessError();
            }
        }
        catch(Exception e)
        {
            valid=false;
            throw new MessageExternalizationException(Integrity.FAIL_AND_CANDIDATE_TO_BAN, new CryptoException("",e));
        }
    }

}
