package com.distrimind.util.crypto;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

/**
 * @author Jason Mahdjoub
 * @version 1.0
 * @since MaDKitLanEdition 3.24
 */
public class P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature extends P2PLoginAgreement {
    private final P2PASymmetricSecretMessageExchangerAgreement p2PASymmetricSecretMessageExchangerAgreement;
    private final P2PLoginWithSymmetricSignature login;

    @Override
    public void zeroize() {
        if (login!=null)
            login.zeroize();
        if (p2PASymmetricSecretMessageExchangerAgreement!=null)
            p2PASymmetricSecretMessageExchangerAgreement.zeroize();
    }
    @Override
    public boolean isDestroyed() {
        return (login==null || login.isDestroyed()) && p2PASymmetricSecretMessageExchangerAgreement.isDestroyed();
    }

    @Override
    public boolean isPostQuantumAgreement() {
        return (p2PASymmetricSecretMessageExchangerAgreement!=null && p2PASymmetricSecretMessageExchangerAgreement.isPostQuantumAgreement())
                && (login!=null && login.isPostQuantumAgreement());
    }

    P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(AbstractSecureRandom random, char[] message, byte[] salt,
                                                                       int offset_salt, int len_salt, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        super(secretKeyForSignature==null?2:4, secretKeyForSignature==null?2:4);
        p2PASymmetricSecretMessageExchangerAgreement=new P2PASymmetricSecretMessageExchangerAgreement(random, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message);
        if (secretKeyForSignature==null)
            login=null;
        else
            login=new P2PLoginWithSymmetricSignature(secretKeyForSignature, random);
    }
    P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(AbstractSecureRandom random, byte[] message, int offset, int len, byte[] salt,
                                                                       int offset_salt, int len_salt, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature, MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        super(secretKeyForSignature==null?2:4, secretKeyForSignature==null?2:4);
        p2PASymmetricSecretMessageExchangerAgreement=new P2PASymmetricSecretMessageExchangerAgreement(random,messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message, offset, len, messageIsKey);
        if (secretKeyForSignature==null)
            login=null;
        else
            login=new P2PLoginWithSymmetricSignature(secretKeyForSignature, random);
    }
    @Override
    protected boolean isAgreementProcessValidImpl() {

        return p2PASymmetricSecretMessageExchangerAgreement.isAgreementProcessValidImpl() && (login==null || login.isAgreementProcessValidImpl());
    }
    @Override
    protected byte[] getDataToSend(int stepNumber) throws IOException {
        if (login!=null && stepNumber<2)
            return login.getDataToSend();
        else
            return p2PASymmetricSecretMessageExchangerAgreement.getDataToSend();
    }
    @Override
    protected void receiveData(int stepNumber, byte[] data) throws IOException {
        if (login!=null && stepNumber<2)
            login.receiveData(data);
        else
            p2PASymmetricSecretMessageExchangerAgreement.receiveData(data);

    }

}
