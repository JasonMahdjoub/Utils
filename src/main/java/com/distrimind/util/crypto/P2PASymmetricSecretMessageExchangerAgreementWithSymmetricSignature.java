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
    private static final class Finalizer extends Cleaner
    {
        private final P2PASymmetricSecretMessageExchangerAgreement p2PASymmetricSecretMessageExchangerAgreement;
        private final P2PLoginWithSymmetricSignature login;

        private Finalizer(P2PASymmetricSecretMessageExchangerAgreement p2PASymmetricSecretMessageExchangerAgreement, P2PLoginWithSymmetricSignature login) {
            this.p2PASymmetricSecretMessageExchangerAgreement = p2PASymmetricSecretMessageExchangerAgreement;
            this.login = login;
        }

        @Override
        protected void performCleanup() {
            if (login!=null)
                login.clean();
            if (p2PASymmetricSecretMessageExchangerAgreement!=null)
                p2PASymmetricSecretMessageExchangerAgreement.clean();
        }
    }
    private final Finalizer finalizer;


    @Override
    public boolean isPostQuantumAgreement() {
        return (finalizer.p2PASymmetricSecretMessageExchangerAgreement!=null && finalizer.p2PASymmetricSecretMessageExchangerAgreement.isPostQuantumAgreement())
                && (finalizer.login!=null && finalizer.login.isPostQuantumAgreement());
    }

    P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(AbstractSecureRandom random, char[] message, byte[] salt,
                                                                       int offset_salt, int len_salt, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        super(secretKeyForSignature==null?2:4, secretKeyForSignature==null?2:4);
        finalizer=new Finalizer(new P2PASymmetricSecretMessageExchangerAgreement(random, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message),
                secretKeyForSignature==null?null:new P2PLoginWithSymmetricSignature(secretKeyForSignature, random));
        registerCleaner(finalizer);
    }
    P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(AbstractSecureRandom random, byte[] message, int offset, int len, byte[] salt,
                                                                       int offset_salt, int len_salt, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature, MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
        super(secretKeyForSignature==null?2:4, secretKeyForSignature==null?2:4);
        finalizer=new Finalizer(new P2PASymmetricSecretMessageExchangerAgreement(random,messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message, offset, len, messageIsKey),
                secretKeyForSignature==null?null:new P2PLoginWithSymmetricSignature(secretKeyForSignature, random));
        registerCleaner(finalizer);
    }
    @Override
    protected boolean isAgreementProcessValidImpl() {

        return finalizer.p2PASymmetricSecretMessageExchangerAgreement.isAgreementProcessValidImpl() && (finalizer.login==null || finalizer.login.isAgreementProcessValidImpl());
    }
    @Override
    protected byte[] getDataToSend(int stepNumber) throws IOException {
        if (finalizer.login!=null && stepNumber<2)
            return finalizer.login.getDataToSend();
        else
            return finalizer.p2PASymmetricSecretMessageExchangerAgreement.getDataToSend();
    }
    @Override
    protected void receiveData(int stepNumber, byte[] data) throws IOException {
        if (finalizer.login!=null && stepNumber<2)
            finalizer.login.receiveData(data);
        else
            finalizer.p2PASymmetricSecretMessageExchangerAgreement.receiveData(data);

    }

}
