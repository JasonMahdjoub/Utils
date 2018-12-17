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
public class P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature extends P2PLoginAgreement {
    private final P2PASymmetricSecretMessageExchangerAgreement p2PASymmetricSecretMessageExchangerAgreement;
    private final P2PLoginWithSymmetricSignature login;
    /*P2PJPakeAndLoginAgreement(AbstractSecureRandom random, Serializable participantID, char[] message, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {

        this(random, participantID, message, null, 0, 0, secretKeyForSignature);
    }*/
    P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(AbstractSecureRandom random, char[] message, byte[] salt,
                              int offset_salt, int len_salt, SymmetricSecretKey secretKeyForSignature,MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
        super(secretKeyForSignature==null?2:4, secretKeyForSignature==null?2:4);
        p2PASymmetricSecretMessageExchangerAgreement=new P2PASymmetricSecretMessageExchangerAgreement(random, messageDigestType, passwordHashType, myPublicKey, salt, offset_salt, len_salt, message);
        if (secretKeyForSignature==null)
            login=null;
        else
            login=new P2PLoginWithSymmetricSignature(secretKeyForSignature, random);
    }
    /*P2PJPakeAndLoginAgreement(AbstractSecureRandom random, Serializable participantID, byte[] message, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, IOException {

        this(random, participantID, message, 0, message.length,null, 0, 0, messageIsKey, secretKeyForSignature);
    }*/
    P2PASymmetricSecretMessageExchangerAgreementWithSymmetricSignature(AbstractSecureRandom random, byte[] message, int offset, int len, byte[] salt,
                                                                       int offset_salt, int len_salt, boolean messageIsKey, SymmetricSecretKey secretKeyForSignature, MessageDigestType messageDigestType, PasswordHashType passwordHashType, ASymmetricPublicKey myPublicKey) throws NoSuchAlgorithmException, InvalidKeySpecException, NoSuchProviderException, NoSuchPaddingException, InvalidAlgorithmParameterException, InvalidKeyException {
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
    protected byte[] getDataToSend(int stepNumber) throws Exception {
        if (login!=null && stepNumber<2)
            return login.getDataToSend();
        else
            return p2PASymmetricSecretMessageExchangerAgreement.getDataToSend();
    }
    @Override
    protected void receiveData(int stepNumber, byte[] data) throws CryptoException {
        if (login!=null && stepNumber<2)
            login.receiveData(data);
        else
            p2PASymmetricSecretMessageExchangerAgreement.receiveData(data);

    }
}
