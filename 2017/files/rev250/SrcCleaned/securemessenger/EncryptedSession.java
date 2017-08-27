package messenger.hackit2017.helper.securemessenger;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import messenger.hackit2017.helper.securemessenger.xy.a;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class EncryptedSession
{
  private Participant participant1;
  private byte[] firstAgreement;
  private Participant participant2;
  private long shiftCounter;
  
  public EncryptedSession(Participant paramParticipant1, Participant paramParticipant2, byte[] privateKey)
  {
    participant1 = paramParticipant1;
    participant2 = paramParticipant2;
    firstAgreement = Curve25519.get("best").getAgreement(paramParticipant2.getCurve25519PublicKey(), privateKey);
    shiftCounter = 0L;
    Logger.add(participant2 + "/session/est/base/", firstAgreement);
  }
  
  private byte[] getIVShifted(long shiftCounter)
  {
    byte[] arrayOfByte = firstAgreement;
    int i = 0;
    while (i < paramLong)
    {
      arrayOfByte = xy.a(3).a(arrayOfByte, "h4ck1t{RotationFlagInfo}".getBytes(), 32);
      i += 1;
    }
    return arrayOfByte;
  }
  
  private Cipher getCipherInstance()
  {
    return Cipher.getInstance("AES/CBC/PKCS5Padding");
  }
  
  public ECKey encryptData(StringStorage paramStringStorage, PublicKeyStorage paramPublicKeyStorage)
  {
    Curve25519 curve25519Obj = Curve25519.get("best");
    Curve25519KeyPair localCurve25519KeyPair = curve25519Obj.generateKeyPair();
    byte[] agreement = ((Curve25519)curve25519Obj).calculateAgreement(paramPublicKeyStorage.getMSGPubKey(), localCurve25519KeyPair.getPrivateKey());
    Logger.add(participant1.username + "/session/ephemeral/shared/", arrayOfByte);
    shiftCounter += 1L;
    byte[] keyBytes = sha256Hmac(getIVShifted(shiftCounter), "WhisperSystems".getBytes(), 16);
    arrayOfByte = sha256Hmac(agreement, "WhisperSystems".getBytes(), 16);
    Cipher localCipher = getCipherInstance();
    localCipher.init(1, new SecretKeySpec(keyBytes, "AES"), new IvParameterSpec(arrayOfByte));
    //  doFinal(byte[] input)
    return new ECKey(localCipher.doFinal(paramStringStorage.getStoredValue().getBytes()), shiftCounter, paramPublicKeyStorage.getSeed(), localCurve25519KeyPair.getPublicKey());
  }
  
  public StringStorage decrypt(ECKey paramECKey, byte[] privateKeyParam)
  {
    byte[] arrayOfByte = Curve25519.get("best").calculateAgreement(paramECKey.getPublicKey(), privateKeyParam);
    byte[] AESKEY = sha256Hmac(getIVShifted(paramECKey.getStoredMessageCounter()), "WhisperSystems".getBytes(), 16);
    arrayOfByte = sha256Hmac(arrayOfByte, "WhisperSystems".getBytes(), 16);
    Cipher localCipher = getCipherInstance();
    localCipher.init(2, new SecretKeySpec(AESKEY, "AES"), new IvParameterSpec(arrayOfByte));
    return new StringStorage(new String(localCipher.doFinal(paramECKey.getEncryptedData())));
  }
  
  public boolean equals(Object paramObject)
  {
    return ((paramObject instanceof EncryptedSession)) && (participant1.equals(participant1)) && (participant2.equals(participant2));
  }
}
