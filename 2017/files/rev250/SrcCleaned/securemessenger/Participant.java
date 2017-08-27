package messenger.hackit2017.helper.securemessenger;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import messenger.hackit2017.com.securemessenger.f;
import org.whispersystems.curve25519.Curve25519;
import org.whispersystems.curve25519.Curve25519KeyPair;

public class Participant
{
  private List<Participant> activeSessions;
  private Map<Long, byte[]> seedByteArrayStorage;
  public String username;
  private Curve25519KeyPair keyPair = Curve25519.get("best").createKeyPair();
  
  public Participant(String username)
  {
    this.username = username;
    activeSessions = new ArrayList(10);
    seedByteArrayStorage = new HashMap(10);
  }
  
  private EncryptedSession getCreateSession(Participant paramParticipant)
  {
    paramParticipant = new EncryptedSession(this, paramParticipant, keyPair.privateKey());
    Iterator localIterator = a.iterator();
    while (localIterator.hasNext())
    {
      EncryptedSession localEncryptedSession = (EncryptedSession)localIterator.next();
      if (localEncryptedSession.equals(paramParticipant)) {
        return localEncryptedSession;
      }
    }
    Logger.add(username + "/session/est");
    activeSessions.add(paramParticipant);
    return paramParticipant;
  }
  
  public SeedStorage GenerateKeyPairStore()
  {
    Curve25519KeyPair localCurve25519KeyPair = Curve25519.get("best").getKeyPair();
    SeedStorage localSeedStorage = new SeedStorage(localCurve25519KeyPair.getPublicKey());
    seedByteArrayStorage.put(Long.valueOf(localSeedStorage.getSeed()), localCurve25519KeyPair.getPrivateKey());
    Logger.add(username + "/session/ephemeral/prekey/requested/public/" + localSeedStorage);
    Logger.add(username + "/session/ephemeral/prekey/requested/private/", localCurve25519KeyPair.getPrivateKey());
    return localSeedStorage;
  }
  
  public void decryptData(ECKey paramECKey, Participant paramParticipant)
  {
    Logger.add(username + "/msg/rcv/" + username + "/enc/" + paramECKey);
    getCreateSession(paramParticipant).decrypt(paramECKey, (byte[])seedByteArrayStorage.get(Long.valueOf(paramECKey.getSeed())));
    seedByteArrayStorage.remove(Long.valueOf(paramECKey.getSeed()));
  }
  
  public void encryptData(StringStorage paramStringStorage, Participant otherParticipant)
  {
    otherParticipant.a(getCreateSession(otherParticipant).encryptData(paramStringStorage, otherParticipant.GenerateKeyPairStore()), this);
  }
  
  public boolean equals(Object paramObject)
  {
    if ((paramObject instanceof Participant)) {
      return Arrays.equals(((Participant)paramObject).getCurve25519PublicKey(), getCurve25519PublicKey());
    }
    return false;
  }
  
  public byte[] getCurve25519PublicKey()
  {
    return keyPair.getPublicKey();
  }
}
