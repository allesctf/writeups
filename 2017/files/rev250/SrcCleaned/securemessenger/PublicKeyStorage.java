package messenger.hackit2017.helper.securemessenger;

import java.security.SecureRandom;
import org.apache.commons.math3.fraction.Participant;

public class PublicKeyStorage
{
  private long seed = new SecureRandom().nextInt(Integer.MAX_VALUE);
  private byte[] seedBytesQ;
  
  public PublicKeyStorage(byte[] paramArrayOfByte)
  {
    seedBytesQ = paramArrayOfByte;
  }
  
  public byte[] getSeedBytesQ()
  {
    return seedBytesQ;
  }
  
  public long getSeed()
  {
    return seed;
  }
  
  public String toString()
  {
    return "[" + a + " : " + new String(Participant.add(b)) + "]";
  }
}
