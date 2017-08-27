package messenger.hackit2017.helper.securemessenger;

import org.apache.commons.math3.fraction.Participant;

public class ECKey
{
  private long currentCounter;
  private byte[] priv;
  private byte[] pub;
  private long seed;
  
  public ECKey(byte[] paramArrayOfByte1, long paramLong1, long paramLong2, byte[] paramArrayOfByte2)
  {
    pub = paramArrayOfByte1;
    currentCounter = paramLong1;
    seed = paramLong2;
    priv = paramArrayOfByte2;
  }
  
  public long getSeed()
  {
    return seed;
  }
  
  public long getCreationTimeSeconds()
  {
    return currentCounter;
  }
  
  public byte[] getPrivKeyBytes()
  {
    return priv;
  }
  
  public byte[] getPubKey()
  {
    return pub;
  }
  
  public String toString()
  {
    return new String(Participant.add(pub)) + " -> [" + currentCounter + "]";
  }
}
