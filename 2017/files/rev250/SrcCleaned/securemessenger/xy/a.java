package messenger.hackit2017.helper.securemessenger.xy;

import java.io.ByteArrayOutputStream;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public abstract class a
{
  public a() {}
  
  public static a a(int paramInt)
  {
    switch (paramInt)
    {
    default: 
      throw new AssertionError("Unknown version: " + paramInt);
    case 2: 
      return new XYGraphWidget();
    }
    return new PositionMetric();
  }
  
  private byte[] read(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, int paramInt)
  {
    double d = paramInt / 32.0D;
    try
    {
      d = Math.ceil(d);
      int k = (int)d;
      Object localObject1 = new byte[0];
      ByteArrayOutputStream localByteArrayOutputStream = new ByteArrayOutputStream();
      int j = b();
      int i = paramInt;
      paramInt = j;
      for (;;)
      {
        j = b();
        if (paramInt >= j + k) {
          break;
        }
        Object localObject2 = Mac.getInstance("HmacSHA256");
        ((Mac)localObject2).init(new SecretKeySpec(paramArrayOfByte1, "HmacSHA256"));
        ((Mac)localObject2).update((byte[])localObject1);
        if (paramArrayOfByte2 != null) {
          ((Mac)localObject2).update(paramArrayOfByte2);
        }
        byte b = (byte)paramInt;
        ((Mac)localObject2).update(b);
        localObject2 = ((Mac)localObject2).doFinal();
        localObject1 = localObject2;
        j = localObject2.length;
        j = Math.min(i, j);
        localByteArrayOutputStream.write((byte[])localObject2, 0, j);
        i -= j;
        paramInt += 1;
      }
      paramArrayOfByte1 = localByteArrayOutputStream.toByteArray();
      return paramArrayOfByte1;
    }
    catch (Exception paramArrayOfByte1)
    {
      throw new AssertionError(paramArrayOfByte1);
    }
  }
  
  private byte[] sha256Hmac(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2)
  {
    try
    {
      Mac localMac = Mac.getInstance("HmacSHA256");
      localMac.init(new SecretKeySpec(paramArrayOfByte1, "HmacSHA256"));
      paramArrayOfByte1 = localMac.doFinal(paramArrayOfByte2);
      return paramArrayOfByte1;
    }
    catch (Exception paramArrayOfByte1)
    {
      throw new AssertionError(paramArrayOfByte1);
    }
  }
  
  public byte[] a(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, int paramInt)
  {
    return a(paramArrayOfByte1, new byte[32], paramArrayOfByte2, paramInt);
  }
  
  public byte[] a(byte[] paramArrayOfByte1, byte[] paramArrayOfByte2, byte[] paramArrayOfByte3, int paramInt)
  {
    return read(sha256Hmac(paramArrayOfByte2, paramArrayOfByte1), paramArrayOfByte3, paramInt);
  }
  
  protected abstract int b();
}
