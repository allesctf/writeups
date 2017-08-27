package messenger.hackit2017.helper.securemessenger;

import android.util.Log;
import java.io.PrintStream;
import org.apache.commons.math3.fraction.Participant;

public class Logger
{
  public static void add(String paramString)
  {
    write(paramString);
  }
  
  public static void add(String paramString, byte[] paramArrayOfByte)
  {
    write(paramString + new String(Participant.add(paramArrayOfByte)));
  }
  
  private static void write(String paramString)
  {
    System.out.println(paramString);
    Log.i("Messenger", paramString);
  }
}
