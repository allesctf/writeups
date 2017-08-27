package messenger.hackit2017.helper.securemessenger;

import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.os.Bundle;

public class GetMessageReceiver
  extends BroadcastReceiver
{
  public GetMessageReceiver() {}
  
  public void onReceive(Context paramContext, Intent paramIntent)
  {
    Object localObject = paramIntent.getExtras().get("encrypted");
    if (!(localObject instanceof ECKey)) {
      throw new ClassCastException("Garbage got.");
    }
    paramIntent = paramIntent.getExtras().get("participant");
    if (!(localObject instanceof Participant)) {
      throw new ClassCastException("Garbage got.");
    }
    try
    {
      paramContext = Main.getParticipant();
      localObject = (ECKey)localObject;
      paramIntent = (Participant)paramIntent;
      paramContext.a((ECKey)localObject, paramIntent);
      return;
    }
    catch (Exception paramContext)
    {
      paramContext.printStackTrace();
    }
  }
}
