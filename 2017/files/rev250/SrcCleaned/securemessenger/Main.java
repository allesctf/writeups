package messenger.hackit2017.helper.securemessenger;

import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import java.util.HashMap;
import messenger.hackit2017.com.securemessenger.d;

public class Main
  extends AppCompatActivity
{
  private static final Participant i = new Participant("alice");
  private HashMap<String, d> map = new HashMap();
  
  public Main() {}
  
  public static Participant getParticipant()
  {
    return i;
  }
  
  protected void onCreate(Bundle paramBundle)
  {
    super.onCreate(paramBundle);
    setContentView(2130968603);
    paramBundle = (Button)findViewById(2131427426);
    EditText localEditText = (EditText)findViewById(2131427423);
    paramBundle.setOnClickListener(new Main.1(this, (EditText)findViewById(2131427425), localEditText));

      if (!inHashmap)
        add new Particpant ("bob", etc...)

        try
        {
          AliceParticipant.createPencryptDataartipantQ(new StringStorage(localEditText.getText().toString()), existingParticipant);
          return;
        }
        catch (Exception paramAnonymousView)
        {
          paramAnonymousView.printStackTrace();
        }

  }
}
