package messenger.hackit2017.helper.securemessenger;

public class StringStorage
{
  private String id;
  
  public StringStorage(String paramString)
  {
    id = paramString;
  }
  
  public String getStoredValue()
  {
    return id;
  }
  
  public String toString()
  {
    return id;
  }
}
