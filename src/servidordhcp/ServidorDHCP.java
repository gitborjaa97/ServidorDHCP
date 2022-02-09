package servidordhcp;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketException;
import java.nio.ByteBuffer;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ServidorDHCP {

    private static int tiempoCesion = 6000;
    private static int tiempoRenovacion = 3000;
    private static byte[] macCliente = new byte[6];
    private static byte[] ipCliente = getByteIP("10.0.2.35");
    private static byte[] ipRouter = getByteIP("10.0.2.1");
    private static String ipServidor = "10.0.2.201";
    private static byte[] servidor = getByteIP(ipServidor);    
    private static byte[] dns = getByteIP("8.8.8.8");
    private static byte[] mascara = getByteIP("255.255.255.0");
    private static int id;

    public static void main(String[] args) {
        System.out.println("Arranca el servidor");
        System.out.println("Esperando mensaje...");
        try {
            boolean salir = false;
            int puertoRecibir = 67;
            int puertoEnviar = 68;
            DatagramSocket socket = new DatagramSocket(puertoRecibir, InetAddress.getByName(ipServidor));
            //Se inica un bucle para asegurar que recibimos los mensajes esperados
            while (!salir) {
                //DHCPDiscover
                byte[] mensaje = recibirMensaje(socket);
                configurarMacId(mensaje);
                byte type = getType(mensaje);
                //Si recibe el discover procede a enviar el mensaje, si no
                //continua esperando el discover
                if (type == 1) {
                    System.out.println("Discover recibido");
                    //DHCPOffer             
                    enviarMensaje("255.255.255.255", socket,
                            puertoEnviar, generarMensaje((short) 1, (short) 2));
                    System.out.println("Offer");
                    //DHCPRequest           
                    type = getType(recibirMensaje(socket));
                    //Si recibe el resquest sale del bucle para enviar ACK
                    //Si no esperara un nuevo discover
                    if (type == 3) {
                        System.out.println("Request");
                        salir = true;
                    }
                }
            }
            //DHCPAck
            enviarMensaje("255.255.255.255", socket,
                            puertoEnviar, generarMensaje((short) 1, (short) 5));
            System.out.println("Ack");

        } catch (SocketException ex) {
            Logger.getLogger(ServidorDHCP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ServidorDHCP.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("IP configurada");
    }
    
    //Recibe el paquete atraves del socket que recibe por parametro
    //y devuelve un array de bytes con su contenido
    private static byte [] recibirMensaje(DatagramSocket s){
        byte[] buffer = new byte[567];
        DatagramPacket paquete = new DatagramPacket(buffer, buffer.length);
        try {
            s.receive(paquete);
        } catch (IOException ex) {
            Logger.getLogger(ServidorDHCP.class.getName()).log(Level.SEVERE, null, ex);
        }
        return buffer;    
    }
    
    //Recibe por parametro la direccion, el puerto y el mensaje que va a enviar.
    //Compone el DatagramPaquet y lo envia por el Socket que le entregemos
    //por parametro
    private static void enviarMensaje(String direccion, DatagramSocket s,
            int puerto, byte [] respuesta){
        try {
            DatagramPacket paqueteEnviar = new DatagramPacket(respuesta, respuesta.length,
                    InetAddress.getByName(direccion), puerto);
            s.send(paqueteEnviar);
        } catch (IOException ex) {
            Logger.getLogger(ServidorDHCP.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
    
    //Recibe una ip en String por parametro y devuelve un array de cuatro bytes 
    //con cada byte de la direccion
    private static byte [] getByteIP(String ip){
        //Se separa por puntos
        String[] dir = ip.split("\\.");
        byte[] devolver = new byte[dir.length];
        for (int i = 0; i < dir.length; i++) {
            //Se guarda en cada posicion el valor de cada byte 
            devolver[i] = (byte) Integer.parseInt(dir[i]);
        }
        return devolver;        
    }

    //Recibe por parametro el array de bytes con el mensaje recibido.
    //Obtiene y configura el id de transaccion y la mac del cliente 
    private static void configurarMacId(byte[] data) {
        ByteBuffer bBuffer = ByteBuffer.wrap(data);

        id = bBuffer.getInt(4);

        for (int i = 28; i < 34; i++) {
            macCliente[i - 28] = bBuffer.get(i);
        }
    }
    
    private static byte getType(byte[] data){
        ByteBuffer bBuffer = ByteBuffer.wrap(data);
        
        int puntero = 240;
        boolean terminar = false;
        byte type = -1;
        //Utilizo un "puntero" que me srive para recorrer el Magic cookie
        //con el esquema inpuesto. Lee el codigoy la longitud ya aumneta
        // en dos, comprueba que no sea el codigo buscado, y aumenta el puntero
        //en la longitud inidicada.
        while (!terminar) {
            int codigo = bBuffer.get(puntero);
            ++puntero;
            int longitud = bBuffer.get(puntero);
            ++puntero;
            if (codigo == 53) {
                //Se mantienen en bucle hasta encontrar el registro deseado
                terminar = true;
                type = bBuffer.get(puntero);
            }
            puntero += longitud;
        }
        return type;
    }
    
    //Genera la parte variable con los valores entregados por parametro.s
    private static byte[] generarMensaje(short flags, int type) {
        ByteBuffer mensaje = ByteBuffer.allocate(567);
        //Cabecera
        mensaje.put(generarCabecera(flags));
        //Magic cookie
        mensaje.put((byte) 99);
        mensaje.put((byte) 130);
        mensaje.put((byte) 83);
        mensaje.put((byte) 99);
        //Tipo de mensaje
        mensaje.put((byte) 53);
        mensaje.put((byte) 1);
        mensaje.put((byte) type);
        //Mascara de subred
        mensaje.put((byte) 1);
        mensaje.put((byte) 4);
        mensaje.put(mascara);
        mensaje.put((byte) 0);
        //DNS
        mensaje.put((byte) 6);
        mensaje.put((byte) 4);
        mensaje.put(dns);
        //Router
        mensaje.put((byte) 3);
        mensaje.put((byte) 4);
        mensaje.put(ipRouter);
//        //IP Cliente
        mensaje.put((byte) 50);
        mensaje.put((byte) 4);
        mensaje.put(ipCliente);
//        Tiempo de cesion(60s)
        mensaje.put((byte) 51);
        mensaje.put((byte) 4);
        mensaje.putInt(tiempoCesion);
        //Tiempo de renovacion
        mensaje.put((byte) 58);
        mensaje.put((byte) 4);
        mensaje.putInt(tiempoRenovacion);
        //IP Servidor
        mensaje.put((byte) 54);
        mensaje.put((byte) 4);
        mensaje.put(servidor);
        //END
        mensaje.put((byte) 255);

        return mensaje.array();
    }

    //Genera la parte fija del mensaje
    private static byte[] generarCabecera(short flags) {

        ByteBuffer mensaje = ByteBuffer.allocate(236);
        //op
        mensaje.put((byte) 2);
        //htype
        mensaje.put((byte) 1);
        //hlen
        mensaje.put((byte) 6);
        //hops
        mensaje.put((byte) 0);
        //xid
        mensaje.putInt(id);
        //Secs
        mensaje.putShort((short) 0);
        //flags 
        mensaje.putShort(flags);
        //ciaddr
        mensaje.putInt(0);
        //yiaddr
        mensaje.put(ipCliente);
        //siaddr
        mensaje.putInt(0);
        //giaddr
        mensaje.putInt(0);
        //chaddr (mac)
        mensaje.put(macCliente);
        return mensaje.array();
    }

}
