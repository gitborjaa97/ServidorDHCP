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
    private static byte[] mac = new byte[6];
    private static byte[] ipCliente = {10, 0, 2, 26};
    private static byte[] router = {10, 0, 2, 1};
    private static byte[] servidor = {10, 0, 2, (byte) 201};
    private static int id;

    public static void main(String[] args) {
        System.out.println("Arranca el servidor");
        System.out.println("Esperando mensaje...");
        try {
            boolean salir = false;
            int puerto = 67;
            DatagramSocket socket = new DatagramSocket(puerto);
            while (!salir) {
                //DHCPDiscover
                byte[] buffer = new byte[567];
                DatagramPacket paquete = new DatagramPacket(buffer, buffer.length);
                socket.receive(paquete);
                byte type = parsearInfo(paquete.getData());
                if (type == 1) {
                    System.out.println("Discover recibido");
                }
                //DHCPOffer                
                byte[] respuesta = generarMensaje((short) 1, (short) 2);
                DatagramPacket paqueteEnviar = new DatagramPacket(respuesta, respuesta.length,
                        InetAddress.getByName("255.255.255.255"), 68);
                socket.send(paqueteEnviar);
                System.out.println("Offer");
                //DHCPRequest            
                buffer = new byte[567];
                paquete = new DatagramPacket(buffer, buffer.length);
                socket.receive(paquete);
                type = parsearInfo(paquete.getData());
                if (type == 3) {
                    System.out.println("Request");
                    salir = true;
                }
            }
            //DHCPAck
            byte[] respuesta = generarMensaje((short) 1, (short) 5);
            DatagramPacket paqueteEnviar = new DatagramPacket(respuesta, respuesta.length,
                    InetAddress.getByName("255.255.255.255"), 68);
            socket.send(paqueteEnviar);
            System.out.println("Ack");

        } catch (SocketException ex) {
            Logger.getLogger(ServidorDHCP.class.getName()).log(Level.SEVERE, null, ex);
        } catch (IOException ex) {
            Logger.getLogger(ServidorDHCP.class.getName()).log(Level.SEVERE, null, ex);
        }
        System.out.println("IP configurada");
    }

    private static byte parsearInfo(byte[] data) {
        ByteBuffer bBuffer = ByteBuffer.wrap(data);

        id = bBuffer.getInt(4);
        System.out.println("Id: " + Integer.toHexString(id));

        for (int i = 28; i < 34; i++) {
//            System.out.print(String.format("%02X ", bBuffer.get(i)));
            mac[i - 28] = bBuffer.get(i);
//            if(i < 33)
//                System.out.print(":");
        }

        int puntero = 240;
        boolean terminar = false;
        byte type = -1;
        while (!terminar) {
            int codigo = bBuffer.get(puntero);
            ++puntero;
            int longitud = bBuffer.get(puntero);
            ++puntero;
            if (codigo == 53) {
                terminar = true;
                type = bBuffer.get(puntero);
            }
            puntero += longitud;
        }
        return type;
    }

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
        for (int i = 0; i < 3; ++i) {
            mensaje.put((byte) 255);
        }
        mensaje.put((byte) 0);
        //DNS
        mensaje.put((byte) 6);
        mensaje.put((byte) 4);
        for (int i = 0; i < 4; ++i) {
            mensaje.put((byte) 8);
        }
        //Router
        mensaje.put((byte) 3);
        mensaje.put((byte) 4);
        for (byte r : router) {
            mensaje.put(r);
        }
//        //IP Cliente
        mensaje.put((byte) 50);
        mensaje.put((byte) 4);
        for (byte i : ipCliente) {
            mensaje.put(i);
        }
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
        for (byte i : servidor) {
            mensaje.put(i);
        }
        //END
        mensaje.put((byte) 255);

        return mensaje.array();
    }

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
        for (byte c : ipCliente) {
            mensaje.put(c);
        }
        //siaddr
        mensaje.putInt(0);
        //giaddr
        mensaje.putInt(0);
        //chaddr (mac)
        for (byte c : mac) {
            mensaje.put(c);
        }
        return mensaje.array();
    }

}
