using System;
using System.Collections.Generic;
using System.Data;
using System.Linq;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using System.Net;
using System.Net.Sockets;
using System.Net.NetworkInformation;
using System.IO;
using System.Text.RegularExpressions;
using System.Security.Cryptography;
namespace SocketEmulator
{
    public partial class SocketEmulator
    {
        // keep alive -> http://jiunway.blogspot.tw/2010/06/c-keep-alivesocket_22.html
        // websocket -> https://stackoverflow.com/questions/8125507/how-can-i-send-and-receive-websocket-messages-on-the-server-side/30829965
        public static string GetCurrentFilePath(string filename)
        {
            String appdir = Path.GetDirectoryName(Application.ExecutablePath);
            String myFilePath = Path.Combine(appdir, filename);
            return myFilePath;
        }

        private void Write_Exception_Log(string str_ex)//Exception log
        {
            lock (_ex_log_server_Lock)
            {
                if (!Directory.Exists(GetCurrentFilePath(@"Exception Log")))
                {
                    DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Exception Log"));
                }
                string file = GetCurrentFilePath(@"Exception Log\Exception_Log_" + DateTime.Now.ToString("yyyyMM") + ".csv");
                string first_line_in_file = "Record Time, Exception";
                if (!File.Exists(file))
                {
                    using (StreamWriter sw = File.CreateText(file))
                    {
                        sw.WriteLine(first_line_in_file);
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " + str_ex);
                    }
                }
                else if (File.Exists(file))
                {
                    using (StreamWriter sw = File.AppendText(file))
                    {
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " + str_ex);
                    }
                }
            }
        }

        //HTTP Request
        private void Socket_Client_HTTP() {
            //ref-http://stackoverflow.com/questions/11862890/c-how-to-execute-a-http-request-using-sockets
            Socket clientSocket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            IPEndPoint IPEndPoint_Socket_Server_Training = new IPEndPoint(IPAddress.Parse("10.100.82.52"), 2044);
            clientSocket.Connect(IPEndPoint_Socket_Server_Training);
            string GETrequest = "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: keep-alive\r\nAccept: text/html\r\nUser-Agent: CSharpTests\r\n\r\n";
            clientSocket.Send(Encoding.ASCII.GetBytes(GETrequest));
            bool flag = true; // just so we know we are still reading
            string headerString = ""; // to store header information
            int contentLength = 0; // the body length
            byte[] bodyBuff = new byte[0]; // to later hold the body content
            while (flag)
            {
                // read the header byte by byte, until \r\n\r\n
                byte[] buffer = new byte[1];
                clientSocket.Receive(buffer, 0, 1, 0);
                headerString += Encoding.ASCII.GetString(buffer);
                if (headerString.Contains("\r\n\r\n"))
                {
                    // header is received, parsing content length
                    // I use regular expressions, but any other method you can think of is ok
                    Regex reg = new Regex("\\\r\nContent-Length: (.*?)\\\r\n");
                    Match m = reg.Match(headerString);
                    contentLength = int.Parse(m.Groups[1].ToString());
                    flag = false;
                    // read the body
                    bodyBuff = new byte[contentLength];
                    clientSocket.Receive(bodyBuff, 0, contentLength, 0);
                }
            }
            //Console.WriteLine("Server Response :");
            string body = Encoding.UTF8.GetString(bodyBuff);
            //Console.WriteLine(body);
            clientSocket.Close();
        }

        private void Byte_Encoding() 
        {
            byte[] byte_hex = { 0x4B, 0x1F };
            string str_hex = 0x4B.ToString("{0:X}");
            short int16_hex = BitConverter.ToInt16(byte_hex, 0);
            short int_dec = 8011;
            byte[] byte_dec = BitConverter.GetBytes(int_dec);
            short int16_dec = BitConverter.ToInt16(byte_dec, 0);
            string str_origin = "HelloWorld---!-22你好";
            int length_str_origin = str_origin.Length;
            byte[] byte_enc_utf8 = Encoding.UTF8.GetBytes(str_origin);
            string str_dec_uft8 = Encoding.UTF8.GetString(byte_enc_utf8);
            //ref-http://www.cnblogs.com/serafin/archive/2012/07/13/2589794.html
            string text = " 【中文】（12.21）(ァぁ)[En] ";
            var String_Len = text.Length;
            var ASCII_Len = Encoding.ASCII.GetBytes(text).Length;
            var Default_Len = Encoding.Default.GetBytes(text).Length;
            var BigEndianUnicode_Len = Encoding.BigEndianUnicode.GetBytes(text).Length;
            var Unicode_Len = Encoding.Unicode.GetBytes(text).Length;
            var UTF32_Len = Encoding.UTF32.GetBytes(text).Length;
            var UTF7_Len = Encoding.UTF7.GetBytes(text).Length;
            var UTF8_Len = Encoding.UTF8.GetBytes(text).Length;
            var GB2312_Len = Encoding.GetEncoding("GB2312").GetBytes(text).Length;
        }

        private void Network_Status()
        {
            IPHostEntry heserver = Dns.GetHostEntry("www.google.com");
            IPAddress curAdd = heserver.AddressList[0];
            Byte[] bytes = curAdd.GetAddressBytes();
            IPAddress[] IPAddress_From_DNS = Dns.GetHostAddresses("www.google.com.tw");
            Uri uri = new Uri("https://www.google.com");
            /*ref-http://stackoverflow.com/questions/520347/how-do-i-check-for-a-network-connection
             *ref--http://stackoverflow.com/questions/314213/checking-network-status-in-c-sharp
            */
            IPAddress testIPAddress = IPAddress.Parse("10.100.82.52");
            Ping ping = null;
            PingReply reply = null;
            try
            {
                ping = new Ping();
                reply = ping.Send(IPAddress.Parse("10.100.82.53"));
                if (reply.Status == IPStatus.Success)
                {

                }
            }
            catch (Exception ex)
            {
            }
            finally
            {
            }

            bool IsNetworkAvailable = System.Net.NetworkInformation.NetworkInterface.GetIsNetworkAvailable();
            NetworkInterface[] Interfaces = System.Net.NetworkInformation.NetworkInterface.GetAllNetworkInterfaces();
            foreach (NetworkInterface Adapter in Interfaces)
            {
                IPInterfaceProperties Properties = Adapter.GetIPProperties();
                PhysicalAddress Address = Adapter.GetPhysicalAddress();
            }

            string str_IP_address = "";
            using (WebClient client = new WebClient())
            {
                str_IP_address = "IP Address: " + client.DownloadString("http://icanhazip.com/");
                //client.Dispose();
            }
            string str_all_Local_IP_address = "";
            string strHostName = Dns.GetHostName();
            IPHostEntry iphostentry = Dns.GetHostEntry(strHostName);
            bool IsGetLocalAddress = false;
            foreach (IPAddress ipaddress in iphostentry.AddressList)
            {
                if (ipaddress.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    if (!IsGetLocalAddress)
                    {
                        str_all_Local_IP_address += "Local IP Address: " + ipaddress.ToString();
                        IsGetLocalAddress = true;
                    }
                }
            }
            NetworkInterface[] adapters = NetworkInterface.GetAllNetworkInterfaces();
            string str_all_Gateway_address = "";
            bool IsGetGatewayaddress = false;
            foreach (NetworkInterface adapter in adapters)
            {
                IPInterfaceProperties adapterProperties = adapter.GetIPProperties();
                GatewayIPAddressInformationCollection addresses = adapterProperties.GatewayAddresses;
                if (addresses.Count > 0)
                {
                    //Console.WriteLine(adapter.Description);
                    foreach (GatewayIPAddressInformation address in addresses)
                    {
                        if (!IsGetGatewayaddress)
                        {
                            str_all_Gateway_address += "Gateway: " + address.Address.ToString();
                            IsGetGatewayaddress = true;
                        }
                    }
                }
            }

            NetworkInterface[] nics = NetworkInterface.GetAllNetworkInterfaces();
            string str_mac_address = "";
            bool IsGetPhysicalAddress = false;
            List<string> macList = new List<string>();
            foreach (var nic in nics)
            {
                if (nic.NetworkInterfaceType == NetworkInterfaceType.Ethernet)
                {
                    if (!IsGetPhysicalAddress)
                    {
                        str_mac_address += "Mac Address: " + nic.GetPhysicalAddress().ToString();
                        IsGetPhysicalAddress = true;
                        //macList.Add(nic.GetPhysicalAddress().ToString());
                    }
                }
            }
        }

        private static byte[] Get_Binary_MD5(byte[] binary_data)//MD5 Hash Code
        {
            MD5 md511 = MD5.Create();
            byte[] hash_data = md511.ComputeHash(binary_data);
            //string str_md5 = "";
            //for (int i = 0; i < hash_data.Length; i++)
            //{
            //    str_md5 += hash_data[i].ToString("x2");
            //}
            md511.Dispose();
            return hash_data;
        }

        private void SSL_Test()
        {
        }

        //Socket
        Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private void Socket_Initial()
        {
            //IPGlobalProperties properties = IPGlobalProperties.GetIPGlobalProperties();
            //            TcpConnectionInformation connections = properties.GetActiveTcpConnections();
            //TcpConnectionInformation[] connections = properties.GetActiveTcpConnections();
            //IPEndPoint IPEndPoint_Palert = null;
            //IPEndPoint IPEndPoint_PC = null;
            //for (int t = 0; t < connections.Length;t++)
            //{
            //    Console.Write("Local endpoint: {0} ", connections[t].LocalEndPoint.Address);
            //    Console.WriteLine("{0}", connections[t].State);
            //    if (connections[t].RemoteEndPoint.Address.ToString() == "10.100.82.155")
            //    {
            //        IPEndPoint_PC = new IPEndPoint(connections[t].LocalEndPoint.Address, connections[t].LocalEndPoint.Port);
            //        IPEndPoint_Palert = new IPEndPoint(connections[t].RemoteEndPoint.Address, connections[t].RemoteEndPoint.Port);
            //    }
            //}

            try
            {
                socket.Bind(new IPEndPoint(IPAddress.Any, Port_Socket_Server_Palert));
                //IPEndPoint IPEndPoint_PC = new IPEndPoint(IPAddress.Parse("10.100.82.52"), Port_Socket_Server_Palert);
                //socket.Bind(IPEndPoint_PC);
                socket.Listen(10);
                while (true)
                {
                    Thread.Sleep(1000);
                    //Thread thread_socketserver = new Thread(Accept_Palert);
                    //thread_socketserver.IsBackground = true;
                    //thread_socketserver.Start();
                    //Socket accepted = null;
                    //try {
                    //    accepted = socket.Accept(); // <-----waits here...???    
                    //}
                    //catch (Exception e) { }

                    //IPEndPoint clientInfo = (IPEndPoint)accepted.RemoteEndPoint;
                    //EndPoint senderRemote = (EndPoint)IPEndPoint_Palert;
                    //byte[] Buffer = new byte[1200];
                    //int bytesRead = accepted.Receive(Buffer, 1200, 0);
                    //byte[] Buffer2 = new byte[1200];
                    //int bytesRead2 = accepted.ReceiveFrom(Buffer2, 0, socket.Available, SocketFlags.None, ref senderRemote);
                    ////byte[] formatted = new byte[bytesRead];
                    //accepted.Close();

                    //s.BeginAccept(new AsyncCallback(Socket_Begin_Accept), s);

                    //byte[] receivedbyte = new byte[1200];
                    //socket.Accept();
                    //socket.Receive(receivedbyte, 1200, 0);
                    //Thread.Sleep(1000);
                    //Thread threadsocketserver1 = new Thread(new ParameterizedThreadStart(Accept_P1));
                    //threadsocketserver1.IsBackground = true;
                    //threadsocketserver1.Start(socket);
                    //Thread.Sleep(1000);//自機測試
                    //Thread threadsocketserver1 = new Thread(Accept_P1);
                    //threadsocketserver1.IsBackground = true;
                    //threadsocketserver1.Start();
                }
            }
            catch (Exception Ex)
            {
            }
        }
        public void Accept_P1()
        {
            //object S
            //Socket socket = (Socket)S;
            Socket p1Socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            //Socket p1Socket = serverserviceSocket;
            try
            {
                p1Socket = socket.Accept();
                //socket.Accept();
                byte[] receivedbyte = new byte[p1Socket.ReceiveBufferSize];
                while (true)
                {
                    //When does Socket.Receive return the data?http://stackoverflow.com/questions/15523976/when-does-socket-receive-return-the-data
                    int size = p1Socket.Receive(receivedbyte, p1Socket.ReceiveBufferSize, 0);
                    string receivedmsg = Encoding.ASCII.GetString(receivedbyte, 0, 2);
                    byte[] msg = Encoding.ASCII.GetBytes("response");
                    int bytesSend = p1Socket.Send(msg, 0, msg.Length, SocketFlags.None);

                    //socket.Receive(receivedbyte, 1200, 0);
                }
            }
            catch (Exception Ex)
            {
            }
            finally
            {
                p1Socket.Close();
            }
        }

        private List<Client_Info> client_info = new List<Client_Info>();
        private int total_client = 0;
        private void Handle_Data()
        {
            while (true)
            {
                if (client_info.Count != 0)
                {
                    //int ss = 1;
                    Monitor.Enter(client_info);
                    //Write_Session_Log_Server();
                    total_client += client_info.Count;
                    label_current_count_session.Invoke(new Action(() => label_current_count_session.Text = client_info.Count.ToString()));
                    label_total_count_session.Invoke(new Action(() => label_total_count_session.Text = total_client.ToString()));
                    //client_info.RemoveAt(0);
                    client_info.RemoveAll(remove_info => true);
                    Monitor.Exit(client_info);
                }
                Thread.Sleep(1 * 1000);
            }
        }

        //Socket
        Socket Socket_Server_Training = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
        private static int Port_Socket_Server_Training = 8011;
        private int maximun_num_client_socket_server_listen = 100000;
        private int num_socket_client_training = 10000;//客戶端數量
        public static int packet_header_length_training = 42;//header length
        private void Button_Socket_Server_Training_Click(object sender, EventArgs e)
        {
            Thread_Socket_Server_Training();
        }
        private class Session_Packet_Server_Training
        {
            /* Define package session protocol header, body
             * index    data
             * 0-1      Socket Special Code 8011
             * 2-3      Synchronized Character 0 {0x20, 0x16}
             * 4-5      Synchronized Character 1 {0x06, 0x02}
             * 6-7      Packet Transmit Time (Year)
             * 8        Packet Transmit Time (Month)
             * 9        Packet Transmit Time (Day)
             * 10       Packet Transmit Time (Hour)
             * 11       Packet Transmit Time (Minute)
             * 12       Packet Transmit Time (Second)
             * 13       Packet Transmit Time (10mSecond)
             * 14-15    Packet Body Info Length
             * 16-17    Packet Body Binary Length
             * 18-33    Binary MD5 Code
             * 34-41    Client ID
            */
            //Socket Send 8192 bytes header,body
            public byte[] header = new byte[packet_header_length_training];
            public byte[] body_info = new byte[0];
            public byte[] body_binary = new byte[0];
            public short socket_special_code;
            public byte[] socket_syn_char0;
            public byte[] socket_syn_char1;
            public DateTime datetime_transmit;
            //public short client_id;
            public Int64 client_id;
            public short packet_body_info_length;
            public short packet_body_binary_length;
            public byte[] binary_md5 = new byte[16];//32 bit MD5
            public bool IsFormatWell = false;
            public void Packet_Decode()
            {
                socket_special_code = BitConverter.ToInt16(header, 0);
                socket_syn_char0 = SubArray(header, 2, 2);
                socket_syn_char1 = SubArray(header, 4, 2);
                datetime_transmit = new DateTime(BitConverter.ToInt16(header, 6),
                                                 Convert.ToInt16(header[8]), Convert.ToInt16(header[9]),
                                                 Convert.ToInt16(header[10]), Convert.ToInt16(header[11]),
                                                 Convert.ToInt16(header[12]), Convert.ToInt16(header[13]));
                //client_id = Convert.ToInt16(header[14]);
                client_id = BitConverter.ToInt64(header, 34);
                packet_body_info_length = BitConverter.ToInt16(header, 14);
                packet_body_binary_length = BitConverter.ToInt16(header, 16);
                body_info = new byte[packet_body_info_length];
                body_binary = new byte[packet_body_binary_length];
                binary_md5 = SubArray(header, 18, 16);
                if ((socket_special_code == Port_Socket_Server_Training) &&
                    (socket_syn_char0[0] == 0x20) &&
                    (socket_syn_char0[1] == 0x16) &&
                    (socket_syn_char1[0] == 0x06) &&
                    (socket_syn_char1[1] == 0x02)
                   )
                {
                    IsFormatWell = true;
                }
            }
            private byte[] SubArray(byte[] data, int index, int length)
            {
                byte[] result = new byte[length];
                Array.Copy(data, index, result, 0, length);
                return result;
            }
            public byte[] packet_status = new byte[0];
            public void Create_Packet_Statue(bool IsReceiveWell)
            {
                if (IsReceiveWell)
                {
                    packet_status = new byte[] { 0x00, 0x08, 0x08, 0x06 };
                }
                else
                {
                    packet_status = new byte[] { 0x00, 0x08, 0x00, 0x00 };
                }
            }
        }
        private void Thread_Socket_Server_Training()
        {
            Thread thread_Socket_Server_Training_Initial = new Thread(Socket_Server_Training_Initial);
            thread_Socket_Server_Training_Initial.IsBackground = true;
            thread_Socket_Server_Training_Initial.Start();

            Thread thread_Handle_Data = new Thread(Handle_Data);
            thread_Handle_Data.IsBackground = true;
            thread_Handle_Data.Start();
        }
        private void Socket_Server_Training_Initial()
        {
            try
            {
                Socket_Server_Training.Bind(new IPEndPoint(IPAddress.Any, Port_Socket_Server_Training));
                Socket_Server_Training.Listen(maximun_num_client_socket_server_listen);
                while (true)
                {
                    Socket Socket_Client_Training = Socket_Server_Training.Accept();
                    Thread thread_Socket_Server_Training_Session_Management = new Thread(new ParameterizedThreadStart(Socket_Server_Training_Session_Management));
                    thread_Socket_Server_Training_Session_Management.IsBackground = true;
                    thread_Socket_Server_Training_Session_Management.Start(Socket_Client_Training);
                    Thread.Sleep(1 * 1);//new thread to proceed package
                }
                Socket_Server_Training.Close();
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Server("Socket_Server_Training_Initial " + ex.ToString());
                Socket_Server_Training.Close();
                Thread.Sleep(5 * 1000);
                Socket_Server_Training_Initial();
            }
            finally
            {
            }
        }
        private void Socket_Server_Training_Session_Management(object arg)
        {
            Socket Socket_Client_Training = arg as Socket;
            Session_Packet_Server_Training Session_Packet = new Session_Packet_Server_Training();
            try
            {
                //while (true)
                //{
                    int size_header = Socket_Client_Training.Receive(Session_Packet.header, packet_header_length_training, SocketFlags.None);
                    Session_Packet.Packet_Decode();
                    if (Session_Packet.IsFormatWell)
                    {
                        if (Session_Packet.packet_body_info_length > 0)
                        { // accept self defined string
                            int size_body_info = Socket_Client_Training.Receive(Session_Packet.body_info, Session_Packet.packet_body_info_length, SocketFlags.None);
                        }
                        if (Session_Packet.packet_body_binary_length > 0)
                        { // accept self defined binary
                            int size_body_binary = Socket_Client_Training.Receive(Session_Packet.body_binary, Session_Packet.packet_body_binary_length, SocketFlags.None);
                        }
                        byte[] decode_binary_md5 = Get_Binary_MD5(Session_Packet.body_binary);
                        //ref-http://stackoverflow.com/questions/43289/comparing-two-byte-arrays-in-net
                        bool IsDecodeWell = decode_binary_md5.SequenceEqual(Session_Packet.binary_md5);
                        Session_Packet.Create_Packet_Statue(IsDecodeWell);
                        if (IsDecodeWell)
                        {
                            Monitor.Enter(client_info);
                            client_info.Add(new Client_Info() {
                                info = Encoding.UTF8.GetString(Session_Packet.body_info),
                                client_id = Session_Packet.client_id.ToString(),
                                remote_endpoint = Socket_Client_Training.RemoteEndPoint.ToString(),
                                datetime_transmit = Session_Packet.datetime_transmit.ToString("yyyy-MM-dd HH:mm:ss"),
                            });
                            Monitor.Exit(client_info);
                            //Write_Session_Log_Server(Session_Packet, Socket_Client_Training);
                            //Write_Session_Binary_Server(Session_Packet, Socket_Client_Training);
                            Socket_Client_Training.Send(new byte[] { 0x00, 0x08, 0x08, 0x06 });
                        }
                        else
                        {
                            Socket_Client_Training.Send(new byte[] { 0x00, 0x08, 0x00, 0x00 });
                        }
                    }
                //}
                Socket_Client_Training.Close();
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Server("Socket_Server_Training_Session_Management " + ex.ToString());
                Thread.Sleep(5 * 1000);
                Socket_Server_Training_Session_Management(arg);
            }
            finally
            {
            }
        }

        //Server log for ok status
        object _sesion_log_server_Lock = new object();
        object _sesion_binary_server_Lock = new object();
        private object _ex_log_server_Lock = new object();
        private void Write_Exception_Log_Server(string str_ex)//Exception log
        {
            lock (_ex_log_server_Lock)
            {
                if (!Directory.Exists(GetCurrentFilePath(@"Server\Exception Log")))
                {
                    DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Server\Exception Log"));
                }
                string file = GetCurrentFilePath(@"Server\Exception Log\Exception_Log_" + DateTime.Now.ToString("yyyyMM") + ".csv");
                string first_line_in_file = "Record Time, Exception";
                if (!File.Exists(file))
                {
                    using (StreamWriter sw = File.CreateText(file))
                    {
                        sw.WriteLine(first_line_in_file);
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " + str_ex);
                    }
                }
                else if (File.Exists(file))
                {
                    using (StreamWriter sw = File.AppendText(file))
                    {
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " + str_ex);
                    }
                }
            }
        }
        private class Client_Info
        {
            public string info;
            public string client_id;
            public string remote_endpoint;
            public string datetime_transmit;
        }
        private void Write_Session_Log_Server()
        {
            try
            {
                lock (_sesion_log_server_Lock)
                {
                    if (!Directory.Exists(GetCurrentFilePath(@"Server\Session Log")))
                    {
                        DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Server\Session Log"));
                    }
                    string file = GetCurrentFilePath(@"Server\Session Log\Session_Log_" + DateTime.Now.ToString("yyyyMM") + ".csv");
                    string first_line_in_file = "Record Time, Transmit Time, Client_id, RemoteEndPoint, Info, ";
                    if (!File.Exists(file))
                    {
                        using (StreamWriter sw = File.CreateText(file))
                        {
                            sw.WriteLine(first_line_in_file);
                            //int i = 0;
                            for (int i = 0; i < client_info.Count; i++)
                            {
                                sw.WriteLine("@" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                                "@" + client_info[i].datetime_transmit + ", " +
                                                client_info[i].client_id + ", " +
                                                client_info[i].remote_endpoint + ", " +
                                                client_info[i].info
                                            );
                            }
                        }
                    }
                    else if (File.Exists(file))
                    {
                        using (StreamWriter sw = File.AppendText(file))
                        {
                            //int i = 0;
                            for (int i = 0; i < client_info.Count; i++)
                            {
                                sw.WriteLine("@" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                                "@" + client_info[i].datetime_transmit + ", " +
                                                client_info[i].client_id + ", " +
                                                client_info[i].remote_endpoint + ", " +
                                                client_info[i].info
                                            );
                            }
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Server("Write_Session_Log_Server " + ex.ToString());
            }
            finally
            {
            }
        }
        private void Write_Session_Log_Server(Session_Packet_Server_Training Session_Packet, Socket Socket_Client_Training)//Server收到正確後寫Session Info檔案
        {
            try
            {
                lock (_sesion_log_server_Lock)
                {
                    if (!Directory.Exists(GetCurrentFilePath(@"Server\Session Log")))
                    {
                        DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Server\Session Log"));
                    }
                    string file = GetCurrentFilePath(@"Server\Session Log\Session_Log_" + DateTime.Now.ToString("yyyyMM") + ".csv");
                    string first_line_in_file = "Record Time, Transmit Time, Client_id, RemoteEndPoint, Info, ";
                    if (!File.Exists(file))
                    {
                        using (StreamWriter sw = File.CreateText(file))
                        {
                            sw.WriteLine(first_line_in_file);
                            string info = "";
                            if (Session_Packet.packet_body_info_length != 0)
                            {
                                info = Encoding.UTF8.GetString(Session_Packet.body_info);
                            }
                            sw.WriteLine("@" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         "@" + Session_Packet.datetime_transmit.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         Session_Packet.client_id.ToString() + ", " +
                                         Socket_Client_Training.RemoteEndPoint + ", " +
                                         info
                                        );
                        }
                    }
                    else if (File.Exists(file))
                    {
                        using (StreamWriter sw = File.AppendText(file))
                        {
                            string info = "";
                            if (Session_Packet.packet_body_info_length != 0)
                            {
                                info = Encoding.UTF8.GetString(Session_Packet.body_info);
                            }
                            sw.WriteLine("@" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         "@" + Session_Packet.datetime_transmit.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         Session_Packet.client_id.ToString() + ", " +
                                         Socket_Client_Training.RemoteEndPoint + ", " +
                                         info
                                        );
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Server("Write_Session_Log_Server " + ex.ToString());
            }
            finally
            {
            }
        }
        private void Write_Session_Binary_Server(Session_Packet_Server_Training Session_Packet, Socket Socket_Client_Training)//Server收到正確後寫Session Binary檔案
        {
            try
            {
                lock (_sesion_binary_server_Lock)
                {
                    if (!Directory.Exists(GetCurrentFilePath(@"Server\Session Binary")))
                    {
                        DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Server\Session Binary"));
                    }
                    string file = GetCurrentFilePath(@"Server\Session Binary\Client" + Session_Packet.client_id + @"_Binary_" + Session_Packet.datetime_transmit.ToString("yyyyMMddhhmmss") + ".bin");
                    File.WriteAllBytes(file, Session_Packet.body_binary);
                }
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Server("Write_Session_Binary_Server " + ex.ToString());
            }
            finally
            {
            }
        }

        //練習多使用者
        private void Button_Socket_Client_Training_Click(object sender, EventArgs e)
        {
            Int64 max_num_client_training = Convert.ToInt64(TextBox_Num_Socket_Client_Training.Text);
            for (Int64 cid = 0; cid < max_num_client_training; cid++)
            {
                //short client_id = (short)cid;
                Int64 client_id = (Int64)cid;
                Thread_Socket_Client_Training(client_id);
                //Thread.Sleep(1);
            }
        }
        private class Session_Packet_Client_Training
        {
            /* define package session protocol header body
             * index    data
             * 0-1      Socket Special Code 8011
             * 2-3      Synchronized Character 0 {0x20, 0x16}
             * 4-5      Synchronized Character 1 {0x06, 0x02}
             * 6-7      Packet Transmit Time (Year)
             * 8        Packet Transmit Time (Month)
             * 9        Packet Transmit Time (Day)
             * 10       Packet Transmit Time (Hour)
             * 11       Packet Transmit Time (Minute)
             * 12       Packet Transmit Time (Second)
             * 13       Packet Transmit Time (10mSecond)
             * 14-15    Packet Body Info Length
             * 16-17    Packet Body Binary Length
             * 18-33    Binary MD5 Code
             * 34-41    Client ID
            */
            //Socket Send 8192 bytes header,body
            public byte[] header = new byte[packet_header_length_training];
            public byte[] body_info = new byte[0];
            public byte[] body_binary = new byte[0];
            public byte[] packet = new byte[0];
            public DateTime datetime_transmit;
            //public short client_id;
            public Int64 client_id2;
            public string str_2send;
            public void Packet_Encode(Int64 client_id2)
            {
                byte[] byte_socket_spacial_code = BitConverter.GetBytes((short)Port_Socket_Server_Training);//Socket Special Code 8011
                byte[] byte_socket_syn_char0 = { 0x20, 0x16 };//Synchronized Character 0 {0x20, 0x16}
                byte[] byte_socket_syn_char1 = { 0x06, 0x02 };//Synchronized Character 1 {0x06, 0x02}

                datetime_transmit = DateTime.Now;
                byte[] byte_datetime_transmit_year = BitConverter.GetBytes((short)datetime_transmit.Year);
                byte byte_datetime_transmit_month = Convert.ToByte((short)datetime_transmit.Month);
                byte byte_datetime_transmit_day = Convert.ToByte((short)datetime_transmit.Day);
                byte byte_datetime_transmit_hour = Convert.ToByte((short)datetime_transmit.Hour);
                byte byte_datetime_transmit_minute = Convert.ToByte((short)datetime_transmit.Minute);
                byte byte_datetime_transmit_second = Convert.ToByte((short)datetime_transmit.Second);
                byte byte_datetime_transmit_10msecond = Convert.ToByte((short)(datetime_transmit.Millisecond / 10));
                this.client_id2 = client_id2;
                //byte byte_client_id = Convert.ToByte(client_id);
                byte[] byte_client_id = BitConverter.GetBytes(client_id2);
                Random rand_str = new Random();
                string a2z = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!@()";
                string str_2send = "";
                for (int rs = 0; rs < rand_str.Next(0, a2z.Length); rs++)
                {
                    int num_rs = rand_str.Next(0, a2z.Length);
                    str_2send += a2z[num_rs];
                }
                this.str_2send = str_2send;
                byte[] byte_str2send = Encoding.UTF8.GetBytes("Hello There! " + str_2send);//self defined string
                byte[] byte_packet_body_info_length = BitConverter.GetBytes((short)byte_str2send.Length);//Packet Body Info Length
                body_binary = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };//self defined binary
                byte[] byte_packet_body_binary_length = BitConverter.GetBytes((short)body_binary.Length);//Packet Body Binary Length
                byte[] byte_packet_md5 = Get_Binary_MD5(body_binary);//Binary MD5

                //完成header
                int packet_length_accumulation = 0;
                Buffer.BlockCopy(byte_socket_spacial_code, 0, header, 0, byte_socket_spacial_code.Length);//0-1
                packet_length_accumulation += byte_socket_spacial_code.Length;
                Buffer.BlockCopy(byte_socket_syn_char0, 0, header, packet_length_accumulation, byte_socket_syn_char0.Length);//2-3
                packet_length_accumulation += byte_socket_syn_char0.Length;
                Buffer.BlockCopy(byte_socket_syn_char1, 0, header, packet_length_accumulation, byte_socket_syn_char1.Length);//4-5
                packet_length_accumulation += byte_socket_syn_char1.Length;
                Buffer.BlockCopy(byte_datetime_transmit_year, 0, header, packet_length_accumulation, byte_datetime_transmit_year.Length);//6-7
                packet_length_accumulation += byte_datetime_transmit_year.Length;
                header[packet_length_accumulation] = byte_datetime_transmit_month;//8
                packet_length_accumulation++;
                header[packet_length_accumulation] = byte_datetime_transmit_day;//9
                packet_length_accumulation++;
                header[packet_length_accumulation] = byte_datetime_transmit_hour;//10
                packet_length_accumulation++;
                header[packet_length_accumulation] = byte_datetime_transmit_minute;//11
                packet_length_accumulation++;
                header[packet_length_accumulation] = byte_datetime_transmit_second;//12
                packet_length_accumulation++;
                header[packet_length_accumulation] = byte_datetime_transmit_10msecond;//13
                packet_length_accumulation++;
                Buffer.BlockCopy(byte_packet_body_info_length, 0, header, packet_length_accumulation, byte_packet_body_info_length.Length);//14-15
                packet_length_accumulation += byte_packet_body_info_length.Length;
                Buffer.BlockCopy(byte_packet_body_binary_length, 0, header, packet_length_accumulation, byte_packet_body_binary_length.Length);//16-17
                packet_length_accumulation += byte_packet_body_binary_length.Length;
                Buffer.BlockCopy(byte_packet_md5, 0, header, packet_length_accumulation, byte_packet_md5.Length);//18-33
                packet_length_accumulation += byte_packet_md5.Length;
                //header[packet_length_accumulation] = byte_client_id[1];//15
                Buffer.BlockCopy(byte_client_id, 0, header, packet_length_accumulation, byte_client_id.Length);//34-41
                packet_length_accumulation += byte_client_id.Length;

                //define packet length
                packet = new byte[header.Length + byte_str2send.Length + body_binary.Length];
                //header
                Buffer.BlockCopy(header, 0, packet, 0, header.Length);
                //body_info
                body_info = byte_str2send;
                Buffer.BlockCopy(body_info, 0, packet, header.Length, body_info.Length);
                //body_binary
                Buffer.BlockCopy(body_binary, 0, packet, header.Length + body_info.Length, body_binary.Length);
            }
            public byte[] packet_status = new byte[4];
        }
        //socket client (retry)
        private void Thread_Socket_Client_Training(Int64 client_id)
        {
            try
            {
                Thread thread_Socket_Client_Training_Session_Management = new Thread(Socket_Client_Training_Session_Management);
                thread_Socket_Client_Training_Session_Management.IsBackground = true;
                thread_Socket_Client_Training_Session_Management.Start(client_id);
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Client("Button_Socket_Client0_Training_Click " + ex.ToString());
            }
            finally
            {
            }
        }
        private void Socket_Client_Training_Session_Management(object arg)
        {
            //short client_id = (short)arg;
            Int64 client_id = (Int64)arg;
            try
            {
                using(Socket Socket_Client_Training = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp)){
                IPEndPoint Socket_Server_Training = new IPEndPoint(IPAddress.Parse("10.100.82.52"), Port_Socket_Server_Training);
                Socket_Client_Training.Connect(Socket_Server_Training);
                //while (true)
                //{
                    Session_Packet_Client_Training Session_Packet = new Session_Packet_Client_Training();
                    Session_Packet.Packet_Encode(client_id);
                    Socket_Client_Training.Send(Session_Packet.packet);
                    int resend_times = 0;
                    bool IsFinishSending = false;
                    while (!IsFinishSending)
                    {
                        int size_packet_status = Socket_Client_Training.Receive(Session_Packet.packet_status, Session_Packet.packet_status.Length, SocketFlags.None);
                        bool IsDecodeWell = Session_Packet.packet_status.SequenceEqual(new byte[] { 0x00, 0x08, 0x08, 0x06 });
                        if (IsDecodeWell)
                        {
                            IsFinishSending = true;
                        }
                        else
                        {
                            Socket_Client_Training.Send(Session_Packet.packet);
                            resend_times++;
                        }
                        if (resend_times == 3)
                        {
                            Write_Exception_Log_Client(" Packet Lost | " + "client_id " + client_id.ToString() + " | " + " LocalEndPoint " + Socket_Client_Training.LocalEndPoint + " | " + " md5 wrong and resend over 3 times | Packet Lost");
                            //Write_Session_Log_Client(Session_Packet, Socket_Client_Training);
                            //Write_Session_Binary_Client(Session_Packet, Socket_Client_Training);
                            IsFinishSending = true;
                        }
                    }
                    //Thread.Sleep(30 * 60 * 1000);
                //}
                Socket_Client_Training.Close();
            }
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Client("Socket_Client_Training_Session_Management " + "client_id " + client_id.ToString() + " | " + ex.ToString());
                //Socket_Client_Training.Close();
                Thread.Sleep(30 * 1000);
                Socket_Client_Training_Session_Management(arg);
            }
            finally
            {
            }
        }

        //Server receiving error，log in client
        private object _ex_log_client_Lock = new object();
        private object _sesion_log_client_Lock = new object();
        private object _sesion_binary_client_Lock = new object();
        private void Write_Exception_Log_Client(string str_ex)//Exception log client
        {
            lock (_ex_log_client_Lock)
            {
                if (!Directory.Exists(GetCurrentFilePath(@"Client\Exception Log")))
                {
                    DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Client\Exception Log"));
                }
                string file = GetCurrentFilePath(@"Client\Exception Log\Exception_Log_" + DateTime.Now.ToString("yyyyMM") + ".csv");
                string first_line_in_file = "Record Time, Exception";
                if (!File.Exists(file))
                {
                    using (StreamWriter sw = File.CreateText(file))
                    {
                        sw.WriteLine(first_line_in_file);
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " + str_ex);
                    }
                }
                else if (File.Exists(file))
                {
                    using (StreamWriter sw = File.AppendText(file))
                    {
                        sw.WriteLine(DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " + str_ex);
                    }
                }
            }
        }
        private void Write_Session_Log_Client(Session_Packet_Client_Training Session_Packet, Socket Socket_Client_Training)//Sever沒收到正確回報Client，於Client端寫Session Info檔案
        {
            try
            {
                lock (_sesion_log_client_Lock)
                {
                    if (!Directory.Exists(GetCurrentFilePath(@"Client\Session Log")))
                    {
                        DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Client\Session Log"));
                    }
                    string file = GetCurrentFilePath(@"Client\Session Log\Packet_Lost_Session_Log_" + DateTime.Now.ToString("yyyyMM") + ".csv");
                    string first_line_in_file = "Record Time, Transmit Time, Client_id, RemoteEndPoint, Info, ";
                    if (!File.Exists(file))
                    {
                        using (StreamWriter sw = File.CreateText(file))
                        {
                            sw.WriteLine(first_line_in_file);
                            sw.WriteLine("@" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         "@" + Session_Packet.datetime_transmit.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         Session_Packet.client_id2.ToString() + ", " +
                                         Socket_Client_Training.RemoteEndPoint + ", " +
                                         Session_Packet.str_2send
                                        );
                        }
                    }
                    else if (File.Exists(file))
                    {
                        using (StreamWriter sw = File.AppendText(file))
                        {
                            sw.WriteLine("@" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         "@" + Session_Packet.datetime_transmit.ToString("yyyy-MM-dd HH:mm:ss") + ", " +
                                         Session_Packet.client_id2.ToString() + ", " +
                                         Socket_Client_Training.RemoteEndPoint + ", " +
                                         Session_Packet.str_2send
                                        );
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Client("Write_Session_Log_Client " + ex.ToString());
            }
            finally
            {
            }
        }
        private void Write_Session_Binary_Client(Session_Packet_Client_Training Session_Packet, Socket Socket_Client_Training)//Sever沒收到正確回報Client，於Client端寫Session Binary檔案
        {
            try
            {
                lock (_sesion_binary_client_Lock)
                {
                    if (!Directory.Exists(GetCurrentFilePath(@"Client\Session Binary")))
                    {
                        DirectoryInfo di = Directory.CreateDirectory(GetCurrentFilePath(@"Client\Session Binary"));
                    }
                    string file = GetCurrentFilePath(@"Client\Session Binary\Packet_Lost_Client" + Session_Packet.client_id2 + @"_Binary_" + Session_Packet.datetime_transmit.ToString("yyyyMMddhhmmss") + ".bin");
                    File.WriteAllBytes(file, Session_Packet.body_binary);
                }
            }
            catch (Exception ex)
            {
                Write_Exception_Log_Client("Write_Session_Binary_Client " + ex.ToString());
            }
            finally
            {
            }
        }
    }
}