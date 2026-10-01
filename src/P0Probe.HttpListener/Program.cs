using System;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Threading;

/// <summary>
/// P0-b1：验证 .NET Framework 4.8 的 HttpListener 能以非管理员身份绑定 127.0.0.1 随机端口并回显请求。
/// 随机端口用 TcpListener(loopback, 0) 预留后转交 HttpListener（HttpListener 不暴露实际端口）。
/// </summary>
internal static class Program
{
    private static void Main()
    {
        int port;
        var t = new TcpListener(IPAddress.Loopback, 0);
        try
        {
            t.Start();
            port = ((IPEndPoint)t.LocalEndpoint).Port;
        }
        finally
        {
            t.Stop();
        }
        Console.WriteLine("Reserved random port: " + port);

        var listener = new HttpListener();
        listener.Prefixes.Add("http://127.0.0.1:" + port + "/");
        try
        {
            listener.Start();
        }
        catch (Exception ex)
        {
            Console.WriteLine("P0-B1 RESULT: FAIL - " + ex.GetType().Name + ": " + ex.Message);
            Environment.Exit(1);
        }
        Console.WriteLine("HttpListener started on 127.0.0.1:" + port);

        var done = new ManualResetEvent(false);
        listener.BeginGetContext(ar =>
        {
            var ctx = listener.EndGetContext(ar);
            string host = ctx.Request.Headers["Host"];
            string body = "{\"echo\":\"ok\",\"host\":\"" + host + "\",\"port\":" + port + "}";
            var bytes = Encoding.UTF8.GetBytes(body);
            ctx.Response.ContentType = "application/json";
            ctx.Response.OutputStream.Write(bytes, 0, bytes.Length);
            ctx.Response.Close();
            done.Set();
        }, null);

        string resp;
        using (var wc = new WebClient())
        {
            wc.Headers["Host"] = "127.0.0.1:" + port;
            resp = wc.DownloadString("http://127.0.0.1:" + port + "/");
        }
        if (!done.WaitOne(3000))
        {
            Console.WriteLine("P0-B1 RESULT: FAIL - request handler timeout");
            Environment.Exit(1);
        }
        Console.WriteLine("Echo response: " + resp);
        listener.Stop();
        Console.WriteLine("P0-B1 RESULT: OK - non-admin HttpListener bind + serve on 127.0.0.1 random port");
    }
}
