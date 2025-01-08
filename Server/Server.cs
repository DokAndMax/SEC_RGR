using Helpers;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace Server;
public class Server(int port)
{
    private readonly TcpListener _listener = new(IPAddress.Any, port);
    private NetworkStream? _stream;
    private readonly RSAHelper _rsaHelper = new();
    private byte[]? _sessionKey;
    private byte[]? _clientRandom;
    private byte[]? _serverRandom;

    public void Start()
    {
        _listener.Start();
        Console.WriteLine("Server started.");
        TcpClient client = _listener.AcceptTcpClient();
        _stream = client.GetStream();

        // 1. Ініціювання клієнтом
        _clientRandom = ReceiveClientRandom(_stream);

        // 2. Відповідь сервера
        _serverRandom = GenerateRandomBytes(32);
        SendServerRandom(_stream, _serverRandom);

        string publicKey = _rsaHelper.GetPublicKey();
        SendPublicKey(_stream, publicKey);

        // 4. Обмін секретними рядками
        byte[] encryptedPremaster = ReceiveEncryptedPremaster(_stream);
        _sessionKey = _rsaHelper.DecryptData(encryptedPremaster); // Premaster secret
        Console.WriteLine("Premaster secret received.");

        // 5. Генерація ключів сеансу
        _sessionKey = DeriveSessionKey(_sessionKey, _clientRandom, _serverRandom);
        Console.WriteLine("Session key derived.");

        // 6. Готовність клієнта та сервера
        byte[]? encryptedMessage = ReceiveEncryptedMessage(_stream);
        string decryptedMessage = DecryptMessage(encryptedMessage!, _sessionKey);
        Console.WriteLine("Message received: " + decryptedMessage);
        if (decryptedMessage != "Ready")
        {
            throw new Exception();
        }
        SendMessage(_stream, "Ready", _sessionKey);
        
        HandleCommunication(_stream);
    }

    private static byte[] ReceiveClientRandom(NetworkStream stream)
    {
        var buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);

        string clientRandom = Convert.ToHexString(buffer, 0, bytesRead);
        Console.WriteLine("Client random: " + clientRandom);

        return buffer.Take(bytesRead).ToArray();
    }

    private static void SendServerRandom(NetworkStream stream, byte[] serverRandom)
    {
        stream.Write(serverRandom, 0, serverRandom.Length);
    }

    private static void SendPublicKey(NetworkStream stream, string publicKey)
    {
        byte[] publicKeyBytes = Encoding.UTF8.GetBytes(publicKey);
        stream.Write(publicKeyBytes, 0, publicKeyBytes.Length);
    }

    private static byte[] ReceiveEncryptedPremaster(NetworkStream stream)
    {
        var buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        return buffer.Take(bytesRead).ToArray();
    }

    private void HandleCommunication(NetworkStream stream)
    {
        if (_stream is null || !_stream.Socket.Connected || _sessionKey is null)
        {
            Console.WriteLine("Client is not connected!");
            return;
        }

        try
        {
            while (true)
            {
                byte[]? encryptedMessage = ReceiveEncryptedMessage(stream);

                if (encryptedMessage is null) break;

                string decryptedMessage = DecryptMessage(encryptedMessage, _sessionKey);
                
                Console.WriteLine("Message received: " + decryptedMessage);

                string response = "Acknowledged: " + decryptedMessage;
                SendMessage(stream, response, _sessionKey);
            }
        }
        catch (IOException e)
        {
            Console.WriteLine(e.Message);
        }
    }

    private static void SendMessage(NetworkStream stream, string message, byte[] sessionKey)
    {
        byte[] encryptedMessage = AESHelper.EncryptWithAES(Encoding.UTF8.GetBytes(message), sessionKey);
        stream.Write(encryptedMessage, 0, encryptedMessage.Length);
        Console.WriteLine("Message sent: " + message);
    }

    private static byte[]? ReceiveEncryptedMessage(NetworkStream stream)
    {
        var buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);

        return bytesRead == 0 ? null : buffer.Take(bytesRead).ToArray();
    }

    private static string DecryptMessage(byte[] encryptedMessage, byte[] sessionKey)
    {
        byte[] decryptedMessage = AESHelper.DecryptWithAES(encryptedMessage, sessionKey);

        string message = Encoding.UTF8.GetString(decryptedMessage);

        return message;
    }

    private static byte[] GenerateRandomBytes(int size)
    {
        var randomBytes = new byte[size];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomBytes);
        return randomBytes;
    }

    private static byte[] DeriveSessionKey(byte[] premaster, byte[] clientRandom, byte[] serverRandom)
    {
        using var hmac = new HMACSHA256(premaster);
        byte[] combined = clientRandom.Concat(serverRandom).ToArray();
        return hmac.ComputeHash(combined);
    }
}