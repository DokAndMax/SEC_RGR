using Helpers;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

namespace Client;

public class Client
{
    private readonly TcpClient _tcpClient = new();
    private NetworkStream? _stream;
    private readonly RSAHelper _rsaHelper = new();
    private byte[]? _sessionKey;
    private byte[]? _clientRandom;
    private byte[]? _serverRandom;

    public void Connect(string serverIp, int port)
    {
        _tcpClient.Connect(serverIp, port);
        _stream = _tcpClient.GetStream();

        // 1. Ініціювання клієнтом
        _clientRandom = GenerateRandomBytes(32);
        SendClientRandom(_stream, _clientRandom);

        // 2. Відповідь сервера
        _serverRandom = ReceiveServerRandom(_stream);

        string serverPublicKey = ReceivePublicKey(_stream);
        _sessionKey = GenerateRandomBytes(32); // Premaster secret

        // 4. Обмін секретними рядками
        SendPremasterSecret(_stream, _sessionKey, serverPublicKey);

        // 5. Генерація ключів сеансу
        _sessionKey = DeriveSessionKey(_sessionKey, _clientRandom, _serverRandom);
        Console.WriteLine("Session key derived.");

        // 6. Готовність клієнта та сервера:
        SendMessage(_stream, "Ready", _sessionKey);
        if (ReceiveMessage(_stream, _sessionKey) != "Ready")
        {
            throw new Exception();
        }
    }

    private static void SendClientRandom(NetworkStream stream, byte[] clientRandom)
    {
        stream.Write(clientRandom, 0, clientRandom.Length);
    }

    private static byte[] ReceiveServerRandom(NetworkStream stream)
    {
        var buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);

        string serverRandom = Convert.ToHexString(buffer, 0, bytesRead);
        Console.WriteLine("Server random: " + serverRandom);

        return buffer.Take(bytesRead).ToArray();
    }

    private void SendPremasterSecret(NetworkStream stream, byte[] premasterSecret, string serverPublicKey)
    {
        byte[] encryptedSecret = _rsaHelper.EncryptData(premasterSecret, serverPublicKey);
        stream.Write(encryptedSecret, 0, encryptedSecret.Length);

        Console.WriteLine("Encrypted premaster secret sent.");
    }

    public void StartCommunication()
    {
        if (_stream is null || !_stream.Socket.Connected || _sessionKey is null)
        {
            Console.WriteLine("Client is not connected!");
            return;
        }

        Console.WriteLine("Start chatting! Type your messages below. Type 'exit' to end the chat.");

        try
        {
            while (true)
            {
                Console.Write("You: ");
                string? message = Console.ReadLine();

                if (message is null) continue;
                if (message.Equals("exit", StringComparison.CurrentCultureIgnoreCase)) break;

                SendMessage(_stream, message, _sessionKey);
                ReceiveMessage(_stream, _sessionKey);
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

    private static string ReceiveMessage(NetworkStream stream, byte[] sessionKey)
    {
        var buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        byte[] decryptedMessage = AESHelper.DecryptWithAES(buffer.Take(bytesRead).ToArray(), sessionKey);

        string message = Encoding.UTF8.GetString(decryptedMessage);
        Console.WriteLine("Message received: " + message);

        return message;
    }

    private static string ReceivePublicKey(NetworkStream stream)
    {
        var buffer = new byte[4096];
        int bytesRead = stream.Read(buffer, 0, buffer.Length);
        return Encoding.UTF8.GetString(buffer, 0, bytesRead);
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