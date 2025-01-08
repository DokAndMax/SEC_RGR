namespace Client;

internal class Program
{
    private static void Main(string[] args)
    {
        var client = new Client();
        client.Connect("127.0.0.1", 5000);
        client.StartCommunication();
    }
}