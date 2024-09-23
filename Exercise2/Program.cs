using System;
using System.Net;
using System.Threading.Tasks;
using crypto;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Choose mode: (1) Server, (2) Client");
        string? choice = Console.ReadLine();

        // Ask for password
        Console.Write("Enter password for key derivation: ");
        string password = Console.ReadLine();

        if (choice == "1")
        {
            await RunServer(password); // Pass the password to the server
        }
        else if (choice == "2")
        {
            await RunClient(password); // Pass the password to the client
        }
        else
        {
            Console.WriteLine("Invalid choice. Exiting.");
        }
    }

    static async Task RunServer(string password)
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 8080); // Using localhost and port 8080

        using (var serverSocket = new SocketWrapper(password)) // Pass password to derive the key
        {
            await serverSocket.Listen(ipEndPoint); // Start listening for connections
            Console.WriteLine("Client connected.");

            while (true)
            {
                try
                {
                    string message = await serverSocket.Receive(password); // Try to receive and decrypt the message

                    if (message == "exit")
                    {
                        break;
                    }
                }
                catch (System.Security.Cryptography.AuthenticationTagMismatchException)
                {
                    // This error occurs when the decryption process fails (e.g., wrong password or corrupted data)
                    Console.WriteLine("Error: Decryption failed, likely due to wrong password. Disconnecting you...");
                    break; // Exit loop if decryption fails
                }
                catch (Exception ex)
                {
                    // Catch any other errors
                    Console.WriteLine($"Error: {ex.Message}");
                    break;
                }
            }
        }
    }

    static async Task RunClient(string password)
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 8080); // Using localhost and port 8080

        using (var clientSocket = new SocketWrapper(password)) // Pass password to derive the key
        {
            await clientSocket.Connect(ipEndPoint); // Connect to the server
            Console.WriteLine("Connected to server.");

            while (true)
            {
                Console.Write("Enter message to send (type 'exit' to quit): ");
                string message = Console.ReadLine();

                await clientSocket.Send(message); // Send encrypted message to server

                if (message == "exit")
                {
                    break;
                }
            }

            clientSocket.Disconnect(); // Disconnect from the server
        }
    }
}
