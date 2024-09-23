﻿using System;
using System.Net;
using System.Threading.Tasks;
using crypto;

class Program
{
    static async Task Main(string[] args)
    {
        Console.WriteLine("Choose mode: (1) Server, (2) Client");
        string? choice = Console.ReadLine();

        if (choice == "1")
        {
            await RunServer(); // Run as server
        }
        else if (choice == "2")
        {
            await RunClient(); // Run as client
        }
        else
        {
            Console.WriteLine("Invalid choice. Exiting.");
        }
    }

    static async Task RunServer()
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 8080); // Using localhost and port 8080

        using (var serverSocket = new SocketWrapper())
        {
            await serverSocket.Listen(ipEndPoint); // Start listening for connections
            Console.WriteLine("Client connected.");

            while (true)
            {
                string message = await serverSocket.Receive(); // Receive message from client
                Console.WriteLine($"Received: {message}");
                
                if (message == "exit")
                {
                    break;
                }
            }
        }
    }

    static async Task RunClient()
    {
        var ipEndPoint = new IPEndPoint(IPAddress.Loopback, 8080); // Using localhost and port 8080

        using (var clientSocket = new SocketWrapper())
        {
            await clientSocket.Connect(ipEndPoint); // Connect to the server
            Console.WriteLine("Connected to server.");

            while (true)
            {
                Console.Write("Enter message to send (type 'exit' to quit): ");
                string message = Console.ReadLine();

                await clientSocket.Send(message); // Send message to server

                if (message == "exit")
                {
                    break;
                }
            }

            clientSocket.Disconnect(); // Disconnect from the server
        }
    }
}
