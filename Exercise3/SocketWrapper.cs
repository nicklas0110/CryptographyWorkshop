using System;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace crypto
{
    public class SocketWrapper : IDisposable
    {
        const int BUFFER_SIZE = 1_024;
        private Socket? _listener;
        private Socket? _socket;
        private ECDiffieHellman _ecdh; // Cross-platform ECDH instance
        private byte[] _publicKey; // Public key to send
        private byte[] _sharedSecret; // Shared secret derived from the key exchange
        private EncryptionHelper? _encryptionHelper;

        public SocketWrapper()
        {
            // Initialize cross-platform ECDH and generate the public-private key pair
            _ecdh = ECDiffieHellman.Create();
            _publicKey = _ecdh.ExportSubjectPublicKeyInfo(); // Export public key using SubjectPublicKeyInfo format
        }

        public void Dispose()
        {
            _listener?.Dispose();
            _socket?.Dispose();
            _ecdh?.Dispose();
        }

        public async Task Connect(IPEndPoint ipEndPoint)
        {
            _socket = new Socket(
                ipEndPoint.AddressFamily,
                SocketType.Stream,
                ProtocolType.Tcp
            );

            Console.WriteLine("Connecting...");
            await _socket.ConnectAsync(ipEndPoint);

            // Send our public key to the server
            await _socket.SendAsync(_publicKey, SocketFlags.None);

            // Receive the server's public key
            var serverPublicKey = new byte[BUFFER_SIZE];
            int receivedBytes = await _socket.ReceiveAsync(serverPublicKey, SocketFlags.None);

            // Import the server's public key from the received byte array
            var serverECDHPublicKey = ECDiffieHellman.Create();
            serverECDHPublicKey.ImportSubjectPublicKeyInfo(serverPublicKey.AsSpan(0, receivedBytes), out _);

            // Generate shared secret from the server's public key
            _sharedSecret = _ecdh.DeriveKeyMaterial(serverECDHPublicKey.PublicKey);

            // Initialize the encryption helper with the shared secret
            _encryptionHelper = new EncryptionHelper(_sharedSecret);

            Console.WriteLine("Shared secret derived.");
        }

        public void Disconnect()
        {
            _socket?.Shutdown(SocketShutdown.Both);
        }

        public async Task Listen(IPEndPoint ipEndPoint)
        {
            _listener = new Socket(ipEndPoint.AddressFamily, SocketType.Stream, ProtocolType.Tcp);

            _listener.Bind(ipEndPoint);
            _listener.Listen(100);

            Console.WriteLine("Listening...");

            _socket = await _listener.AcceptAsync();

            // Receive client's public key
            var clientPublicKey = new byte[BUFFER_SIZE];
            int receivedBytes = await _socket.ReceiveAsync(clientPublicKey, SocketFlags.None);

            // Send our public key to the client
            await _socket.SendAsync(_publicKey, SocketFlags.None);

            // Import the client's public key from the received byte array
            var clientECDHPublicKey = ECDiffieHellman.Create();
            clientECDHPublicKey.ImportSubjectPublicKeyInfo(clientPublicKey.AsSpan(0, receivedBytes), out _);

            // Generate shared secret from the client's public key
            _sharedSecret = _ecdh.DeriveKeyMaterial(clientECDHPublicKey.PublicKey);

            // Initialize the encryption helper with the shared secret
            _encryptionHelper = new EncryptionHelper(_sharedSecret);

            Console.WriteLine("Shared secret derived.");
        }

        public async Task Send(string message)
        {
            if (_encryptionHelper == null)
                throw new InvalidOperationException("Encryption helper not initialized.");

            var (cipherText, iv, tag) = _encryptionHelper.Encrypt(message);

            byte[] ivLength = BitConverter.GetBytes(iv.Length);
            byte[] cipherTextLength = BitConverter.GetBytes(cipherText.Length);
            byte[] tagLength = BitConverter.GetBytes(tag.Length);

            await _socket!.SendAsync(ivLength.Concat(iv)
                                             .Concat(cipherTextLength).Concat(cipherText)
                                             .Concat(tagLength).Concat(tag)
                                             .ToArray(), SocketFlags.None);

            Console.WriteLine($"Socket sent encrypted message.");
        }

        public async Task<string> Receive()
        {
            if (_encryptionHelper == null)
                throw new InvalidOperationException("Encryption helper not initialized.");

            var lengthBuffer = new byte[4];

            // Receive IV
            await _socket!.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int ivLength = BitConverter.ToInt32(lengthBuffer, 0);
            var iv = new byte[ivLength];
            await _socket.ReceiveAsync(iv, SocketFlags.None);

            // Receive ciphertext
            await _socket.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int cipherTextLength = BitConverter.ToInt32(lengthBuffer, 0);
            var cipherText = new byte[cipherTextLength];
            await _socket.ReceiveAsync(cipherText, SocketFlags.None);

            // Receive tag
            await _socket.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int tagLength = BitConverter.ToInt32(lengthBuffer, 0);
            var tag = new byte[tagLength];
            await _socket.ReceiveAsync(tag, SocketFlags.None);

            // Decrypt message
            var decryptedMessage = _encryptionHelper.Decrypt(cipherText, iv, tag);
            Console.WriteLine("Message received with unique values:");
            Console.WriteLine($"IV: {BitConverter.ToString(iv)}");
            Console.WriteLine($"Tag: {BitConverter.ToString(tag)}");
            Console.WriteLine($"sharedSecret: {BitConverter.ToString(_sharedSecret)}");
            Console.WriteLine($"Socket received decrypted message: \"{decryptedMessage}\"");
            return decryptedMessage;
        }
    }
}
