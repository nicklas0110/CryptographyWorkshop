using System;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading.Tasks;

namespace crypto
{
    public class SocketWrapper : IDisposable
    {
        const int BUFFER_SIZE = 1_024;
        private Socket? _listener;
        private Socket? _socket;
        private EncryptionHelper _encryptionHelper;

        public SocketWrapper(string password)
        {
            // Initialize the encryption helper with a password
            _encryptionHelper = new EncryptionHelper(password);
        }

        public void Dispose()
        {
            _listener?.Dispose();
            _socket?.Dispose();
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
        }

        public async Task Send(string message)
        {
            var (cipherText, iv, tag, salt) = _encryptionHelper.Encrypt(message);

            // Send salt, IV, ciphertext, and tag with their lengths
            byte[] saltLength = BitConverter.GetBytes(salt.Length);
            byte[] ivLength = BitConverter.GetBytes(iv.Length);
            byte[] cipherTextLength = BitConverter.GetBytes(cipherText.Length);
            byte[] tagLength = BitConverter.GetBytes(tag.Length);

            await _socket!.SendAsync(saltLength.Concat(salt)
                                               .Concat(ivLength).Concat(iv)
                                               .Concat(cipherTextLength).Concat(cipherText)
                                               .Concat(tagLength).Concat(tag)
                                               .ToArray(), SocketFlags.None);

            Console.WriteLine($"Socket sent encrypted message.");
        }

        public async Task<string> Receive(string password)
        {
            var lengthBuffer = new byte[4];

            // Read salt length and salt
            await _socket!.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int saltLength = BitConverter.ToInt32(lengthBuffer, 0);
            var salt = new byte[saltLength];
            await _socket.ReceiveAsync(salt, SocketFlags.None);

            // Read IV length and IV
            await _socket.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int ivLength = BitConverter.ToInt32(lengthBuffer, 0);
            var iv = new byte[ivLength];
            await _socket.ReceiveAsync(iv, SocketFlags.None);

            // Read ciphertext length and ciphertext
            await _socket.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int cipherTextLength = BitConverter.ToInt32(lengthBuffer, 0);
            var cipherText = new byte[cipherTextLength];
            await _socket.ReceiveAsync(cipherText, SocketFlags.None);

            // Read tag length and tag
            await _socket.ReceiveAsync(lengthBuffer, SocketFlags.None);
            int tagLength = BitConverter.ToInt32(lengthBuffer, 0);
            var tag = new byte[tagLength];
            await _socket.ReceiveAsync(tag, SocketFlags.None);

            // Decrypt message
            var decryptedMessage = _encryptionHelper.Decrypt(cipherText, iv, tag, salt, password);
            Console.WriteLine("Message received with unique values:");
            Console.WriteLine($"IV: {BitConverter.ToString(iv)}");
            Console.WriteLine($"Tag: {BitConverter.ToString(tag)}");
            Console.WriteLine($"Salt: {BitConverter.ToString(salt)}");
            Console.WriteLine($"Password: {password}");
            Console.WriteLine($"Socket received decrypted message: \"{decryptedMessage}\"");
            return decryptedMessage;
        }
    }
}
