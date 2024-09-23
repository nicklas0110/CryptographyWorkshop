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

        public SocketWrapper()
        {
            // Initialize the encryption helper
            _encryptionHelper = new EncryptionHelper();
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
            var (cipherText, iv, tag) = _encryptionHelper.Encrypt(message);

            // Send IV, ciphertext, and tag with their lengths
            byte[] ivLength = BitConverter.GetBytes(iv.Length);
            byte[] cipherTextLength = BitConverter.GetBytes(cipherText.Length);
            byte[] tagLength = BitConverter.GetBytes(tag.Length);

            await _socket!.SendAsync(ivLength.Concat(iv).Concat(cipherTextLength).Concat(cipherText).Concat(tagLength).Concat(tag).ToArray(), SocketFlags.None);

            Console.WriteLine($"Socket sent encrypted message.");
        }

        public async Task<string> Receive()
        {
            var lengthBuffer = new byte[4];

            // Read IV length and IV
            await _socket!.ReceiveAsync(lengthBuffer, SocketFlags.None);
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
            var decryptedMessage = _encryptionHelper.Decrypt(cipherText, iv, tag);
            Console.WriteLine($"Socket received decrypted message: \"{decryptedMessage}\"");
            Console.WriteLine("Message received with unique values:");
            Console.WriteLine($"IV: {BitConverter.ToString(iv)}");
            Console.WriteLine($"Tag: {BitConverter.ToString(tag)}");
            return decryptedMessage;
        }
    }
}
