using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Numerics;
using System.Security.Cryptography;


namespace MyRSA
{
    class Program
    {
        /// <summary>
        /// Выводит сообщение и подпись этого сообщения.
        /// </summary>
        /// <param name="signedMessage">Подписанное сообщение.</param>
        public static void PrintSignedMessage(Dictionary<string, BigInteger> signedMessage)
        {
            Console.WriteLine("Подписываемое сообщение:\n" + signedMessage["message"] + "\n");
            Console.WriteLine("Подпись сообщения:\n" + signedMessage["signature"] + "\n");
        }

        /// <summary>
        /// Выводит результат проверки подписи сообщения.
        /// </summary>
        /// <param name="rsa">Объект SimpleRSA, содержажщий ключи.</param>
        /// <param name="signedMessage">Подписанное сообщение.</param>
        public static void PrintSigCheckResult(SimpleRSA rsa, Dictionary<string, BigInteger> signedMessage)
        {
            if (rsa.CheckDigitalSignature(signedMessage["message"], signedMessage["signature"]))
            {
                Console.WriteLine("Сообщение прошло проверку!\n");
            }
            else
            {
                Console.WriteLine("Сообщение не прошло проверку!\n");
            }
        }

        static void Main(string[] args)
        {
            uint size; // Размер p и q
            BigInteger message; // Подписываемое сообщение

            // Проверка корректности ввода.
            if (args.Length != 2 || !uint.TryParse(args[0], out size) || !BigInteger.TryParse(args[1], out message))
            {
                Console.WriteLine("Укажите размер p и q в битах и подписываемое сообщение (MyRSA.exe <bits> <message>).");
                Console.ReadKey();

                return;
            }

            if (size < 8)
            {
                Console.WriteLine("Размер p и q должен быть не меньше 8 бит!");
                return;
            }

            Console.WriteLine("Размер p и q: " + size + " бит.\n");

            // Генерируем ключи RSA
            SimpleRSA rsa = new SimpleRSA(size);

            // Получаем подписанное сообщение
            Dictionary<string, BigInteger> signedMessage = rsa.GetDigitalSignature(message);
            PrintSignedMessage(signedMessage);

            // Проверка подписи сообщения
            Console.WriteLine("Проверка подписанного сообщения:");
            PrintSigCheckResult(rsa, signedMessage);
            Console.WriteLine();

            // Проверка подпси измененного сообщения
            Dictionary<string, BigInteger> brokenMessage = new Dictionary<string, BigInteger>(signedMessage);
            brokenMessage["message"] += 1;

            Console.WriteLine("Проверка подписанного сообщения после измения сообщения:");
            PrintSignedMessage(brokenMessage);
            PrintSigCheckResult(rsa, brokenMessage);
            Console.WriteLine();

            // Проверка подписи сообщения сподменой подписи
            Dictionary<string, BigInteger> brokenSignature = new Dictionary<string, BigInteger>(signedMessage);
            brokenSignature["signature"] += 1;

            Console.WriteLine("Проверка подписанного сообщения после изменения подписи:");
            PrintSignedMessage(brokenSignature);
            PrintSigCheckResult(rsa, brokenSignature);
            Console.WriteLine();

            Console.ReadKey();
        }
    }
}
