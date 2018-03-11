using System;
using System.Numerics;
using System.Security.Cryptography;
using System.Collections.Generic;

namespace MyRSA
{
    /// <summary>
    /// Простая реализация RSA.
    /// </summary>
    class SimpleRSA
    {
        private BigInteger p = 0, q = 0, e = 0, n = 0, gcd = 0, x = 0, y = 0;

        private Dictionary<string, BigInteger> publicKey = new Dictionary<string, BigInteger>();
        private Dictionary<string, BigInteger> privateKey = new Dictionary<string, BigInteger>();

        /// <summary>
        /// Конструктор класса SimpleRSA.
        /// </summary>
        /// <param name="size">Размер p и q в битах.</param>
        public SimpleRSA(uint size = 32)
        {
            /* Генерация p и q */
            do
            {
                p = GetRandomBigInteger(size);

            } while (!Miller(p, BigInteger.Log(p, 2), size)); // Повторять, пока p не простое

            do
            {
                do
                {
                    q = GetRandomBigInteger(size);

                } while (!Miller(q, BigInteger.Log(q, 2), size)); // Повторять, пока q не простое
            } while (p == q); // Начать заного, если p == q

            /* Генерация e через числа Ферма */
            BigInteger EulerFunc = EulerTotientFunction(p, q);
            BigInteger ePower = 0;

            while (FermatNumber(ePower + 1) < EulerFunc)
            {
                ePower++;
            }

            e = FermatNumber(ePower);

            /* Генерация n */
            n = p * q;

            /* Генерация d */
            Gcdext(e, EulerFunc, ref gcd, ref x, ref y);

            x = (x % EulerFunc + EulerFunc) % EulerFunc; // d
            
            /*Генерация закрытого ключа */
            privateKey["d"] = x;
            privateKey["n"] = n;

            /* Генерация открытого ключа */
            publicKey["e"] = e;
            publicKey["n"] = n;

        }

        /// <summary>
        /// Вычисляет подпись сообщения message.
        /// </summary>
        /// <param name="message">Сообщение, которое нужно подписать.</param>
        /// <returns>Массив, где [0] - сообщение, а [1] - подпись.</returns>
        public Dictionary<string, BigInteger> GetDigitalSignature(BigInteger message)
        {
            Dictionary<string, BigInteger> signedMessage = new Dictionary<string, BigInteger>();

            signedMessage["message"] = message;
            signedMessage["signature"] = ModPower(message, privateKey["d"], privateKey["n"]);

            return signedMessage;
        }

        /// <summary>
        /// Проверяет подпись сообщения.
        /// </summary>
        /// <param name="message">Проверяемое сообщение.</param>
        /// <param name="signature">Подпись сообщения.</param>
        /// <returns>true - подпись прошла проверку, false - не прошла.</returns>
        public bool CheckDigitalSignature(BigInteger message, BigInteger signature)
        {
            if (ModPower(signature, publicKey["e"], publicKey["n"]) == message)
                return true;

            return false;
        }

        /// <summary>
        /// Расширенный алгоритм Евклида. Находит такой НОД gcd, что gcd = a * x + b * y. (a > b)
        /// </summary>
        /// <param name="a">Первое число (открытая экспонента e).</param>
        /// <param name="b">Второе число (значние функции эйлера).</param>
        /// <param name="gcd">Наибольшой общий делитель.</param>
        /// <param name="x">В x попадет значение секретной экспоненты d.</param>
        /// <param name="y"></param>
        private void Gcdext(BigInteger a, BigInteger b, ref BigInteger gcd, ref BigInteger x, ref BigInteger y)
        {
            BigInteger s;

            // Если b равно 0, то НОД равен a
            if (b == 0)
            {
                gcd = a;
                x = 1;
                y = 0;

                return;
            }

            // Рекурсивно пересчитываем x и y
            Gcdext(b, a % b, ref gcd, ref x, ref y);

            // Пересчет x и y
            s = y;
            y = x - (a / b) * y;
            x = s;
        }

        /// <summary>
        /// Находит значение функции Эйлера.
        /// </summary>
        /// <param name="p">p в алгоритме RSA</param>
        /// <param name="q">q в алгоритме RSA</param>
        /// <returns>Значение функции Эйлера.</returns>
        private BigInteger EulerTotientFunction(BigInteger p, BigInteger q)
        {
            return (p - 1) * (q - 1);
        }

        /// <summary>
        /// Находит число ферма.
        /// </summary>
        /// <param name="power">Степень степени 2.</param>
        /// <returns>Число ферма</returns>
        private BigInteger FermatNumber(BigInteger power)
        {
            BigInteger Fermat = BigPow(2, BigPow(2, power)) + 1;

            return Fermat;
        }

        /// <summary>
        /// Возводит число в степень.
        /// </summary>
        /// <param name="number">Возводимое в степень число</param>
        /// <param name="power">Степень, в которую нужно возвести.</param>
        /// <returns>Число, возведенное в степень.</returns>
        private BigInteger BigPow(BigInteger number, BigInteger power)
        {
            if (power < 0)
                return 0;

            BigInteger result = 1;

            for (BigInteger i = 0; i < power; i++)
                result *= number;

            return result;

        }

        /// <summary>
        /// Получает простое случайное BigInteger число.
        /// </summary>
        /// <param name="size">Размер получаемоего числа в битах.</param>
        /// <returns>Простое случайное BigInteger число</returns>
        private BigInteger GetRandomBigInteger(long size)
        {
            // Получение случайного числа
            var rng = new RNGCryptoServiceProvider();
            byte[] bytes = new byte[size / 8];

            // Заполнить массив случайными битами
            rng.GetBytes(bytes);

            // Делаем Число положительным
            bytes[bytes.Length - 1] &= 0x7F;

            // Перевод массива в тип BigInteger
            BigInteger randomBigInt = new BigInteger(bytes);

            return randomBigInt;
        }

        /// <summary>
        /// Модульно умножает число number на mul по модулю mod.
        /// </summary>
        /// <param name="number">Умножаемое по модулю число.</param>
        /// <param name="mul">Число, на которое нужно умножить.</param>
        /// <param name="mod">Модуль, по которому нужно умножить.</param>
        /// <returns>умноженное по модулю число.</returns>
        private BigInteger ModMul(BigInteger number, BigInteger mul, BigInteger mod)
        {
            BigInteger result = 0, y = number % mod;

            while (mul > 0)
            {
                if (mul % 2 == 1)
                {
                    result = (result + y) % mod;
                }

                y = (y * 2) % mod;
                mul /= 2;
            }

            return x % mod;
        }

        /// <summary>
        /// Быстро возводит модульно number в степень power по модулю mod.
        /// </summary>
        /// <param name="number">Возводимое модульно в степень число.</param>
        /// <param name="power">Степень, в которую возводится число.</param>
        /// <param name="mod">Модуль по короторому возводимтся число.</param>
        /// <returns>Возведенноев степень по модулю число.</returns>
        private BigInteger ModPower(BigInteger number, BigInteger power, BigInteger mod)
        {
            BigInteger result = 1;
            BigInteger y = number;
            
            while (power > 0)
            {
                if (power % 2 == 1)
                    result = (result * y) % mod;    
                
                y = (y * y) % mod;
                power /=  2;
            }

            return result % mod;
        }


        /// <summary>
        /// Тест простоты Миллера-Рабина.
        /// </summary>
        /// <param name="number">Проверяемое число.</param>
        /// <param name="k">Число раундов.</param>
        /// <param name="size">Размер проверяемого числа.</param>
        /// <returns></returns>
        private bool Miller(BigInteger number, double k, uint size)
        {
            //  number должен быть больше 2 и не должен быть четным
            if (number < 3 || number % 2 == 0)
            {
                return false;
            }

            // Нахождение s в (2 ^ s) * t
            BigInteger s = number - 1;
            
            while (s % 2 == 0)
            {
                s /= 2;
            }

            // Повторяем k раудов
            for (int i = 0; i < k; i++)
            {
                // Берем случайное число в отрезке [2, number - 2]
                BigInteger a = GetRandomBigInteger(size) % (number - 1) + 1;

                // Сохраняем s
                BigInteger temp = s;

                // Находит остаток от деления
                BigInteger mod = ModPower(a, temp, number);
                
                while (temp != number - 1 && mod != 1 && mod != number - 1)
                {
                    mod = ModMul(mod, mod, number);
                    temp *= 2;
                }

                
                if (mod != number - 1 && temp % 2 == 0)
                {
                    // Число составное
                    return false;
                }
            }

            // Число псевдопростое
            return true;
        }
    }
}
