using System;
using System.Numerics;
using System.Security.Cryptography;

namespace MyRSA
{ 
    /// <summary>
    /// Простая реализация RSA.
    /// </summary>
    class SimpleRSA
    {
        /// <summary>
        /// Конструктор класса SimpleRSA.
        /// </summary>
        /// <param name="size">Размер p и q в битах.</param>
        public SimpleRSA(int size = 1024)
        {

        }

        /// <summary>
        /// Получает простое случайное BigInteger число.
        /// </summary>
        /// <param name="size">Размер получаемоего числа в битах.</param>
        /// <returns>Простое случайное BigInteger число</returns>
        public BigInteger GetRandomBigInteger(int size =  1024)
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
        /// Проверка числа на простоту.
        /// </summary>
        /// <param name="number">проверяемое число.</param>
        /// <returns>true - число простое, иначе - false/returns>
        public bool CheckPrime(BigInteger number) {
            /* 
             * Если number делиться без остатка на любое число от 2 до number / 2 - 1,
             * то оно не простое.
             */
            for(BigInteger d = 2; d < number / 2 + 1; d++) {
                // Число не простое
                if (number % d == 0)
                    return false;
            }

            // У числа нет дилителя от 2 до number / 2 - 1, т. е. оно простое.
            return true;
        }
    }
}
