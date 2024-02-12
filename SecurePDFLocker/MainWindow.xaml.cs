using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.Security.Cryptography;
using System.IO;

namespace SecurePDFLocker
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        // Event handler for when the "Enter Key" TextBox gains focus
        private void KeyTextBox_GotFocus(object sender, RoutedEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            if (openFileDialog.ShowDialog() == true)
            {
                // Set the selected file path to the "Enter Key" TextBox
                EncryptFileTextBox.Text = openFileDialog.FileName;
            }
            else if (openFileDialog.ShowDialog() == true)
            {
                DecryptFileTextBox.Text = openFileDialog.FileName;
            }

        }

        private void KeyTextBox_TextChanged(object sender, TextChangedEventArgs e)
        {

        }

        public byte[] DeriveKeyFromPassword(string password, byte[] salt, int keySize = 32, int iterations = 10000)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))// create a key from the password
            {
                return deriveBytes.GetBytes(keySize);
            }
        }

        public byte[] GenerateSalt(int size = 16) // code generates a random salt of a specified length using a cryptographic random number generator and returns it as an array of bytes. 
        {
            using (var rng = new RNGCryptoServiceProvider())
            {
                var salt = new byte[size];
                rng.GetBytes(salt);
                return salt;
            }
        }


        public byte[] Encrypt(byte[] data, byte[] key, byte[] iv)
        {
            using (var aesAlg = Aes.Create()) //Object from
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                using (var encryptor = aesAlg.CreateEncryptor())
                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        csEncrypt.Write(data, 0, data.Length);
                    }
                    return msEncrypt.ToArray();
                }
            }
        }


        public byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] iv)
        {
            using (var aesAlg = Aes.Create())
            {
                aesAlg.Key = key;
                aesAlg.IV = iv;

                using (var decryptor = aesAlg.CreateDecryptor())
                using (var msDecrypt = new MemoryStream(encryptedData))
                using (var csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                using (var decryptedData = new MemoryStream())
                {
                    csDecrypt.CopyTo(decryptedData);
                    return decryptedData.ToArray();
                }
            }
        }

        // Event handler for Encrypt button click
        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string password = KeyTextBox.Text; // Assuming KeyTextBox contains the password
            byte[] salt = GenerateSalt(); // Generate salt
            byte[] key = DeriveKeyFromPassword(password, salt); // Derive key from password and salt

            byte[] dataToEncrypt = Encoding.UTF8.GetBytes("C:\\Users\\HUM014\\Downloads\\DUC Work\\TEST.pdf"); // Replace this with your actual data

            // Encrypt data
            byte[] encryptedData = Encrypt(dataToEncrypt, key, key); // Using the key as IV for simplicity

            // Save or use the encrypted data as needed
        }


        // Event handler for Decrypt button click
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string password = KeyTextBox.Text; // Assuming KeyTextBox contains the password
            byte[] salt = GenerateSalt(); // Generate salt
            byte[] key = DeriveKeyFromPassword(password, salt); // Derive key from password and salt

            byte[] encryptedData = File.ReadAllBytes("path_to_encrypted_file"); // Read encrypted data from file

            // Decrypt data
            byte[] decryptedData = Decrypt(encryptedData, key, key); // Using the key as IV for simplicity

            // Process or display the decrypted data as needed
        }

        private void KeyTextBox_TextChanged_1(object sender, TextChangedEventArgs e)
        {

        }

        // Other methods like DeriveKeyFromPassword, GenerateSalt, Encrypt, Decrypt go here...

    }

}




