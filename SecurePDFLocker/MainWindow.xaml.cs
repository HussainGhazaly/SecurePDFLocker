﻿using Microsoft.Win32;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Windows;
using System.Windows.Controls;

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
                // Check which TextBox has gained focus
                if (sender == EncryptFileTextBox)
                {
                    // Set the selected file path to the "Encrypt" TextBox
                    EncryptFileTextBox.Text = openFileDialog.FileName;
                }
                else if (sender == DecryptFileTextBox)
                {
                    // Set the selected file path to the "Decrypt" TextBox
                    DecryptFileTextBox.Text = openFileDialog.FileName;
                }
            }
        }

        private void KeyTextBox_TextChanged(object sender, TextChangedEventArgs e) //This method is an event handler for the TextChanged event of the KeyTextBox
        {

        }

        public byte[] DeriveKeyFromPassword(string password, byte[] salt, int keySize = 32, int iterations = 10000)
        {
            using (var deriveBytes = new Rfc2898DeriveBytes(password, salt, iterations))//This method generates a cryptographic key from a password and salt using the PBKDF2 algorithm (implemented by Rfc2898DeriveBytes). It returns the derived key as a byte array.
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
            using (var aesAlg = Aes.Create()) //this method encrypts a byte array (data) using the AES encryption algorithm
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


        public byte[] Decrypt(byte[] encryptedData, byte[] key, byte[] iv) // This method decrypts an encrypted byte array using the AES decryption algorithm
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

        //
        // This method handles the Click event of the EncryptButton control.
        // It performs file encryption using AES algorithm with a password.
        // The encrypted file is saved with a .enc extension.
        private void EncryptButton_Click(object sender, RoutedEventArgs e)
        {
            string password = KeyTextBox.Text; // Assuming KeyTextBox contains the password
            byte[] salt = GenerateSalt(); // Generate salt
            byte[] key = DeriveKeyFromPassword(password, salt); // Derive key from password and salt
            byte[] iv = GenerateSalt(16); // Generate initialization vector (IV)

            byte[] dataToEncrypt = File.ReadAllBytes(EncryptFileTextBox.Text); // Read data from file

            // Encrypt data
            byte[] encryptedData = Encrypt(dataToEncrypt, key, iv);

            // Concatenate salt with encrypted data
            byte[] saltedEncryptedData = salt.Concat(encryptedData).ToArray();

            // Save encrypted data (with salt) to a file
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Encrypted Files (*.enc)|*.enc|All files (*.*)|*.*";
            if (saveFileDialog.ShowDialog() == true)
            {
                File.WriteAllBytes(saveFileDialog.FileName, saltedEncryptedData);
                // Display a message box indicating the selected file path
                MessageBox.Show("File encrypted and saved to: " + saveFileDialog.FileName, "Encryption Completed", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }

        // 
        // This method handles the Click event of the DecryptButton control.
        // It performs file decryption using AES algorithm with a password.
        // The decrypted file is saved with a .txt extension.
        private void DecryptButton_Click(object sender, RoutedEventArgs e)
        {
            string password = KeyTextBox.Text; // Assuming KeyTextBox contains the password

            byte[] encryptedDataWithSalt = File.ReadAllBytes(DecryptFileTextBox.Text); // Read encrypted data from file

            // Extract salt from the first 16 bytes of the encrypted data
            byte[] salt = encryptedDataWithSalt.Take(16).ToArray();

            // Derive key using the extracted salt
            byte[] key = DeriveKeyFromPassword(password, salt);

            // Extract encrypted data (excluding salt)
            byte[] encryptedData = encryptedDataWithSalt.Skip(16).ToArray();

            // Decrypt data
            byte[] decryptedData = Decrypt(encryptedData, key, salt);

            // Prompt user to select a destination file path to save the decrypted data
            SaveFileDialog saveFileDialog = new SaveFileDialog();
            saveFileDialog.Filter = "Decrypted Files (*.txt)|*.txt|All files (*.*)|*.*";
            if (saveFileDialog.ShowDialog() == true)
            {
                // Save decrypted data to the selected file
                File.WriteAllBytes(saveFileDialog.FileName, decryptedData);

                // Display a message box indicating the selected file path
                MessageBox.Show("File decrypted and saved to: " + saveFileDialog.FileName, "Decryption Completed", MessageBoxButton.OK, MessageBoxImage.Information);
            }
        }


        private void KeyTextBox_TextChanged_1(object sender, TextChangedEventArgs e)
        {

        }

        // Other methods like DeriveKeyFromPassword, GenerateSalt, Encrypt, Decrypt go here...

    }

}




