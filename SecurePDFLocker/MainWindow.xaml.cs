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
                KeyTextBox.Text = openFileDialog.FileName;
            }
        }

        private void Encrypt_Click(object sender, RoutedEventArgs e)
        {

        }

        private void Decrypt_Click(object sender, RoutedEventArgs e)
        {

        }
    }
}
