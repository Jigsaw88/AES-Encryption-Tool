using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace TextEncrypt
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        public static byte[] GenerateSalt(int saltSizeInBytes)
        {
            byte[] salt = new byte[saltSizeInBytes];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }
            return salt;
        }

        public static byte[] ConverteTextToSalt(string saltString)
        {
            saltString = saltString.Replace(" ", "").Replace("-", "");
            if (saltString.StartsWith("0x"))
            {
                saltString = saltString.Substring(2);
            }
            if (byte.TryParse(saltString, System.Globalization.NumberStyles.HexNumber, null, out byte singleByte))
            {
                return new byte[] { singleByte };
            }

            if (saltString.Length % 2 != 0)
            {
                throw new ArgumentException("Invalid salt format.");
            }

            byte[] saltBytes = new byte[saltString.Length / 2];
            for (int i = 0; i < saltBytes.Length; i++)
            {
                string hexByte = saltString.Substring(i * 2, 2);
                if (!byte.TryParse(hexByte, System.Globalization.NumberStyles.HexNumber, null, out saltBytes[i]))
                {
                    throw new ArgumentException($"Invalid salt format at position {i * 2}: {hexByte}");
                }
            }

            return saltBytes;
        }

        public string Encrypt(string input)
        {
            string EncryptionKey = siticoneMaterialTextBox2.Text.Replace(" ", "");
            byte[] clearBytes = Encoding.Unicode.GetBytes(input);
            byte[] salt;
            if (siticoneCheckBox2.Checked)
            {
                salt = GenerateSalt(16);
            }
            else
            {
                salt = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };
            }
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateEncryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(clearBytes, 0, clearBytes.Length);
                        cs.Close();
                    }
                    input = Convert.ToBase64String(ms.ToArray());
                }
            }
            if (siticoneCheckBox2.Checked)
            {
                string saltString = BitConverter.ToString(salt).Replace("-", "");
                return input + "\n   Salt: " + saltString;
            }
            else
            {
                return input;
            }
                
        }

        public string Decrypt(string input)
        {
            string EncryptionKey = siticoneMaterialTextBox2.Text.Replace(" ", "");
            input = input.Replace(" ", "+");
            byte[] cipherBytes = Convert.FromBase64String(input);
            byte[] salt;
            if (siticoneMaterialTextBox4.Text.Length > 0)
            {
                salt = ConverteTextToSalt(siticoneMaterialTextBox4.Text);
            }
            else
            {
                salt = new byte[] { 0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76 };
            }
            using (Aes encryptor = Aes.Create())
            {
                Rfc2898DeriveBytes pdb = new Rfc2898DeriveBytes(EncryptionKey, salt);
                encryptor.Key = pdb.GetBytes(32);
                encryptor.IV = pdb.GetBytes(16);
                using (MemoryStream ms = new MemoryStream())
                {
                    using (CryptoStream cs = new CryptoStream(ms, encryptor.CreateDecryptor(), CryptoStreamMode.Write))
                    {
                        cs.Write(cipherBytes, 0, cipherBytes.Length);
                        cs.Close();
                    }
                    input = Encoding.Unicode.GetString(ms.ToArray());
                }
            }
            return input;
        }

        private void siticoneButton1_Click(object sender, EventArgs e)
        {
            if (siticoneMaterialTextBox2.Text.Length == 0)
            {
                MessageBox.Show("Please provide a valid key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                siticoneMaterialTextBox3.Text = Encrypt(siticoneMaterialTextBox1.Text);
                if (siticoneCheckBox1.Checked)
                {
                    Clipboard.SetText(siticoneMaterialTextBox3.Text);
                }
            }
            
        }

        private void siticoneButton2_Click(object sender, EventArgs e)
        {
            if (siticoneMaterialTextBox2.Text.Length == 0)
            {
                MessageBox.Show("Please provide a valid key.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
            else
            {
                siticoneMaterialTextBox3.Text = Decrypt(siticoneMaterialTextBox1.Text);
                if (siticoneCheckBox1.Checked)
                {
                    Clipboard.SetText(siticoneMaterialTextBox3.Text);
                }
            }
        }
    }
}
