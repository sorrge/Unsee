using BitMiracle.LibJpeg.Classic;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
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

namespace UnseeGUI
{
  /// <summary>
  /// Interaction logic for MainWindow.xaml
  /// </summary>
  public partial class MainWindow : Window
  {
    private static readonly RandomNumberGenerator Random = RandomNumberGenerator.Create();
    static readonly int SizeCheckOverhead = Crypto.AESThenHMAC.SaltBitSize / 8 + 2;

    enum ContentType { MessageOnly = 0, FileOnly = 1, MessageAndFile = 2 };

    Steganography.IContainer container = null;
    byte[] secret = null, revealedSecret = null;
    int secretSize;

    public MainWindow()
    {
      InitializeComponent();
      SecretSize = 0;
      ContainerName_TextChanged(null, null);
      SecretFileName_TextChanged(null, null);
    }

    private void ContainerName_TextChanged(object sender, TextChangedEventArgs e)
    {
      ContainerThumbnail.Source = null;
      container = null;

      if (ContainerName.Text == "")
        ContainerStatusLabel.Text = "No container file loaded";
      else
      {
        if (File.Exists(ContainerName.Text))
        {
          try
          {
            LoadContainer();
            var accessTime = File.GetLastAccessTimeUtc(ContainerName.Text);
            var src = new BitmapImage();
            src.BeginInit();
            src.StreamSource = new MemoryStream(File.ReadAllBytes(ContainerName.Text));
            src.EndInit();
            //src.UriSource = new Uri(System.IO.Path.GetFullPath(ContainerName.Text));
            ContainerThumbnail.Source = src;
            File.SetLastAccessTimeUtc(ContainerName.Text, accessTime);

            ContainerStatusLabel.Text = "File loaded, maximum secret size: " + container.Size + " bytes";
          }
          catch(IOException ex)
          {
            ContainerStatusLabel.Text = "File cannot be read: " + ex.Message;
          }
          catch (Exception ex)
          {
            ContainerStatusLabel.Text = "Error reading file: " + ex.Message;
          }
        }
        else
          ContainerStatusLabel.Text = "File does not exits";
      }

      UpdateButtons();
    }

    private void LoadContainer()
    {
      var accessTime = File.GetLastAccessTimeUtc(ContainerName.Text);
      using (FileStream containerFile = new FileStream(ContainerName.Text, FileMode.Open, FileAccess.Read))
        container = new Steganography.JPEGDCTContainer(containerFile, ContainerName.Text);
      File.SetLastAccessTimeUtc(ContainerName.Text, accessTime);
    }

    private void ContainerName_Drop(object sender, DragEventArgs e)
    {
      string[] droppedFiles = null;
      if (e.Data.GetDataPresent(DataFormats.FileDrop))
        droppedFiles = e.Data.GetData(DataFormats.FileDrop, true) as string[];

      if (null == droppedFiles || droppedFiles.Length == 0)
        return;
      
      (sender as TextBox).Text = droppedFiles[0];
    }

    private void ContainerName_PreviewDragOver(object sender, DragEventArgs e)
    {
      e.Effects = DragDropEffects.All;
      e.Handled = true;
    }

    private void ContainerFileBrowse_Click(object sender, RoutedEventArgs e)
    {
      var ofd = new Microsoft.Win32.OpenFileDialog() 
      {
        Filter = "JPEG Files (*.jpg, *.jpeg)|*.jpg;*.jpeg",
        DefaultExt = ".jpg",
        CheckFileExists = true
      };

      var result = ofd.ShowDialog();
      if (result == false)
        return;

      ContainerName.Text = ofd.FileName;
    }

    private void SecretMessageText_TextChanged(object sender, TextChangedEventArgs e)
    {
      UpdateSize();
    }

    void UpdateSize()
    {
      int payloadSize = Encoding.UTF8.GetByteCount(SecretMessageText.Text);
      if (secret != null)
        payloadSize += 9 + Encoding.UTF8.GetByteCount(System.IO.Path.GetFileName(SecretFileName.Text)) + secret.Length;
      else if (payloadSize != 0)
        ++payloadSize;

      SecretSize = payloadSize == 0 ? 0 : Crypto.AESThenHMAC.MessageSizeEstimation(payloadSize) + SizeCheckOverhead;
    }

    int SecretSize
    {
      set
      {
        if (value == 0)
          SecretSizeText.Content = "0 (erase mode)";
        else
          SecretSizeText.Content = value + " bytes";

        secretSize = value;
        UpdateButtons();
      }
      get { return secretSize; }
    }

    void UpdateButtons()
    {
      HideButton.IsEnabled = container != null && container.Size >= SecretSize;
      HideButton.ToolTip = container == null ? "Choose a container file first" : SecretSize == 0 ? "Erase all secret data in the container" :
        SecretSize > container.Size ? "The container is too small for the secret" : "Hide the secret in the container";

      RevealButton.IsEnabled = container != null && container.Size >= Crypto.AESThenHMAC.MessageSizeEstimation(1) + SizeCheckOverhead;
      RevealButton.ToolTip = container == null ? "Choose a container file first" :
        container.Size < Crypto.AESThenHMAC.MessageSizeEstimation(1) + SizeCheckOverhead ? "The container is too small to hold any secret" : "Reveal the secret";

      RevealedSecretFileSave.IsEnabled = revealedSecret != null;
    }

    private void HideButton_Click(object sender, RoutedEventArgs e)
    {
      if (!string.IsNullOrEmpty(SecretMessageText.Text) || secret != null)
      {
        try
        {
          container.SetAccessPassword(PasswordText.Text);

          byte[] salt, key;
          Crypto.AESThenHMAC.GenerateKeyFromPassword(PasswordText.Text, out salt, out key);
          for (int i = 0; i < salt.Length; ++i)
            container[i] = salt[i];

          var secretFileName = System.IO.Path.GetFileName(SecretFileName.Text);

          var message = new byte[1 + Encoding.UTF8.GetByteCount(SecretMessageText.Text) +
            (secret == null ? 0 : 8 + Encoding.UTF8.GetByteCount(secretFileName) + secret.Length)];

          message[0] = (byte)(string.IsNullOrEmpty(SecretMessageText.Text) ?
            ContentType.FileOnly : secret == null ? ContentType.MessageOnly : ContentType.MessageAndFile);

          int p = 1;
          if (secret != null)
          {
            var nameLength = BitConverter.GetBytes((uint)secretFileName.Length);
            Array.Copy(nameLength, 0, message, p, 4);
            p += 4;
            var nameBytes = Encoding.UTF8.GetBytes(secretFileName);
            Array.Copy(nameBytes, 0, message, p, nameBytes.Length);
            p += nameBytes.Length;
            var fileLength = BitConverter.GetBytes((uint)secret.Length);
            Array.Copy(fileLength, 0, message, p, 4);
            p += 4;
            Array.Copy(secret, 0, message, p, secret.Length);
            p += secret.Length;
          }

          var messageBytes = Encoding.UTF8.GetBytes(SecretMessageText.Text);
          Array.Copy(messageBytes, 0, message, p, messageBytes.Length);

          var payload = Crypto.AESThenHMAC.SimpleEncryptWithPassword(message, PasswordText.Text);


          for (int i = 0; i < payload.Length; ++i)
            container[i + salt.Length] = payload[i];

          for (int i = 0; i < payload.Length; ++i)
            if (container[i + salt.Length] != payload[i])
              throw new Exception("Secret verification failed");


          byte[] buffer = new byte[4];
          Random.GetBytes(buffer);
          uint r = (uint)(BitConverter.ToUInt32(buffer, 0) % 8);
          container[salt.Length + payload.Length] = key[r];
          Random.GetBytes(buffer);
          r = (uint)((r + 1 + (uint)(BitConverter.ToUInt32(buffer, 0) % 7)) % 8);
          container[salt.Length + payload.Length + 1] = key[r];

          container.Save();
          LoadContainer();
          container.SetAccessPassword(PasswordText.Text);

          for (int i = 0; i < payload.Length; ++i)
            if (container[i + salt.Length] != payload[i])
              throw new Exception("Secondary secret verification failed");

          MessageBox.Show(this, "The secret has been successfully placed in the container.");
        }
        catch (Exception ex)
        {
          MessageBox.Show(this, "Secret hiding failed: " + ex.Message);
        }
      }
      else
      {
        byte[] buffer = new byte[container.Size], buffer2 = new byte[container.Size];
        Random.GetBytes(buffer);
        Random.GetBytes(buffer2);
        for (int i = 0; i < container.Size; ++i)
          if (buffer2[i] < 10 || i < 100)
            container[i] = buffer[i];

        container.Save();
        MessageBox.Show("Any secret messages have been erased from the container.");
      }
    }

    private void RevealButton_Click(object sender, RoutedEventArgs e)
    {
      RevealedSecretMessageText.Text = "";
      revealedSecret = null;
      RevealedSecretFileName.Text = "";
      RevealedSecretStatusLabel.Text = "";

      container.SetAccessPassword(PasswordText.Text);

      byte[] allPayload = new byte[container.Size];
      for (int i = 0; i < container.Size; ++i)
        allPayload[i] = container[i];

      byte[] salt = new byte[Crypto.AESThenHMAC.SaltBitSize / 8];
      for (int i = 0; i < salt.Length; ++i)
        salt[i] = container[i];

      var key = Crypto.AESThenHMAC.RestoreKeyFromPassword(RevealPasswordText.Text, salt);

      for (int takeSize = Crypto.AESThenHMAC.MessageSizeEstimation(1); takeSize <= container.Size - SizeCheckOverhead; takeSize += 16)
      {
        byte k1 = allPayload[salt.Length + takeSize], k2 = allPayload[salt.Length + takeSize + 1];
        int r = -1;
        for(int i = 0; i < 8; ++i)
          if(key[i] == k1)
          {
            r = i;
            break;
          }

        if (r == -1)
          continue;

        bool found = false;
        for (int i = 0; i < 8; ++i)
          if (key[i] == k2 && i != r)
          {
            found = true;
            break;
          }

        if (!found)
          continue;

        byte[] payload = new byte[takeSize];
        Array.Copy(allPayload, salt.Length, payload, 0, takeSize);
        var secret = Crypto.AESThenHMAC.SimpleDecryptWithPassword(payload, RevealPasswordText.Text);
        if (secret != null)
        {
          if (Unpack(secret))
            MessageBox.Show("The secret has been successfully revealed.");
          else
            MessageBox.Show("The secret has been successfully decrypted, but could not be fully understood.");

          return;
        }
      }

      MessageBox.Show("The secret could not be found.");
    }

    bool Unpack(byte[] secret)
    {
      int p = 1;
      try
      {
        if (secret[0] > 2)
          return false;

        if (secret[0] == (byte)ContentType.FileOnly || secret[0] == (byte)ContentType.MessageAndFile)
        {
          int fileNameLength = (int)BitConverter.ToUInt32(secret, p);
          p += 4;
          RevealedSecretFileName.Text = Encoding.UTF8.GetString(secret, p, fileNameLength);
          p += fileNameLength;
          int fileLength = (int)BitConverter.ToUInt32(secret, p);
          p += 4;
          if (p + fileLength > secret.Length)
            return false;

          revealedSecret = new byte[fileLength];
          Array.Copy(secret, p, revealedSecret, 0, fileLength);
          p += fileLength;

          RevealedSecretStatusLabel.Text = "The secret file size is " + fileLength + " bytes";
        }
        else
        {
          RevealedSecretFileName.Text = "";
          RevealedSecretStatusLabel.Text = "There is no secret file";
        }

        if (secret[0] == (byte)ContentType.MessageOnly || secret[0] == (byte)ContentType.MessageAndFile)
          RevealedSecretMessageText.Text = Encoding.UTF8.GetString(secret, p, secret.Length - p);
        else
          RevealedSecretMessageText.Text = "(The secret message is empty)";
      }
      catch(Exception)
      {
        return false;
      }

      return true;
    }

    private void SecretFileName_TextChanged(object sender, TextChangedEventArgs e)
    {
      secret = null;

      if (SecretFileName.Text == "")
        SecretStatusLabel.Text = "No Secret file loaded";
      else
      {
        if (File.Exists(SecretFileName.Text))
        {
          try
          {
            secret = File.ReadAllBytes(SecretFileName.Text);
            SecretStatusLabel.Text = "File loaded, size: " + secret.Length + " bytes. File name will be stored";
          }
          catch (IOException ex)
          {
            SecretStatusLabel.Text = "File cannot be read: " + ex.Message;
          }
          catch (Exception ex)
          {
            SecretStatusLabel.Text = "Error reading file: " + ex.Message;
          }
        }
        else
          SecretStatusLabel.Text = "File does not exits";
      }

      UpdateSize();
      UpdateButtons();
    }

    private void SecretFileBrowse_Click(object sender, RoutedEventArgs e)
    {
      var ofd = new Microsoft.Win32.OpenFileDialog()
      {
        Filter = "Any (*.*)|*.*",
        CheckFileExists = true
      };

      var result = ofd.ShowDialog();
      if (result == false)
        return;

      SecretFileName.Text = ofd.FileName;
    }

    private void RevealedSecretFileSave_Click(object sender, RoutedEventArgs e)
    {
      var sfd = new Microsoft.Win32.SaveFileDialog()
      {
        FileName = RevealedSecretFileName.Text,
        CheckPathExists = true,
        OverwritePrompt = true
      };

      var result = sfd.ShowDialog();
      if (result == false)
        return;

      File.WriteAllBytes(sfd.FileName, revealedSecret);
    }

    private void CloseCommandBinding_Executed(object sender, ExecutedRoutedEventArgs e)
    {
      Close();
    }
  }
}
