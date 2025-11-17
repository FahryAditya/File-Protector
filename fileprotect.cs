// Program.cs
// File Protector - single file WinForms app
// .NET 6+ (Windows)
// Features: AES-256-CBC + PBKDF2, HMAC-SHA256, drag & drop, encrypt/decrypt, save log

using System;
using System.IO;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Security.Cryptography;
using System.Threading.Tasks;

static class Program
{
    [STAThread]
    static void Main()
    {
        ApplicationConfiguration.Initialize();
        Application.Run(new MainForm());
    }
}

public class MainForm : Form
{
    // UI controls
    ListBox listFiles;
    TextBox txtPassword;
    Button btnEncrypt, btnDecrypt, btnAdd, btnRemove, btnClear, btnSaveLog;
    CheckBox chkOverwrite;
    ProgressBar progressBar;
    Label lblStatus;

    StringBuilder logBuilder = new StringBuilder();

    public MainForm()
    {
        Text = "File Protector — AES256 (single file)";
        Width = 820;
        Height = 520;
        StartPosition = FormStartPosition.CenterScreen;

        // Controls
        listFiles = new ListBox() { Left = 12, Top = 12, Width = 560, Height = 340, AllowDrop = true };
        listFiles.DragEnter += ListFiles_DragEnter;
        listFiles.DragDrop += ListFiles_DragDrop;

        btnAdd = new Button() { Left = 590, Top = 12, Width = 180, Text = "Add file..." };
        btnAdd.Click += (s,e) => AddFilesDialog();

        btnRemove = new Button() { Left = 590, Top = 52, Width = 180, Text = "Remove selected" };
        btnRemove.Click += (s,e) => {
            var sel = listFiles.SelectedItems.Cast<string>().ToArray();
            foreach(var it in sel) listFiles.Items.Remove(it);
        };

        btnClear = new Button() { Left = 590, Top = 92, Width = 180, Text = "Clear list" };
        btnClear.Click += (s,e) => listFiles.Items.Clear();

        var lblPass = new Label() { Left = 590, Top = 150, Width = 180, Text = "Password:", AutoSize = false, TextAlign = System.Drawing.ContentAlignment.MiddleLeft };
        txtPassword = new TextBox() { Left = 590, Top = 176, Width = 180, UseSystemPasswordChar = true };

        chkOverwrite = new CheckBox() { Left = 590, Top = 214, Width = 180, Text = "Overwrite original (dangerous)" };

        btnEncrypt = new Button() { Left = 590, Top = 250, Width = 180, Text = "Encrypt" };
        btnDecrypt = new Button() { Left = 590, Top = 290, Width = 180, Text = "Decrypt" };

        btnSaveLog = new Button() { Left = 590, Top = 360, Width = 180, Text = "Save Log" };
        btnSaveLog.Click += BtnSaveLog_Click;

        progressBar = new ProgressBar() { Left = 12, Top = 370, Width = 560, Height = 22 };
        lblStatus = new Label() { Left = 12, Top = 400, Width = 760, Height = 60, Text = "Ready.", AutoSize = false };

        Controls.AddRange(new Control[] { listFiles, btnAdd, btnRemove, btnClear, lblPass, txtPassword, chkOverwrite, btnEncrypt, btnDecrypt, progressBar, lblStatus, btnSaveLog });

        btnEncrypt.Click += async (s,e) => await ProcessFilesAsync(true);
        btnDecrypt.Click += async (s,e) => await ProcessFilesAsync(false);

        // Double click to remove
        listFiles.DoubleClick += (s,e) => {
            if (listFiles.SelectedItem != null) listFiles.Items.Remove(listFiles.SelectedItem);
        };

        // initial example text in status
        AppendLog("File Protector started.");
        UpdateStatus("Ready.");
    }

    void ListFiles_DragEnter(object sender, DragEventArgs e)
    {
        if (e.Data.GetDataPresent(DataFormats.FileDrop)) e.Effect = DragDropEffects.Copy;
    }

    void ListFiles_DragDrop(object sender, DragEventArgs e)
    {
        var files = (string[])e.Data.GetData(DataFormats.FileDrop);
        foreach (var f in files)
        {
            if (File.Exists(f) && !listFiles.Items.Contains(f)) listFiles.Items.Add(f);
        }
    }

    void AddFilesDialog()
    {
        using var dlg = new OpenFileDialog();
        dlg.Multiselect = true;
        if (dlg.ShowDialog() == DialogResult.OK)
        {
            foreach (var f in dlg.FileNames) if (!listFiles.Items.Contains(f)) listFiles.Items.Add(f);
        }
    }

    void BtnSaveLog_Click(object sender, EventArgs e)
    {
        using var sfd = new SaveFileDialog();
        sfd.Filter = "Text|*.txt|All|*.*";
        sfd.FileName = $"fileprotector_log_{DateTime.Now:yyyyMMdd_HHmmss}.txt";
        if (sfd.ShowDialog() == DialogResult.OK)
        {
            File.WriteAllText(sfd.FileName, logBuilder.ToString());
            MessageBox.Show("Log saved.");
        }
    }

    void AppendLog(string line)
    {
        string ts = DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss");
        string l = $"[{ts}] {line}";
        logBuilder.AppendLine(l);
        lblStatus.Text = l;
        // Also optionally keep a file history (not required)
    }

    void UpdateStatus(string s)
    {
        lblStatus.Text = s;
        AppendLog(s);
    }

    async Task ProcessFilesAsync(bool encrypt)
    {
        if (listFiles.Items.Count == 0) { MessageBox.Show("No files selected."); return; }
        string password = txtPassword.Text;
        if (string.IsNullOrEmpty(password)) { MessageBox.Show("Enter password."); return; }

        DisableUi(true);
        try
        {
            int total = listFiles.Items.Count;
            progressBar.Value = 0;
            progressBar.Maximum = total;

            for (int i = 0; i < total; i++)
            {
                string path = listFiles.Items[i].ToString();
                try
                {
                    if (encrypt)
                    {
                        await Task.Run(() => EncryptFile(path, password, chkOverwrite.Checked));
                        AppendLog($"Encrypted: {path}");
                    }
                    else
                    {
                        await Task.Run(() => DecryptFile(path, password, chkOverwrite.Checked));
                        AppendLog($"Decrypted: {path}");
                    }
                }
                catch (Exception ex)
                {
                    AppendLog($"Error processing {path}: {ex.Message}");
                    MessageBox.Show($"Error processing {path}:\n{ex.Message}");
                }
                progressBar.Value = i + 1;
            }

            MessageBox.Show("Operation completed.");
        }
        finally
        {
            DisableUi(false);
            UpdateStatus("Ready.");
        }
    }

    void DisableUi(bool disable)
    {
        listFiles.Enabled = !disable;
        btnAdd.Enabled = !disable;
        btnRemove.Enabled = !disable;
        btnClear.Enabled = !disable;
        btnEncrypt.Enabled = !disable;
        btnDecrypt.Enabled = !disable;
        txtPassword.Enabled = !disable;
        chkOverwrite.Enabled = !disable;
    }

    // --- CRYPTO LAYER ---
    // File format (binary):
    // [magic 8 bytes] [version 1 byte] [saltLen 1 byte] [salt bytes] [ivLen 1 byte] [iv bytes] [ciphertext len (8 bytes, ulong)] [ciphertext bytes] [hmac 32 bytes]
    // magic: "FPROTECT" (8 bytes)
    static readonly byte[] MAGIC = Encoding.ASCII.GetBytes("FPROTECT");
    const byte VERSION = 1;
    const int SALT_BYTES = 16;
    const int IV_BYTES = 16; // AES CBC 128-bit IV
    const int KEY_BYTES = 32; // AES-256
    const int HMAC_BYTES = 32; // SHA256

    // Parameters
    const int PBKDF2_ITER = 120000; // adjust for performance vs security

    void EncryptFile(string inputPath, string password, bool overwrite)
    {
        // target file
        string outPath = overwrite ? inputPath : (inputPath + ".enc");

        // if output exists and not overwrite, append numeric
        if (!overwrite && File.Exists(outPath))
        {
            int c = 1;
            string basep = outPath;
            while (File.Exists(outPath)) { outPath = basep + $".{c++}"; }
        }

        // generate salt & iv
        byte[] salt = RandomBytes(SALT_BYTES);
        byte[] iv = RandomBytes(IV_BYTES);

        // derive keys: one for AES, one for HMAC (use single derivation -> expand)
        using var kdf = new Rfc2898DeriveBytes(password, salt, PBKDF2_ITER, HashAlgorithmName.SHA256);
        byte[] key = kdf.GetBytes(KEY_BYTES);
        byte[] hmacKey = kdf.GetBytes(KEY_BYTES);

        // stream encrypt
        using var outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write);
        // header
        outFs.Write(MAGIC, 0, MAGIC.Length);
        outFs.WriteByte(VERSION);
        outFs.WriteByte((byte)salt.Length);
        outFs.Write(salt, 0, salt.Length);
        outFs.WriteByte((byte)iv.Length);
        outFs.Write(iv, 0, iv.Length);

        // placeholder for ciphertext length (8 bytes)
        outFs.Write(BitConverter.GetBytes((ulong)0), 0, 8);

        long cipherStartPos = outFs.Position;

        using (var aes = Aes.Create())
        {
            aes.KeySize = 256;
            aes.Key = key;
            aes.IV = iv;
            aes.Mode = CipherMode.CBC;
            aes.Padding = PaddingMode.PKCS7;

            using var cs = new CryptoStream(outFs, aes.CreateEncryptor(), CryptoStreamMode.Write);
            using var inFs = new FileStream(inputPath, FileMode.Open, FileAccess.Read);

            // copy with buffer
            byte[] buffer = new byte[81920];
            int read;
            while ((read = inFs.Read(buffer, 0, buffer.Length)) > 0)
            {
                cs.Write(buffer, 0, read);
            }
            cs.FlushFinalBlock();
            cs.Close();
        }

        long cipherEndPos = outFs.Position;
        ulong cipherLen = (ulong)(cipherEndPos - cipherStartPos);

        // compute HMAC over everything up to now (header + ciphertext)
        outFs.Flush();
        outFs.Seek(0, SeekOrigin.Begin);
        byte[] allData = new byte[cipherEndPos];
        outFs.Read(allData, 0, (int)allData.Length);

        byte[] hmac;
        using (var h = new HMACSHA256(hmacKey))
        {
            hmac = h.ComputeHash(allData);
        }

        // append hmac
        outFs.Seek(0, SeekOrigin.End);
        outFs.Write(hmac, 0, hmac.Length);

        // write ciphertext length at reserved spot
        outFs.Seek(MAGIC.Length + 1 + 1 + salt.Length + 1 + iv.Length, SeekOrigin.Begin);
        outFs.Write(BitConverter.GetBytes(cipherLen), 0, 8);
        outFs.Flush();
        outFs.Close();
    }

    void DecryptFile(string inputPath, string password, bool overwrite)
    {
        // validate input file exists
        if (!File.Exists(inputPath)) throw new FileNotFoundException(inputPath);

        using var inFs = new FileStream(inputPath, FileMode.Open, FileAccess.Read);

        // read header
        byte[] magic = new byte[MAGIC.Length];
        inFs.Read(magic,0,magic.Length);
        if (!magic.SequenceEqual(MAGIC)) throw new InvalidDataException("File is not a FileProtector-encrypted file (magic mismatch).");

        int version = inFs.ReadByte();
        if (version != VERSION) throw new InvalidDataException("Unsupported version.");

        int saltLen = inFs.ReadByte();
        byte[] salt = new byte[saltLen]; inFs.Read(salt,0,saltLen);
        int ivLen = inFs.ReadByte();
        byte[] iv = new byte[ivLen]; inFs.Read(iv,0,ivLen);

        // read ciphertext length
        byte[] lenBuf = new byte[8]; inFs.Read(lenBuf,0,8);
        ulong cipherLen = BitConverter.ToUInt64(lenBuf, 0);

        long cipherStartPos = inFs.Position;
        long expectedHmacPos = cipherStartPos + (long)cipherLen;

        // read ciphertext & hmac
        // compute keys
        using var kdf = new Rfc2898DeriveBytes(password, salt, PBKDF2_ITER, HashAlgorithmName.SHA256);
        byte[] key = kdf.GetBytes(KEY_BYTES);
        byte[] hmacKey = kdf.GetBytes(KEY_BYTES);

        // compute HMAC over header + ciphertext
        // rewind to start and read up through ciphertext
        inFs.Seek(0, SeekOrigin.Begin);
        byte[] headerPlusCipher = new byte[expectedHmacPos];
        int got = inFs.Read(headerPlusCipher,0,headerPlusCipher.Length);

        // then read stored HMAC
        inFs.Seek(expectedHmacPos, SeekOrigin.Begin);
        byte[] storedHmac = new byte[HMAC_BYTES];
        int r = inFs.Read(storedHmac,0,storedHmac.Length);
        if (r != HMAC_BYTES) throw new InvalidDataException("File truncated or corrupt.");

        byte[] computedHmac;
        using (var h = new HMACSHA256(hmacKey))
        {
            computedHmac = h.ComputeHash(headerPlusCipher);
        }

        if (!storedHmac.SequenceEqual(computedHmac))
        {
            throw new CryptographicException("HMAC verification failed. Wrong password or corrupted file.");
        }

        // decrypt
        string outPath;
        if (overwrite)
        {
            // if file has .enc extension, attempt remove .enc
            if (inputPath.EndsWith(".enc", StringComparison.OrdinalIgnoreCase))
                outPath = inputPath.Substring(0, inputPath.Length - 4);
            else outPath = inputPath + ".dec";
        }
        else
        {
            outPath = inputPath + ".dec";
            int c = 1;
            string basep = outPath;
            while (File.Exists(outPath)) { outPath = basep + $".{c++}"; }
        }

        // position to ciphertext start
        inFs.Seek(cipherStartPos, SeekOrigin.Begin);
        using var aes = Aes.Create();
        aes.KeySize = 256;
        aes.Key = key;
        aes.IV = iv;
        aes.Mode = CipherMode.CBC;
        aes.Padding = PaddingMode.PKCS7;

        using var cryptoStream = new CryptoStream(inFs, aes.CreateDecryptor(), CryptoStreamMode.Read);
        using var outFs = new FileStream(outPath, FileMode.Create, FileAccess.Write);

        byte[] buffer = new byte[81920];
        int read;
        long remaining = (long)cipherLen;
        while (remaining > 0 && (read = cryptoStream.Read(buffer, 0, (int)Math.Min(buffer.Length, remaining))) > 0)
        {
            outFs.Write(buffer, 0, read);
            remaining -= read;
        }

        outFs.Flush();
        outFs.Close();
    }

    // Utilities
    static byte[] RandomBytes(int count)
    {
        byte[] b = new byte[count];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(b);
        return b;
    }
}
