# ShellCodeRunner Example Code
XOR Payload Encryptor for .NET and Payload Runner with Built-in XOR Decryptor
## This is just an Example
This code is an example for running shell code on a Windows system via .NET assembly.  It consists of 2 projects:
##### 1. XORKryptor
- XOR encryptor that can be used on any file, but was written to as an example to encrypt Cobalt Strike payloads.
##### 2. ShellCodeRunner: Executing the shellcode injection technique
- Example code inteded for running XOR encrypted Cobalt Strike beacon payloads.  It contains a XOR decryptor which decrypts the 
payload before running.
- Where traditional ShellCode Injection typically opens an already running process and uses CreateRemoteThread, the method in this example
instead, uses CreateThread to create a new thread within the ShellCodeRunner process itself.<br/>
The ShellCodeRunner uses the following steps: 
  1. Allocate a chunk of memory in the calling process (VirtualAlloc) with RW memory protection
  2. Copy the shellcode payload to the newly allocated section (Marshal.Copy)
  3. Change memory protection to RX (VirtualProtect)
  4. Create a new thread in the remote process to execute the shellcode (CreateThread).
  5. Wait for beacon to call to exit (WaitForSingleObject)
## Special Thanks
This example code was made entirely possible by @djhohnstein<br/>
He is a MOUNTAIN of knowledge and I learned a LOT!
