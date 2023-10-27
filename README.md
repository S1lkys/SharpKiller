# SharpKiller
Lifetime AMSI bypass AMSI-Killer by @ZeroMemoryEx ported to .NET Framework 4.8.


Newly integrated features:

[ x ] - Live scan for new powershell processes every 0.5 seconds -> Automatically patches new powershell instances 

#### Building the solution
* Set your platform explicitly to x64 in Build > configuration manager

## How does it work?
### Opcode Scan

* we get the exact address of the jump instruction by searching for the first byte of each instruction this technique is effective even in the face of updates or modifications to the target data set.

* for example :

  ` | 48:85D2 | test rdx, rdx |`

  ` | 74 3F | je amsi.7FFAE957C694 |`

  ` | 48 : 85C9 | test rcx, rcx |`

  ` | 74 3A | je amsi.7FFAE957C694 |`

  ` | 48 : 8379 08 00 | cmp qword ptr ds : [rcx + 8] , 0 |`

  ` | 74 33 | je amsi.7FFAE957C694 |`

* the search pattern will be like this :

  `{ 0x48,'?','?', 0x74,'?',0x48,'?' ,'?' ,0x74,'?' ,0x48,'?' ,'?' ,'?' ,'?',0x74,0x33}`

  
  ![image](https://user-images.githubusercontent.com/60795188/221431685-60fb2012-db0f-41aa-bd7b-3a19f07c91c4.png)

## Patch

### Before Patch

* The program tests the value of RDX against itself. If the comparison evaluates to 0, the program executes a jump to return. Otherwise, the program proceeds to evaluate the next instruction

  ![image](https://user-images.githubusercontent.com/60795188/221431975-73c78c9c-5358-44c2-b0de-41d68024e2bb.png)
  
  <img src="https://github.com/S1lkys/SharpKiller/assets/40408435/59f4ef29-9ed1-4d14-9ea8-f29bf299534d" height="500">

* we cant execute "Invoke-Mimikatz"

  ![image](https://user-images.githubusercontent.com/60795188/221432132-20993ccf-c53e-493d-8b22-feaea86fb6bf.png)

### After Patch


* we patch the first byte and change it from JE to JMP so it return directly 

  ![Screenshot 2023-02-26 195848](https://user-images.githubusercontent.com/60795188/221444031-5b8c365f-cb38-4ce4-89b5-153ecc12208d.png)

  ![image](https://user-images.githubusercontent.com/60795188/221432418-841db688-879c-4915-8d6e-926236a3732c.png)

* now we can execute "Invoke-Mimikatz"
  <img src="https://raw.githubusercontent.com/S1lkys/SharpKiller/main/media/demo_.jpg" height="450">


### Newly created processes

* Sharp-Killer will patch any newly created Powershell processes in near real time.
  <img src="https://raw.githubusercontent.com/S1lkys/SharpKiller/main/media/demo.jpg" height="450">

## Video demo
  ![video](https://raw.githubusercontent.com/S1lkys/SharpKiller/main/media/demo.gif)

## References:
* https://github.com/ZeroMemoryEx/Amsi-Killer
