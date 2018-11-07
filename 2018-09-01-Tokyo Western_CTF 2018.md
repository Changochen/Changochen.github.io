---
layout: post
title: "TokyoWestern CTF 2018 BBQ"
date: "2018.09.01"
---


## BBQ --- Tokyo Western CTF 2018

Hi, I am [Ne0](https://github.com/Changochen). Long time no see. Last weekend I played Tokyo Western CTF as a member of r3kapig. Obviously the quality and difficulty of this year's challenges got great improvement. When I got the first blood of  `BBQ` , I thought that no more than `3` team can solve this challenge , but there are 4 in the end.. orz.. Thanks my teammates for carrying me!



### Program Info

This program is simple : You can buy food ,grill it and eat it ,and of course , say bye-bye.

```bash
Today is BBQ Party!

1. Buy
2. Grill
3. Eat
0. Break up
Choice:
```



Details can be found in the binary. 

The food and cooked food structure is like this:

```cpp
struct Food{
    struct Food* next;
    size_t amount;
    char* name;
};

struct Cooked_food{
    struct Food* food;
    unsigned long useless;
    unsigned long tag;
};
```



### Vulnerabilities

The old binary has two bugs , one is out of bound and the other is uninitialized stack pointer , while the new binary has only the latter. As it is the uninitialized stack pointer bug that matters, let's just focus on it.

Out of bound

```cpp
printf("griddle index >> ", v0);
    v3 = getint();
    if ( cook_list[v3] )
    {
      puts("now cooking...");
    }
// and others....
```

Uninitialized stack pointer

```cpp
  struct Cooked_food *ptr; // [rsp+8h] [rbp-28h]
  unsigned __int64 v4; // [rsp+28h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  show_cook_list();
  printf("griddle index >> ");
  v2 = getint();
  if ( cook_list[v2] )
  {
    ptr = cook_list[v2];
    puts("found food.");
  }
  else
  {
    puts("empty..."); // if goes here, the ptr will be uninitialized....ooops...
  }
  if ( ptr )
  {
    v0 = ptr->tag;
    if ( v0 == 0xBADF00D22LL )
    {
      puts("I don't want to eat charcoal...");
    }
    else if ( v0 == 0xDEADBEEF11LL )
    {
      ptr->tag = 0xCAFEBABE33LL;
      free(ptr);
      puts("Yummy!");
      cook_list[v2] = 0LL;
    }
   }
```

And after some debugging , I found that the `ptr` can be one of the following:

1.  a file structure pointer 
2. if `grill()` is called, it will be the newly allocate `Cooked_food` structure pointer.
3. if `buy` is called, it will be the name of the food if the name is longer than `40` bytes.

The first one is useless , but with the last two, we can own the world!

### Exploit Steps

1. Create a freed `0x20` sized chunk. Like `grill` and `eat`
2. call `grill()` , and `ptr` will be a newly allocated chunk. 
3. call `buy` , input a name that is 40-byte long. This partial-overwrites the lowest byte of `ptr` , making it point to a food name. 
4. call `grill()` to free `ptr` , then the first 8 bytes of the freed food name chunk now has a `fd` pointer. That leaks the heap address.
5. With leaked heap address, we can now free arbitrary address, as long as the `address+0x10` contains the stupid tag `0xDEADBEEF11`
6. Fake a `0xe0` sized chunk ,and free it , leaving some libc pointers in the heap.
7. Try making a name pointer point to these libc pointers, and leak it . Libc address get~~
8. With libc address , we can fake a `Food` structure in `&__malloc_hook-0x18`. And by changing the amount of the food, we can leave a `0x21` in `&__malloc_hook-0x10`
9. Now it is obvious that we should use `fastbin attack` to modify the `fd` of a `0x20` sized `fastbin` chunk to point to `&__malloc_hook-0x18` But this is not as easy as it looks, because the only thing we can control is the name of `Food`, and the name can't contain any null bytes ! LOL
10. So my approach is : Fake a `Food` structure in `main_arena` ! We only need to free a `0x30` sized chunk and a `0x20` sized chunk , and make them to be the count and the name of the fake `Food` ,leaving `next` be empty. Then change the amount ,make it point to somewhere in the heap that we can control. And the `fastbin` looks like `modified_fd---->somewhere_controled---> &__malloc_hook-0x18` 
11. Finally! Use `fastbin` attack to modify the `__malloc_hook` to `one_gadget`. Pwn!!!



The final script can be found in [here](https://github.com/Changochen/CTF/blob/master/2018/TokyoWestern/BBQ/exp.py). If you like the writeup , please follow me on [github](https://github.com/Changochen) !

### Conclusion

The logic of this program is really simple ,and the vulnerability is also obvious. But it is extremely hard to exploit.... Maybe there are simpler ways? If you have better ways to exploit it , please share it with me ^_^.
