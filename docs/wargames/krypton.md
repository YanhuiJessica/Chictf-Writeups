---
title: OverTheWire：Krypton
---

## Level 0

```bash
$ echo S1JZUFRPTklTR1JFQVQ= | base64 --decode
KRYPTONISGREAT
```

## Level 1

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>krypton1</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>KRYPTONISGREAT</td>
  </tr>
</tbody>
</table>

```bash
$ ssh krypton1@krypton.labs.overthewire.org -p 2231

$ ls /krypton
krypton1  krypton2  krypton3  krypton4  krypton5  krypton6
$ ls /krypton/krypton1
krypton2  README
$ cat /krypton/krypton1/README 
Welcome to Krypton!

This game is intended to give hands on experience with cryptography
and cryptanalysis.  The levels progress from classic ciphers, to modern,
easy to harder.

Although there are excellent public tools, like cryptool,to perform
the simple analysis, we strongly encourage you to try and do these
without them for now.  We will use them in later excercises.

** Please try these levels without cryptool first **


The first level is easy.  The password for level 2 is in the file 
'krypton2'.  It is 'encrypted' using a simple rotation called ROT13.  
It is also in non-standard ciphertext format.  When using alpha characters for
cipher text it is normal to group the letters into 5 letter clusters, 
regardless of word boundaries.  This helps obfuscate any patterns.

This file has kept the plain text word boundaries and carried them to
the cipher text.

Enjoy!

$ cd /krypton/krypton1
$ cat krypton2 | tr 'a-zA-Z' 'n-za-mN-ZA-M'
LEVEL TWO PASSWORD ROTTEN
```

## Level 2

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>krypton2</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>ROTTEN</td>
  </tr>
</tbody>
</table>

```bash
$ ssh krypton2@krypton.labs.overthewire.org -p 2231

$ cd /krypton/krypton2
$ ls
encrypt  keyfile.dat  krypton3  README
$ cat README 
Krypton 2

ROT13 is a simple substitution cipher.

Substitution ciphers are a simple replacement algorithm.  In this example
of a substitution cipher, we will explore a 'monoalphebetic' cipher.
Monoalphebetic means, literally, "one alphabet" and you will see why.

This level contains an old form of cipher called a 'Caesar Cipher'.
A Caesar cipher shifts the alphabet by a set number.  For example:

plain:	a b c d e f g h i j k ...
cipher:	G H I J K L M N O P Q ...

In this example, the letter 'a' in plaintext is replaced by a 'G' in the
ciphertext so, for example, the plaintext 'bad' becomes 'HGJ' in ciphertext.

The password for level 3 is in the file krypton3.  It is in 5 letter
group ciphertext.  It is encrypted with a Caesar Cipher.  Without any 
further information, this cipher text may be difficult to break.  You do 
not have direct access to the key, however you do have access to a program 
that will encrypt anything you wish to give it using the key.  
If you think logically, this is completely easy.

One shot can solve it!

Have fun.

Additional Information:

The `encrypt` binary will look for the keyfile in your current working
directory. Therefore, it might be best to create a working direcory in /tmp
and in there a link to the keyfile. As the `encrypt` binary runs setuid
`krypton3`, you also need to give `krypton3` access to your working directory.

Here is an example:

krypton2@melinda:~$ mktemp -d
/tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:~$ cd /tmp/tmp.Wf2OnCpCDQ
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ln -s /krypton/krypton2/keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
keyfile.dat
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ chmod 777 .
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ /krypton/krypton2/encrypt /etc/issue
krypton2@melinda:/tmp/tmp.Wf2OnCpCDQ$ ls
ciphertext  keyfile.dat

$ cat krypton3 
OMQEMDUEQMEK
$ ./encrypt

 usage: encrypt foo  - where foo is the file containing the plaintext
$ mktemp -d
/tmp/tmp.aHZs9AbfRo
$ cd /tmp/tmp.aHZs9AbfRo
$ ln -s /krypton/krypton2/keyfile.dat
$ chmod 777 .
$ echo abcABC > test
$ /krypton/krypton2/encrypt test
$ cat ciphertext 
MNOMNO
$ cd /krypton/krypton2
$ cat krypton3 | tr 'A-Z' 'O-ZA-N'
CAESARISEASY
```