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

## Level 3

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>krypton3</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>CAESARISEASY</td>
  </tr>
</tbody>
</table>

```bash
$ ssh krypton3@krypton.labs.overthewire.org -p 2231

$ cd /krypton/krypton3
$ ls
found1  found2  found3  HINT1  HINT2  krypton4  README
$ cat README 
Well done.  You‘ve moved past an easy substitution cipher.

Hopefully you just encrypted the alphabet a plaintext 
to fully expose the key in one swoop.

The main weakness of a simple substitution cipher is 
repeated use of a simple key.  In the previous exercise
you were able to introduce arbitrary plaintext to expose
the key.  In this example, the cipher mechanism is not 
available to you, the attacker.

However, you have been lucky.  You have intercepted more
than one message.  The password to the next level is found
in the file 'krypton4'.  You have also found 3 other files.
(found1, found2, found3)

You know the following important details:

- The message plaintexts are in English (*** very important)
- They were produced from the same key (*** even better!)


Enjoy.

$ cat HINT1
Some letters are more prevalent in English than others.
$ cat HINT2
"Frequency Analysis" is your friend.
$ cat found1
CGZNL YJBEN QYDLQ ZQSUQ NZCYD SNQVU BFGBK GQUQZ QSUQN UZCYD SNJDS UDCXJ ZCYDS NZQSU QNUZB WSBNZ QSUQN UDCXJ CUBGS BXJDS UCTYV SUJQG WTBUJ KCWSV LFGBK GSGZN LYJCB GJSZD GCHMS UCJCU QJLYS BXUMA UJCJM JCBGZ CYDSN CGKDC ZDSQZ DVSJJ SNCGJ DSYVQ CGJSO JCUNS YVQZS WALQV SJJSN UBTSX COSWG MTASN BXYBU CJCBG UWBKG JDSQV YDQAS JXBNS OQTYV SKCJD QUDCX JBXQK BMVWA SNSYV QZSWA LWAKB MVWAS ZBTSS QGWUB BGJDS TSJDB WCUGQ TSWQX JSNRM VCMUZ QSUQN KDBMU SWCJJ BZBTT MGCZQ JSKCJ DDCUE SGSNQ VUJDS SGZNL YJCBG UJSYY SNXBN TSWAL QZQSU QNZCY DSNCU BXJSG CGZBN YBNQJ SWQUY QNJBX TBNSZ BTYVS OUZDS TSUUM ZDQUJ DSICE SGNSZ CYDSN QGWUJ CVVDQ UTBWS NGQYY VCZQJ CBGCG JDSNB JULUJ STQUK CJDQV VUCGE VSQVY DQASJ UMAUJ CJMJC BGZCY DSNUJ DSZQS UQNZC YDSNC USQUC VLANB FSGQG WCGYN QZJCZ SBXXS NUSUU SGJCQ VVLGB ZBTTM GCZQJ CBGUS ZMNCJ LUDQF SUYSQ NSYNB WMZSW TBUJB XDCUF GBKGK BNFAS JKSSG QGWDC USQNV LYVQL UKSNS TQCGV LZBTS WCSUQ GWDCU JBNCS UESGN SUDSN QCUSW JBJDS YSQFB XUBYD CUJCZ QJCBG QGWQN JCUJN LALJD SSGWB XJDSU COJSS GJDZS GJMNL GSOJD SKNBJ STQCG VLJNQ ESWCS UMGJC VQABM JCGZV MWCGE DQTVS JFCGE VSQNQ GWTQZ ASJDZ BGUCW SNSWU BTSBX JDSXC GSUJS OQTYV SUCGJ DSSGE VCUDV QGEMQ ESCGD CUVQU JYDQU SDSKN BJSJN QECZB TSWCS UQVUB FGBKG QUNBT QGZSU QGWZB VVQAB NQJSW KCJDB JDSNY VQLKN CEDJU TQGLB XDCUY VQLUK SNSYM AVCUD SWCGS WCJCB GUBXI QNLCG EHMQV CJLQG WQZZM NQZLW MNCGE DCUVC XSJCT SQGWC GJKBB XDCUX BNTSN JDSQJ NCZQV ZBVVS QEMSU YMAVC UDSWJ DSXCN UJXBV CBQZB VVSZJ SWSWC JCBGB XDCUW NQTQJ CZKBN FUJDQ JCGZV MWSWQ VVAMJ JKBBX JDSYV QLUGB KNSZB EGCUS WQUUD QFSUY SQNSU
```

- 虽然密文分组了，但仍然是单表代换。词频分析就交给 [quipqiup](https://quipqiup.com/) 好啦
- 选择任意一个 `found` 文件内容加上 `krypton4` 的文件内容就可以获得明文：`WELL DONE THE LEVEL FOUR PASSWORD IS BRUTE`

## Level 4

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>krypton4</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>BRUTE</td>
  </tr>
</tbody>
</table>

```bash
$ ssh krypton4@krypton.labs.overthewire.org -p 2231

$ cd /krypton/krypton4
$ ls
found1  found2  HINT  krypton5  README
$ cat README | iconv -f ISO8859-1 -t UTF-8
Good job!

You more than likely used frequency analysis and some common sense
to solve that one.

So far we have worked with simple substitution ciphers.  They have
also been 'monoalphabetic', meaning using a fixed key, and 
giving a one to one mapping of plaintext (P) to ciphertext (C).
Another type of substitution cipher is referred to as 'polyalphabetic',
where one character of P may map to many, or all, possible ciphertext 
characters.

An example of a polyalphabetic cipher is called a Vigenère Cipher.  It works
like this:

If we use the key(K)  'GOLD', and P = PROCEED MEETING AS AGREED, then "add"
P to K, we get C.  When adding, if we exceed 25, then we roll to 0 (modulo 26).


P     P R O C E   E D M E E   T I N G A   S A G R E   E D
K     G O L D G   O L D G O   L D G O L   D G O L D   G O

becomes:

P     15 17 14 2  4  4  3 12  4 4  19  8 13 6  0  18 0  6 17 4 4   3
K     6  14 11 3  6 14 11  3  6 14 11  3  6 14 11  3 6 14 11 3 6  14
C     21 5  25 5 10 18 14 15 10 18  4 11 19 20 11 21 6 20  2 8 10 17

So, we get a ciphertext of:

VFZFK SOPKS ELTUL VGUCH KR

This level is a Vigenère Cipher.  You have intercepted two longer, english 
language messages.  You also have a key piece of information.  You know the 
key length!

For this exercise, the key length is 6.  The password to level five is in the usual
place, encrypted with the 6 letter key.

Have fun!
$ cat HINT 
Frequency analysis will still work, but you need to analyse it
by "keylength".  Analysis of cipher text at position 1, 6, 12, etc
should reveal the 1st letter of the key, in this case.  Treat this as
6 different mono-alphabetic ciphers...

Persistence and some good guesses are the key!

$ cat found1
YYICS JIZIB AGYYX RIEWV IXAFN JOOVQ QVHDL CRKLB SSLYX RIQYI IOXQT WXRIC RVVKP BHZXI YLYZP DLCDI IKGFJ UXRIP TFQGL CWVXR IEZRV NMYSF JDLCL RXOWJ NMINX FNJSP JGHVV ERJTT OOHRM VMBWN JTXKG JJJXY TSYKL OQZFT OSRFN JKBIY YSSHE LIKLO RFJGS VMRJC CYTCS VHDLC LRXOJ MWFYB JPNVR NWUMZ GRVMF UPOEB XKSDL CBZGU IBBZX MLMKK LOACX KECOC IUSBS RMPXR IPJZW XSPTR HKRQB VVOHR MVKEE PIZEX SDYYI QERJJ RYSLJ VZOVU NJLOW RTXSD LYYNE ILMBK LORYW VAOXM KZRNL CWZRA YGWVH DLCLZ VVXFF KASPJ GVIKW WWVTV MCIKL OQYSW SBAFJ EWRII SFACC MZRVO MLYYI MSSSK VISDY YIGML PZICW FJNMV PDNEH ISSFE HWEIJ PSEEJ QYIBW JFMIC TCWYE ZWLTK WKMBY YICGY WVGBS UKFVG IKJRR DSBJJ XBSWM VVYLR MRXSW BNWJO VCSKW KMBYY IQYYW UMKRM KKLOK YYVWX SMSVL KWCAV VNIQY ISIIB MVVLI DTIIC SGSRX EVYQC CDLMZ XLDWF JNSEP BRROO WJFMI CSDDF YKWQM VLKWM KKLOV CXKFE XRFBI MEPJW SBWFJ ZWGMA PVHKR BKZIB GCFEH WEWSF XKPJT NCYYR TUICX PTPLO VIJVT DSRMV AOWRB YIBIR MVWER QJKWK RBDFY MELSF XPEGQ KSPML IYIBX FJPXR ELPVH RMKFE HLEBJ YMWKM TUFII YSUXE VLJUX YAYWU XRIUJ JXGEJ PZRQS TJIJS IJIJS PWMKK KBEQX USDXC IYIBI YSUXR IPJNM DLBFZ WSIQF EHLYR YVVMY NXUSB SRMPW DMJQN SBIRM VTBIR YPWSP IIIIC WQMVL KHNZK SXMLY YIZEJ FTILY RSFAD SFJIW EVNWZ WOWFJ WSERB NKAKW LTCSX KCWXV OILGL XZYPJ NLSXC YYIBM ZGFRK VMZEH DSRTJ ROGIM RHKPQ TCSCX GYJKB ICSTS VSPFE HGEQF JARMR JRWNS PTKLI WBWVW CXFJV QOVYQ UGSXW BRWCS MSCIP XDFIF OLGSU ECXFJ PENZY STINX FJXVY YLISI MEKJI SEKFJ IEXHF NCPSI PKFVD LCWVA OVCSF JKVKX ESBLM ZJICM LYYMC GMZEX BCMKK LOACX KEXHR MVKBS SSUAK WSSKM VPCIZ RDLCF WXOVL TFRDL CXLRC LMSVL YXGSK LOMPK RGOWD TIXRI PJNIB ILTKV OIQYF SPJCW KLOQQ MRHOW MYYED FCKFV ORGLY XNSPT KLIEL
$ cat found2
YYIIA CWVSL PGLVH DSAFD TYYRY YEDRG LYXER BJIEV EPLVX BICNE XRIDT IICXD TIXRI PJNIB ILTYS EWCXE IKVRM VXBIC RRHOE ETFHD LGHBG YZCWZ RQXMU ISDIA YKLOQ DWFQD LCIVA KRBYY IDMLB FSNQY STLYT NJUEQ VCFKT SPCTW AYSBB ZXRLG XRBOE LIUSB SRMPF EMJYR WZPCS UMNJG WVXRE RBRVW IBMVV KRBRR HOLCW WIOPJ JJWVS LJCCC LCFEH DSRTR XOXFJ CECXM KKLOM PGIIK HYSUR YAQMV HSHLT KOXSU BYEDX FJPAY YJIUS PSPGI IKODF JXSJW TLASW FXRMN XFJCM YRGBZ PVKMN EXYXF JWSBI QYRRN OGQCE NICWW SBCMZ PSEGY SISKW RNKFI XFJWM BIQNE GOCMZ IXKWR JJEBI QTGIM YJNRV DLYYP SETPJ WIBGM TBINJ MTUEX HRMVR ISSBZ PVLYA VEFIP DXSYH ZWVEU JYXKH YRRUC IKWCI FRDFC LXINX FJKMX AMTUQ KRGXY SEPBH VVDEG SCCGI CUZJI SSPZP VIBFG SYVBJ VVKRB YYIXQ WORAC AMZCH BYQYR KKMLG LXDLC QZSXA CSKEG EWNEX YXFJW SBIQY RRNJM ZEHRM QTNRC YNUVV KRBSF SXICA VVURC BNLKX GYNEC JMWYI NMBSK QORRN FRSXY SUXRI QHRVO GPTNJ YYLIR XBICK LPVSD SLXCE LIWMV PCIUS BSRMP WLEQP VXGMR MKLOQ QTKLK XQMVA YYJIE SDFCM LRQVW KFVKP MSXXS QCXYI DLMZX LDXFN JAKWT JICUM LIRRN XFTLK RXDZC SPXFJ JGKVC HISGF SYJLO PYZXL OHFJR VDMJD RXDLC FNOGE PINEI MLBYM MLRMV TYSPH IIKXS WVTSG IJUYZ XFJEY DWFNJ TKHBJ ULKRB XNIBI QTTPE QQDRR NXFJE YDWUJ IICSQ RRPVX FFKLO HPTGT OHYQD SCXYX DEXCY XYIZY RNEXR IZFJO OXZZK XRIQH RVOGP TNHSH LTKQS RBMFA VSLLZ XDSMP YMWXM KZPVX FJSEC OCYWS BMRJE ELPCI YMWXM PVIZE UFPJB SKYYI PMPJR WRIDJ RVOHY XGEBO KNXLD KCYZR DSFNJ WDVYB RRNFS WELSQ SUJSR IIJGX KKMTU HSWRF EGOEU FPJBS KYYIP PYRVW KRBTE PIGYR VROEP YFGYZ CWUSB SRMPA SXFII CVIYA VWGLC SJLOP YDUSG RRTJP OINYY ICIIJ GXRIP AVVIW LZXEX HUFIQ KRBXY ICPCU KWYYL ICCER RNCQY VLNEK GLCSZ XGEQI RCVME MKXRI ENIPL ERMVH RIPKR GOMLF CMDXJ JIMZT JNEKL VMTBE XHQTF RKJRJ IXRIW FCPCX YWKIN XMBRV NXFJV QOVYQ UGSXW YYMCA YXKSL IYSVZ ORRKL PNEWK FVDLC YIEFI JJIWD LCDYE NLYWU PIFCJ EAKPI NEKKR FTLVG LCSKL OCQFN FOJMW VXRIK FXVOE RIZXM LRMRX MVMXJ INXFJ ISKHY SUHSZ GIVHD LCKFV OWRFJ JKVYX KLOCA TLPNW CJFRO MRMVV CMBJZ XGEQF MIBCU NUINM RHYEX HUMVR DLCDT VOTRZ GXYXF JVHQI YSUPY SIJUM XXMNK XRIWH FYVHQ JVMDA YXRPC STJIC NICUR RNXFJ IIGIP JDEXC ZNXNK KEJUV YGIXR XDLCG FXDSK YYICM BJJAO VCXFW DICUK LKXLT EIYJR MVQMS SQUGV MKGUS GRYSU JYVYR FQORR NKWOI KJUXR ERYYI SVHTL VXIWR LWDIL INLKX QMRPV ACIFE COCIU SBSRM PHOWN FZVSR EQPMR ETJEX DLCKR MXXCX KMNIY XRMNX FJKMX AMTUQ KRYSU XRIJN FRCLM TBLSW QMRKQ CKFEI KRBQF SUIBY YSEKF YWYVF SYKLO WAFII MVMBJ ESHUJ TEXRM YWPIX FFKMC GCWKE SRLJZ XRIPH RRGIA QZQLH MBEMX XMYYM CKPJR XNMRH YXRIP JWSBI GKNIM ELSFX TYKUF ZOVGY NIWYQ YJXYT UMVVO ACFII SXFNE OSGMZ CHTYK UFZOV GYJES HRMVG YAYWU PIPGT EEPXC WDIKW SWZRQ XFJUM CXYST IMEPJ WYVPW NELSW KNEHD LCSNI KVCFC PBMEM KEXWU JIINX FJJGK VCHIS GJMWP SEGYS TEBVW ZJEVP MAVVY RWTLV LEAPF ROERF KMWIU JCPSP JYICS XQFZH DLCQZ SXAFT NMVPE TWMBW RNNMV PBJTP KVCIK LOWAF IIMVM BWSBM DDFYP SSSUX RERDF YMSSQ URYXH ZDTYZ CWKLO KSQWH YVMYY CGSSQ UFOOG QCINS PYYID MLBFS NQYSS ENPWI VRDIB TEXRI PTTOC FCQFA LYRNW MKQMS PSEVZ FTOSX UNCPX SRRRX DIPXF QEGFK FVDLC KRPVA MZCHX SRMLV DQCFK EVP

$ mktemp -d
/tmp/tmp.uG3ytoUtVo
$ cd /tmp/tmp.uG3ytoUtVo
$ cp /krypton/krypton4/found* .

$ vi count.py
```

- 按密钥长度分别统计各个位上的字母频率，一般最高频率字母对应明文 `E`，由此可推出密钥
- 需要注意 `found1` 的长度不是 6 的倍数，不能直接与 `found2` 拼接后计算

??? note "count.py"

    ```py
    #!/usr/bin/env python3

    for i in range(1, 3):
      s = ''
      with open('found' + str(i), 'r') as f:
        s += f.read()
      s = s.replace(' ', '')
      d = list(dict() for _ in range(6))
      cnt = list(0 for _ in range(6))
      for i in range(len(s)):
        cnt[i % 6] += 1
        try:
          d[i % 6][s[i]] += 1
        except:
          d[i % 6][s[i]] = 1
    key = ''
    for i in range(6):
      for j in d[i]:
        d[i][j] /= cnt[i]
      d[i] = sorted(d[i].items(), key=lambda kv:(kv[1],kv[0]), reverse=True)
      key += chr((26 + ord(d[i][0][0]) - ord('E')) % 26 + ord('A'))
    print(key)
    ```

```bash
$ python3 count.py 
FRTKEY
```

- 在文本长度不够的情况下，实际字母频率会有一定的偏差，此时需根据解密情况并结合常用词对密钥进行调整
- `found1` 与 `found2` 均以 `YYI` 开头，推测 `YYI` 对应明文 `THE`，调整密钥为 `FREKEY`
- `HCIKV RJOX` 解密为 `CLEAR TEXT`

## Level 5

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>krypton5</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>CLEARTEXT</td>
  </tr>
</tbody>
</table>

```bash
$ ssh krypton5@krypton.labs.overthewire.org -p 2231

$ cd /krypton/krypton5
$ ls
found1  found2  found3  krypton6  README
$ cat README 
Frequency analysis can break a known key length as well.  Lets try one
last polyalphabetic cipher, but this time the key length is unknown.


Enjoy.
$ cat krypton6 
BELOS Z
```

- 由于密钥长度未知，首先要推测密钥长度，通过 [Kasiski 测试](https://planetcalc.com/8550/) 来判断
    - 在维吉尼亚加密中，当明文中一对相同字母组间隔字母数为密钥的倍数时，其对应的密文字母组相同
- 分别分析 `found1`、`found2` 和 `found3`，推测密钥长度为 $3$
    - 需要注意 `Key Length` 是工具处理后的结果，实际字母组间隔均大于 $3$

    File | Key Length | Distances Matched
    -|-|-
    found1 | 3 | 84.18 %
    found2 | 3 | 83.19 %
    found3 | 3 | 78.40 %

- 再使用 [Level 4](#level-4) 的脚本分析，打印输出各个位的字母频率，发现与字母频率表中的值差距较大

??? note "count.py"

    ```py
    #!/usr/bin/env python3

    kl = 3

    for i in range(1, 4):
      s = ''
      with open('found' + str(i), 'r') as f:
        s += f.read()
      s = s.replace(' ', '')
      d = list(dict() for _ in range(kl))
      cnt = list(0 for _ in range(kl))
      for i in range(len(s)):
        cnt[i % kl] += 1
        try:
          d[i % kl][s[i]] += 1
        except:
          d[i % kl][s[i]] = 1
    for i in range(kl):
      for j in d[i]:
        d[i][j] /= cnt[i]
      d[i] = sorted(d[i].items(), key=lambda kv:(kv[1],kv[0]), reverse=True)
      print(d[i])
    ```

```bash
$ python3 count.py 
[('K', 0.08347529812606473), ('Y', 0.07836456558773425), ('O', 0.07155025553662692), ('D', 0.06132879045996593), ('P', 0.05792163543441227), ('C', 0.05792163543441227), ('S', 0.05110732538330494), ('T', 0.049403747870528106), ('Z', 0.04599659284497445), ('X', 0.04599659284497445), ('R', 0.04599659284497445), ('N', 0.044293015332197615), ('G', 0.039182282793867124), ('E', 0.039182282793867124), ('U', 0.030664395229982964), ('L', 0.030664395229982964), ('B', 0.02555366269165247), ('W', 0.020442930153321975), ('V', 0.020442930153321975), ('M', 0.017035775127768313), ('J', 0.017035775127768313), ('I', 0.017035775127768313), ('A', 0.017035775127768313), ('Q', 0.013628620102214651), ('F', 0.013628620102214651), ('H', 0.005110732538330494)]
[('I', 0.09215017064846416), ('X', 0.08191126279863481), ('M', 0.07679180887372014), ('E', 0.06825938566552901), ('L', 0.06484641638225255), ('S', 0.06143344709897611), ('V', 0.059726962457337884), ('H', 0.05460750853242321), ('W', 0.04778156996587031), ('T', 0.04778156996587031), ('R', 0.04436860068259386), ('G', 0.03924914675767918), ('P', 0.03754266211604096), ('B', 0.034129692832764506), ('K', 0.030716723549488054), ('A', 0.027303754266211604), ('Y', 0.023890784982935155), ('J', 0.023890784982935155), ('Z', 0.017064846416382253), ('O', 0.017064846416382253), ('F', 0.015358361774744027), ('C', 0.015358361774744027), ('D', 0.006825938566552901), ('N', 0.005119453924914676), ('U', 0.0034129692832764505), ('Q', 0.0034129692832764505)]
[('Y', 0.07337883959044368), ('L', 0.07167235494880546), ('R', 0.059726962457337884), ('P', 0.05802047781569966), ('V', 0.05631399317406143), ('F', 0.051194539249146756), ('A', 0.04948805460750853), ('U', 0.04607508532423208), ('S', 0.04607508532423208), ('C', 0.04607508532423208), ('G', 0.042662116040955635), ('Q', 0.03924914675767918), ('M', 0.03924914675767918), ('B', 0.03924914675767918), ('K', 0.03583617747440273), ('Z', 0.034129692832764506), ('N', 0.034129692832764506), ('J', 0.034129692832764506), ('H', 0.02901023890784983), ('O', 0.027303754266211604), ('E', 0.025597269624573378), ('W', 0.017064846416382253), ('T', 0.015358361774744027), ('I', 0.011945392491467578), ('D', 0.011945392491467578), ('X', 0.005119453924914676)]
```

- 调整密钥长度为 $3$ 的倍数，当密钥长度为 $9$ 时，可以获得较为合理的字母频率，明文字母 `E` 一般对应频率靠前的密文字母，密钥为 `KEYLENGTH`

```bash
$ python3 count.py 
[('C', 0.12244897959183673), ('O', 0.11224489795918367), ('K', 0.09693877551020408), ('D', 0.09183673469387756), ('Y', 0.08163265306122448), ('R', 0.07142857142857142), ('S', 0.0663265306122449), ('B', 0.061224489795918366), ('X', 0.04591836734693878), ('V', 0.03571428571428571), ('P', 0.030612244897959183), ('N', 0.030612244897959183), ('E', 0.025510204081632654), ('F', 0.02040816326530612), ('W', 0.015306122448979591), ('Q', 0.015306122448979591), ('M', 0.015306122448979591), ('L', 0.015306122448979591), ('Z', 0.01020408163265306), ('U', 0.01020408163265306), ('I', 0.01020408163265306), ('G', 0.01020408163265306), ('A', 0.00510204081632653)]
[('I', 0.11734693877551021), ('S', 0.10204081632653061), ('X', 0.08163265306122448), ('W', 0.08163265306122448), ('V', 0.08163265306122448), ('M', 0.07653061224489796), ('E', 0.07142857142857142), ('R', 0.0663265306122449), ('L', 0.061224489795918366), ('H', 0.03571428571428571), ('J', 0.030612244897959183), ('Y', 0.025510204081632654), ('T', 0.025510204081632654), ('P', 0.025510204081632654), ('F', 0.025510204081632654), ('K', 0.02040816326530612), ('G', 0.015306122448979591), ('C', 0.015306122448979591), ('A', 0.015306122448979591), ('Z', 0.01020408163265306), ('O', 0.01020408163265306), ('Q', 0.00510204081632653)]
[('Y', 0.10204081632653061), ('C', 0.10204081632653061), ('L', 0.09693877551020408), ('R', 0.09183673469387756), ('Q', 0.08673469387755102), ('M', 0.08163265306122448), ('P', 0.061224489795918366), ('F', 0.061224489795918366), ('G', 0.05102040816326531), ('J', 0.04591836734693878), ('K', 0.03571428571428571), ('A', 0.03571428571428571), ('S', 0.025510204081632654), ('B', 0.025510204081632654), ('U', 0.02040816326530612), ('I', 0.02040816326530612), ('Z', 0.01020408163265306), ('T', 0.01020408163265306), ('N', 0.01020408163265306), ('E', 0.01020408163265306), ('W', 0.00510204081632653), ('V', 0.00510204081632653), ('D', 0.00510204081632653)]
[('P', 0.14285714285714285), ('D', 0.09183673469387756), ('Y', 0.08673469387755102), ('T', 0.0663265306122449), ('E', 0.0663265306122449), ('S', 0.061224489795918366), ('L', 0.061224489795918366), ('Z', 0.05102040816326531), ('N', 0.05102040816326531), ('W', 0.04591836734693878), ('O', 0.04591836734693878), ('X', 0.03571428571428571), ('C', 0.030612244897959183), ('Q', 0.025510204081632654), ('J', 0.025510204081632654), ('R', 0.02040816326530612), ('F', 0.02040816326530612), ('A', 0.02040816326530612), ('V', 0.015306122448979591), ('M', 0.015306122448979591), ('I', 0.00510204081632653), ('H', 0.00510204081632653), ('G', 0.00510204081632653), ('B', 0.00510204081632653)]
[('I', 0.1282051282051282), ('E', 0.09230769230769231), ('S', 0.08205128205128205), ('M', 0.07692307692307693), ('X', 0.06153846153846154), ('V', 0.06153846153846154), ('H', 0.06153846153846154), ('P', 0.05641025641025641), ('L', 0.05128205128205128), ('W', 0.046153846153846156), ('R', 0.046153846153846156), ('J', 0.041025641025641026), ('O', 0.035897435897435895), ('G', 0.03076923076923077), ('C', 0.03076923076923077), ('A', 0.02564102564102564), ('Y', 0.020512820512820513), ('T', 0.015384615384615385), ('K', 0.010256410256410256), ('F', 0.010256410256410256), ('Z', 0.005128205128205128), ('Q', 0.005128205128205128), ('B', 0.005128205128205128)]
[('V', 0.09743589743589744), ('R', 0.08205128205128205), ('B', 0.08205128205128205), ('G', 0.07692307692307693), ('N', 0.06666666666666667), ('F', 0.06666666666666667), ('E', 0.06153846153846154), ('Y', 0.05641025641025641), ('U', 0.05128205128205128), ('A', 0.05128205128205128), ('S', 0.041025641025641026), ('P', 0.035897435897435895), ('J', 0.035897435897435895), ('Z', 0.03076923076923077), ('Q', 0.03076923076923077), ('O', 0.020512820512820513), ('L', 0.020512820512820513), ('C', 0.020512820512820513), ('X', 0.015384615384615385), ('T', 0.015384615384615385), ('H', 0.015384615384615385), ('I', 0.010256410256410256), ('W', 0.005128205128205128), ('K', 0.005128205128205128), ('D', 0.005128205128205128)]
[('K', 0.15384615384615385), ('G', 0.10256410256410256), ('U', 0.08205128205128205), ('T', 0.08205128205128205), ('Z', 0.07692307692307693), ('Y', 0.06666666666666667), ('X', 0.05641025641025641), ('O', 0.05641025641025641), ('N', 0.05128205128205128), ('R', 0.046153846153846156), ('I', 0.035897435897435895), ('S', 0.02564102564102564), ('J', 0.02564102564102564), ('E', 0.02564102564102564), ('A', 0.02564102564102564), ('M', 0.020512820512820513), ('C', 0.020512820512820513), ('L', 0.015384615384615385), ('V', 0.010256410256410256), ('H', 0.010256410256410256), ('B', 0.010256410256410256)]
[('X', 0.10256410256410256), ('T', 0.10256410256410256), ('B', 0.09743589743589744), ('L', 0.08205128205128205), ('M', 0.07692307692307693), ('G', 0.07179487179487179), ('H', 0.06666666666666667), ('K', 0.06153846153846154), ('E', 0.041025641025641026), ('A', 0.041025641025641026), ('Z', 0.035897435897435895), ('V', 0.035897435897435895), ('P', 0.03076923076923077), ('I', 0.03076923076923077), ('Y', 0.02564102564102564), ('R', 0.020512820512820513), ('D', 0.020512820512820513), ('W', 0.015384615384615385), ('N', 0.015384615384615385), ('U', 0.010256410256410256), ('F', 0.010256410256410256), ('O', 0.005128205128205128)]
[('L', 0.09743589743589744), ('P', 0.07692307692307693), ('S', 0.07179487179487179), ('H', 0.07179487179487179), ('V', 0.06666666666666667), ('U', 0.06666666666666667), ('K', 0.06666666666666667), ('Z', 0.06153846153846154), ('Y', 0.06153846153846154), ('O', 0.06153846153846154), ('A', 0.06153846153846154), ('W', 0.041025641025641026), ('M', 0.035897435897435895), ('N', 0.02564102564102564), ('F', 0.02564102564102564), ('D', 0.02564102564102564), ('T', 0.020512820512820513), ('J', 0.020512820512820513), ('C', 0.015384615384615385), ('B', 0.010256410256410256), ('R', 0.005128205128205128), ('I', 0.005128205128205128), ('E', 0.005128205128205128)]
```

- 解 `BELOS Z` 得 `RANDO M`

## Level 6

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>krypton6</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>RANDOM</td>
  </tr>
</tbody>
</table>

```bash
$ ssh krypton6@krypton.labs.overthewire.org -p 2231

$ cd /krypton/krypton6
$ ls
encrypt6  HINT1  HINT2  keyfile.dat  krypton7  onetime  README
$ cat README 
Hopefully by now its obvious that encryption using repeating keys
is a bad idea.  Frequency analysis can destroy repeating/fixed key
substitution crypto.

A feature of good crypto is random ciphertext.  A good cipher must
not reveal any clues about the plaintext.  Since natural language 
plaintext (in this case, English) contains patterns, it is left up
to the encryption key or the encryption algorithm to add the 
'randomness'.

Modern ciphers are similar to older plain substitution 
ciphers, but improve the 'random' nature of the key.

An example of an older cipher using a complex, random, large key
is a vigniere using a key of the same size of the plaintext.  For
example, imagine you and your confident have agreed on a key using
the book 'A Tale of Two Cities' as your key, in 256 byte blocks.

The cipher works as such:

Each plaintext message is broken into 256 byte blocks.  For each 
block of plaintext, a corresponding 256 byte block from the book
is used as the key, starting from the first chapter, and progressing.
No part of the book is ever re-used as key.  The use of a key of the 
same length as the plaintext, and only using it once is called a "One Time Pad".

Look in the krypton6/onetime  directory.  You will find a file called 'plain1', a 256 
byte block.  You will also see a file 'key1', the first 256 bytes of
'A Tale of Two Cities'.  The file 'cipher1' is the cipher text of 
plain1.  As you can see (and try) it is very difficult to break
the cipher without the key knowledge.

(NOTE - it is possible though.  Using plain language as a one time pad
key has a weakness.  As a secondary challenge, open README in that directory)

If the encryption is truly random letters, and only used once, then it
is impossible to break.  A truly random "One Time Pad" key cannot be
broken.  Consider intercepting a ciphertext message of 1000 bytes.  One
could brute force for the key, but due to the random key nature, you would
produce every single valid 1000 letter plaintext as well.  Who is to know
which is the real plaintext?!?

Choosing keys that are the same size as the plaintext is impractical.
Therefore, other methods must be used to obscure ciphertext against 
frequency analysis in a simple substitution cipher.  The
impracticality of an 'infinite' key means that the randomness, or
entropy, of the encryption is introduced via the method.

We have seen the method of 'substitution'.  Even in modern crypto,
substitution is a valid technique.  Another technique is 'transposition',
or swapping of bytes.

Modern ciphers break into two types; symmetric and asymmetric.

Symmetric ciphers come in two flavours: block and stream.

Until now, we have been playing with classical ciphers, approximating
'block' ciphers.  A block cipher is done in fixed size blocks (suprise!).
For example, in the previous paragraphs we discussed breaking text and keys
into 256 byte blocks, and working on those blocks.  Block ciphers use a
fixed key to perform substituion and transposition ciphers on each
block discretely.

Its time to employ a stream cipher.  A stream cipher attempts to create
an on-the-fly 'random' keystream to encrypt the incoming plaintext one
byte at a time.  Typically, the 'random' key byte is xor'd with the 
plaintext to produce the ciphertext.  If the random keystream can be
replicated at the recieving end, then a further xor will produce the
plaintext once again.

From this example forward, we will be working with bytes, not ASCII 
text, so a hex editor/dumper like hexdump is a necessity.  Now is the
right time to start to learn to use tools like cryptool.

In this example, the keyfile is in your directory, however it is 
not readable by you.  The binary 'encrypt6' is also available.
It will read the keyfile and encrypt any message you desire, using
the key AND a 'random' number.  You get to perform a 'known ciphertext'
attack by introducing plaintext of your choice.  The challenge here is 
not simple, but the 'random' number generator is weak.

As stated, it is now that we suggest you begin to use public tools, like cryptool,
to help in your analysis.  You will most likely need a hint to get going.
See 'HINT1' if you need a kickstart.

If you have further difficulty, there is a hint in 'HINT2'.

The password for level 7 (krypton7) is encrypted with 'encrypt6'.

Good Luck!
```

流密码，可以采用选择明文攻击，弱随机数生成器，建议使用开源工具（如 `cryptool`）辅助分析。

```bash
$ mktemp -d
/tmp/tmp.dUnxjQOLqJ
$ cd /tmp/tmp.dUnxjQOLqJ
$ ln -s /krypton/krypton6/encrypt6
$ ln -s /krypton/krypton6/keyfile.dat
$ chmod 777 .
$ ./encrypt6 
usage: encrypt6 foo bar 
Where: foo is the file containing the plaintext and bar is the destination ciphertext file.
$ cat /krypton/krypton6/krypton7 
PNUKLYLWRQKGKBE
```

`encrypt6` 不处理英文字母以外的字符

```bash
$ echo -n '!#$%^&*()Aa' > plain
$ ./encrypt6 plain cipher
$ cat cipher 
EI
```

首先获取伪随机序列的周期

```bash
$ for i in $(seq 1 64); do echo -n A; done > plain
$ ./encrypt6 plain cipher
$ cat cipher 
EICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICTDGYIYZKTHNSIRFXYCPFUEOCKRNEICT
```

由此可知，伪随机序列的周期为 30 字节

```bash
$ for i in $(seq 1 30); do echo -n B; done > plain
$ ./encrypt6 plain cipher
$ cat cipher 
FJDUEHZJZALUIOTJSGYZDQGVFPDLSO
```

对比 A 和 B 一个周期的加密结果，注意到 B 的加密结果只是在 A 的基础上字母表位置后移了一位（注意不是**异或**，不要被惯性思维带偏了），即 30 个 A 加密的结果就是一个周期的密钥！

```bash
A: EICTDGYIYZKTHNSIRFXYCPFUEOCKRN
B: FJDUEHZJZALUIOTJSGYZDQGVFPDLSO
```

那么直接密文减去密钥就好了！

```py
m, c, k = '', 'PNUKLYLWRQKGKBE', 'EICTDGYIYZKTHNSIRFXYCPFUEOCKRN'
for i in range(len(c)):
    m += chr((26 + ord(c[i]) - ord(k[i])) % 26 + ord('A'))
print(m)
# LFSRISNOTRANDOM
```