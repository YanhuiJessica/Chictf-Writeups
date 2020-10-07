---
title: OverTheWire：Natas
---

## Level 0

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas0</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>natas0</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas0.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 提示：`You can find the password for the next level on this page.`
- 使用开发者工具查看页面源代码即可获得下一关的口令<br>
![gtVrDuiDfck831PqWsLEZy5gyDz1clto](img/natas01.jpg)

## Level 1

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas1</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>gtVrDuiDfck831PqWsLEZy5gyDz1clto</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas1.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 提示：`You can find the password for the next level on this page, but rightclicking has been blocked!`（但是咕咕几乎不怎么用右键查看页面源代码的(╮ŏωŏ)╭）
- 使用开发者工具查看页面源代码即可获得下一关的口令<br>
![ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi](img/natas02.jpg)

## Level 2

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas2</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>ZluruAthQk7Q2MqmDeTiUij2ZvWy2mBi</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas2.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 提示：`There is nothing on this page`
- 查看页面源代码，发现使用了一张`files`路径下的图片（因为只有 1X1 的大小，所以页面上看不到）<br>
![src="files/pixel.png"](img/natas03.jpg)
- 访问 http://natas2.natas.labs.overthewire.org/files ，发现该路径下还有一个 *users.txt* 文件，查看该文件获得用户 *natas3* 的口令
  ```
  # username:password
  alice:BYNdCesZqW
  bob:jw2ueICLvT
  charlie:G5vCxkVV3m
  natas3:sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14
  eve:zo4mJWyNj2
  mallory:9urtcpzBmH
  ```

## Level 3

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas3</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>sJIJNW6ucpu6HPZ1ZAchaDtwd7oGrD14</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas3.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 这次页面上依然是`There is nothing on this page`，查看页面源代码，发现一段注释信息：`No more information leaks!! Not even Google will find it this time...`
- 嗯？怎么能让谷歌抓取不到网站的？
  > 网站所有者可以详细规定处理其网页的方式，申请重新抓取，或使用 robots.txt 文件完全禁止谷歌抓取工具抓取他们的网站

- 访问 http://natas3.natas.labs.overthewire.org/robots.txt ，查看 *robots.txt* 文件
  ```bash
  # 禁止所有爬虫爬取路径 /s3cr3t
  User-agent: *
  Disallow: /s3cr3t/
  ```
- 目标指向 http://natas3.natas.labs.overthewire.org/s3cr3t/ ，访问可查看到该路径下的一个 *users.txt* 文件，其中包含下一关的口令
  ```
  natas4:Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ
  ```

### 参考资料

- [Google 搜索的工作方式 | 抓取和编入索引](https://www.google.com/intl/zh-CN/search/howsearchworks/crawling-indexing/)
- [Robots.txt Specifications  |  Search for Developers  |  Google Developers](https://developers.google.com/search/reference/robots_txt)

## Level 4

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas4</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>Z9tkRkWmpt9Qr7XrR5jWRkgOU901swEZ</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas4.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 进入后提示<br>
![Access disallowed.](img/natas04.jpg)
- 点击 *Refresh page* 后，从 http://natas4.natas.labs.overthewire.org 进入 http://natas4.natas.labs.overthewire.org/index.php ，且提示文本发生变化<br>
![You are visiting from "http://natas4.natas.labs.overthewire.org/"](img/natas05.jpg)
- 在 HTTP 请求头中包含 *Referer* 字段，用于标识访问来源，提示信息中 *visit from* 的意义与值均与 *Referer* 字段相同，那么将 *Referer* 字段的值改为`http://natas5.natas.labs.overthewire.org/`，再次发送 HTTP 请求即可<br>
![修改 Referer 字段](img/natas06.jpg)<br>
![iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq](img/natas07.jpg)

## Level 5

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas5</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>iX6IOfmpN7AYOQGPwtn3fXpbaJVJcHfq</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas5.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 进入后提示没有登录！(╥ω╥)<br>
![You are not logged in](img/natas08.jpg)
- 查看 HTTP 请求头，发现 *Cookie* 字段为`loggedin=0`，非常可疑(—ˋωˊ—)！<br>
![Cookie: loggedin=0](img/natas09.jpg)
- 将`loggedin=0`修改为`loggedin=1`并发送 HTTP 请求，成功登录！<br>
![The password for natas6 is aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1](img/natas10.jpg)

## Level 6

<table>
<tbody>
  <tr>
    <td>Username</td>
    <td>natas6</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>Password</td>
    <td>aGoY4q2Dc6MgDq4oL4YtoKtyAg9PeHa1</td>
  </tr>
</tbody>
<tbody>
  <tr>
    <td>URL</td>
    <td>http://natas6.natas.labs.overthewire.org</td>
  </tr>
</tbody>
</table>

- 出现输入框了！<br>
![Input secret](img/natas11.jpg)
- 先看看源代码
  ```html
  <html>
  <head>
  <!-- This stuff in the header has nothing to do with the level -->
  </head>
  <body>
  <h1>natas6</h1>
  <div id="content">

  <?

  include "includes/secret.inc";
  # 使用的是相对路径

      if(array_key_exists("submit", $_POST)) {
          # 需要知道 $secret 的值
          if($secret == $_POST['secret']) {
          print "Access granted. The password for natas7 is <censored>";
      } else {
          print "Wrong secret";
      }
      }
  ?>

  <form method=post>
  Input secret: <input name=secret><br>
  <input type=submit name=submit>
  </form>

  <div id="viewsource"><a href="index-source.html">View sourcecode</a></div>
  </div>
  </body>
  </html>
  ```
- 注意到 *include* 文件使用的是相对路径，访问 http://natas6.natas.labs.overthewire.org/includes/secret.inc ，在网页源代码中看到变量 *$secret* 的值<br>
![FOEIUWGHFEEUHOFUOIU](img/natas12.jpg)
- 回到 http://natas6.natas.labs.overthewire.org ，输入密码，获得 *natas7* 的口令<br>
![Access granted. The password for natas7 is 7z3hEENjQtflzgnT29q7wAvMNfZdh0i9](img/natas13.jpg)