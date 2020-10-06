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