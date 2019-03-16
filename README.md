# pySFDL_wget
download SFDLs with python and Wget

# Usage
simpel download
```sh
python <file.sfdl> <password
```

download multi files with find and xargs
```sh
find -iname '*.sfdl' -type f -print0 |xargs -0i -P4 python "{}" password123
```

# install on termux (android)
```sh
pkg install wget
pkg install clang
pkg install libgmp-dev
pkg install python2
pkg install pip2
pip2 install pycrypto
pip2 install simplejson
wget https://github.com/e1nMann/pySFDL_wget/archive/master.tar.gz
tar xfvz master.tar.gz
rm master.tar.gz
cd pySFDL_wget-master
python2 pySFDL_wget.py
```
to download with an socks5 proxy, you need proxychains
```sh
pkg install tor
tor > log &
pkg install proxychains-ng
```
then edit the `$HOME/../usr/etc/proxychains.fong` at the end of file replace tor socks4 to socks5
now you can start pySFDL with it:
```sh
proxychains4 python2 pySFDL.py <filename.sfdl> <password>
```


have fun!

# Info
* author: e1nMann
* date: 14.03.2019
