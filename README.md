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

have fun!

# Info
* author: e1nMann
* date: 14.03.2019
