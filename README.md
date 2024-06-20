# DeObfBr

使用unicorn去除BR混淆

## 用法
```
usage: debr.py [-h] -f FILE -s START -e END [-o OUTPUT]

options:
  -h, --help            show this help message and exit
  -f FILE, --file FILE  The name of the library.
  -s START, --start START
                        The start address of the function.
  -e END, --end END     The end address of the function.
  -o OUTPUT, --output OUTPUT
                        The output file.
```


## 示例


### libtprt
python debr.py -f libtprt.so -s 63884 -e 63C9C

#### 使用前:

CFG:

![alt text](img/5.png)

F5:

![alt text](img/6.png)


#### 使用后:

CFG:

![alt text](img/8.png)

F5:

![alt text](img/7.png)


### libtersafe
python debr.py -f libtersafe.so -s 1BDC58 -e 1BDE3C

#### 使用前:
CFG:

![alt text](img/4.png)

F5:

![alt text](img/1.png)


#### 使用后:
CFG:

![alt text](img/3.png)

F5:

![alt text](img/2.png)

