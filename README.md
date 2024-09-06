# Java Class Reader

This is a simple python script that reads Java `.class` file and print its contents on stdout or a specified output.
The idea of this project comes from the series of videos by [Tsoding](https://github.com/tsoding) about 
[JelloVM](https://github.com/tsoding/JelloVM).

> [!WARNING]  
> The script actually parses only some attributes like `Code` or `ConstantValue`.
> The parsing of the other attributes is still a work in progress.

> [!IMPORTANT]
> The reader follows the Java 8 specification.
> There is no guarantee that it will work correctly with newer versions of Java.

## Usage

```
usage: main.py [-h] [-d] file

positional arguments:
  file         Java compiled .class file

options:
  -h, --help   show this help message and exit
  -d, --dump   Save output in a text file with same name of .class file
```

### Resources
- [Java class File Format](https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html)
- [Java bytecode instructions](https://en.wikipedia.org/wiki/List_of_Java_bytecode_instructions)
- [Java attributes](https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.7)