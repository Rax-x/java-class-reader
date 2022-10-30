from typing import Any, Iterable
from io import BytesIO
from enum import Enum
import argparse

from click import FileError

GenericDict = dict[str, Any]
Container = list|dict
ListOfDict = list[GenericDict]

# TODO:
#   -- Add a verifier who checks if indexes are valid in constant pool


class ClassModifiers(Enum):
    ACC_PUBLIC = 0x0001
    ACC_FINAL = 0x0010
    ACC_SUPER = 0x0020
    ACC_INTERFACE = 0x0200
    ACC_ABSTRACT = 0x0400
    ACC_SYNTHETIC = 0x1000
    ACC_ANNOTATION = 0x2000
    ACC_ENUM = 0x4000

class FieldModifiers(Enum):
    ACC_PUBLIC = 0x0001
    ACC_PRIVATE = 0x0002
    ACC_PROTECTED = 0x0004
    ACC_STATIC = 0x0008
    ACC_FINAL = 0x0010
    ACC_VOLATILE = 0x0040
    ACC_TRANSIENT =	0x0080
    ACC_SYNTHETIC =	0x1000
    ACC_ENUM = 0x4000

class MethodModifiers(Enum):
    ACC_PUBLIC = 0x0001	
    ACC_PRIVATE	= 0x0002
    ACC_PROTECTED = 0x0004	
    ACC_STATIC = 0x0008	
    ACC_FINAL = 0x0010
    ACC_SYNCHRONIZED = 0x0020	
    ACC_BRIDGE = 0x0040	
    ACC_VARARGS = 0x0080	
    ACC_NATIVE = 0x0100	
    ACC_ABSTRACT = 0x0400	
    ACC_STRICT = 0x0800	
    ACC_SYNTHETIC = 0x1000

class ConstantsTag(Enum):
    CONSTANT_Class = 7
    CONSTANT_Fieldref = 9
    CONSTANT_Methodref = 10
    CONSTANT_InterfaceMethodref = 11
    CONSTANT_String = 8
    CONSTANT_Integer = 3
    CONSTANT_Float = 4
    CONSTANT_Long = 5
    CONSTANT_Double = 6
    CONSTANT_NameAndType = 12
    CONSTANT_Utf8 = 1
    CONSTANT_MethodHandle = 15
    CONSTANT_MethodType = 16
    CONSTANT_InvokeDynamic = 18

class CustomPrettyPrinter:
    def __init__(self, indent: int = 4) -> None:
        self.indent = indent

    def get_pairs(self, data: Container):
        if isinstance(data, dict):
            return data.items()
        return enumerate(data)

    def prettify(self, items: Container, level: int = 1) -> str:

        symbol = '[' if isinstance(items, list) else '{'
        end_symbol = ']' if symbol == '[' else '}'

        s = f"{symbol}\n"

        pairs = self.get_pairs(items)

        for key, item in pairs:
            s += f"{' ' * (self.indent * level)}{key} -> "
            if isinstance(item, (list, dict)):
                s += f"{self.prettify(item, level=level+1)},\n"
            else:    
                s += f"{item},\n"
        
        s += f"{' ' * (self.indent * (level-1))}{end_symbol}"
        return s

    def print(self, data: Any) -> None:
        print(self.prettify(data))

def read_class_file(filename: str) -> bytes:
    with open(filename, mode="rb") as f:
        return f.read()

class BytecodeAnalyzer:
    def __init__(self, bytecode: bytes) -> None:
        self.f = BytesIO(bytecode)
        
    def analyze(self) -> GenericDict:
        clazz: GenericDict = {}
        clazz['magic'] = hex(self.parse_bytes(4))
        clazz['minor_version'] = self.parse_bytes(2)
        clazz['major_version'] = self.parse_bytes(2)
        clazz['constant_pool_count'] = self.parse_bytes(2)
        clazz['constant_pool'] = self.parse_constant_pool(clazz['constant_pool_count']-1)
        clazz['access_flags'] = self.decode_access_flags(self.parse_bytes(2), ClassModifiers)
        clazz['this_class'] = self.parse_bytes(2)
        clazz['super_class'] = self.parse_bytes(2)
        clazz['interfaces_count'] = self.parse_bytes(2)
        clazz['interfaces'] = [self.parse_bytes(2) for _ in range(clazz['interfaces_count'])]
        clazz['fields_count'] = self.parse_bytes(2)
        clazz['fields'] = self.parse_fields_or_methods(clazz['fields_count'], FieldModifiers)
        clazz['methods_count'] = self.parse_bytes(2)
        clazz['methods'] = self.parse_fields_or_methods(clazz['methods_count'], MethodModifiers)
        clazz['attributes_count'] = self.parse_bytes(2)
        clazz['attributes'] = self.parse_attributes(clazz['attributes_count'])

        self.f.close()

        return clazz
        
    def parse_methods(self, size: int) -> ListOfDict:
        return []
    
    def parse_fields_or_methods(self, size: int, access_flags_constants: Iterable) -> ListOfDict:
        items: ListOfDict = []

        for _ in range(size):
            item: GenericDict = {}
            item['access_flags'] = self.decode_access_flags(self.parse_bytes(2), access_flags_constants)
            item['name_index'] = self.parse_bytes(2)
            item['descriptor_index'] = self.parse_bytes(2)
            item['attributes_count'] = self.parse_bytes(2)
            item['attributes'] = self.parse_attributes(item['attributes_count'])

            items.append(item)

        return items
    
    def parse_attributes(self, size: int) -> ListOfDict:
        attributes: ListOfDict = []
        
        for _ in range(size):
            attribute_name_index = self.parse_bytes(2)
            attribute_length = self.parse_bytes(4)

            attributes.append(
                {
                    'attribute_name_index': attribute_name_index,
                    'attribute_length': attribute_length,
                    'info': self.f.read(attribute_length)
                }
            )

        return attributes

    def parse_constant_pool(self, size: int) -> ListOfDict:
        pool: ListOfDict = []
        for _ in range(size):
            tag = ConstantsTag(self.parse_bytes(1))
            info: GenericDict = { 'tag': tag.name }
            if tag == ConstantsTag.CONSTANT_Class:
                info['name_index'] = self.parse_bytes(2)
            elif tag in [ConstantsTag.CONSTANT_Fieldref, ConstantsTag.CONSTANT_Methodref, ConstantsTag.CONSTANT_InterfaceMethodref]:
                info['class_index'] = self.parse_bytes(2)
                info['name_and_type_index'] = self.parse_bytes(2)
            elif tag == ConstantsTag.CONSTANT_String:
                info['string_index'] = self.parse_bytes(2)
            elif tag in [ConstantsTag.CONSTANT_Integer, ConstantsTag.CONSTANT_Float]:
                info['bytes'] = self.f.read(4)
            elif tag in [ConstantsTag.CONSTANT_Long, ConstantsTag.CONSTANT_Double]:
                info['high_bytes'] = self.f.read(4)
                info['low_bytes'] = self.f.read(4)
            elif tag == ConstantsTag.CONSTANT_NameAndType:
                info['name_index'] = self.parse_bytes(2)
                info['descriptor_index'] = self.parse_bytes(2)
            elif tag == ConstantsTag.CONSTANT_Utf8:
                info['length'] = self.parse_bytes(2)
                info['bytes'] = self.f.read(info['length'])
            elif tag == ConstantsTag.CONSTANT_MethodHandle:
                info['reference_kind'] = self.parse_bytes(1)
                info['reference_index'] = self.parse_bytes(2)
            elif tag == ConstantsTag.CONSTANT_MethodType:
                info['descriptor_index'] = self.parse_bytes(2)
            elif tag == ConstantsTag.CONSTANT_InvokeDynamic:
                info['bootstrap_method_attr_index'] = self.parse_bytes(2)
                info['name_and_type_index'] = self.parse_bytes(2)
            else:
                raise NotImplementedError(f"Unexpected constant tag '{tag.name}'")

            pool.append(info)
            
        return pool

    def decode_access_flags(self, access_flags: int, constants: Iterable) -> list[str]:
        modifiers: list[str] = []
        for modifier in constants:
            if (access_flags & modifier.value) != 0:
                modifiers.append(modifier.name)
        
        return modifiers

    def parse_bytes(self, n: int) -> int:
        return int.from_bytes(self.f.read(n), 'big')

class BytecodeVerifier:
    def __init__(self, parsed_bytecode: GenericDict) -> None:
        self.bytecode: GenericDict = parsed_bytecode

    def verify(self) -> None:
        pass

def main() -> None:

    parser = argparse.ArgumentParser()
    
    parser.add_argument(
        "file", 
        help="Java compiled .class file",
        type=str
    )

    parser.add_argument(
        "-c", "--check",
        help="Check if bytecode is valid",
        action="store_true"
    )

    parser.add_argument(
        "-d", "--dump", 
        help="Save output in a text file with same name of .class file",
        action="store_true"
    )

    args = parser.parse_args()

    try:
        if not args.file.endswith(".class"):
            raise Exception("Invalid file (Wrong file format).")

        bytecode: bytes = read_class_file(args.file)
        analyzer: BytecodeAnalyzer = BytecodeAnalyzer(bytecode)
        
        output = analyzer.analyze()

        if args.check:
            verifier: BytecodeVerifier = BytecodeVerifier(output)
            verifier.verify()

        printer: CustomPrettyPrinter = CustomPrettyPrinter()

        if args.dump:
            filename: str = f"{args.file[:-5]}txt"
            with open(filename, "w") as f:
                f.write(printer.prettify(output))
        else:
            printer.print(output)

    except Exception as ex:
        print(ex)  

if __name__ == '__main__':
    main()