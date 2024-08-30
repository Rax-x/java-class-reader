from typing import Any, Iterable
from io import BytesIO
from enum import Enum, auto
import argparse
import sys

GenericDict = dict[str, Any]
Container = list|dict
ListOfDict = list[GenericDict]

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
    ACC_TRANSIENT = 0x0080
    ACC_SYNTHETIC = 0x1000
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


def prettify(data: Container, indent: int = 4, level: int = 1) -> str:

    paren = '[' if isinstance(data, list) else '{'
    end_paren = ']' if paren == '[' else '}'

    s = f"{paren}\n"

    pairs = enumerate(data) if isinstance(data, list) else data.items()

    for key, item in pairs:
        s += f"{' ' * (indent * level)}{key} -> "
        if isinstance(item, (list, dict)):
            s += f"{prettify(item, indent=indent, level=level+1)},\n"
        else:    
            s += f"{item},\n"
    
    s += f"{' ' * (indent * (level-1))}{end_paren}"

    return s

def read_class_file(filename: str) -> bytes:
    with open(filename, mode="rb") as f:
        return f.read()

class BytecodeParser:
    def __init__(self, bytecode: bytes) -> None:
        self.stream = BytesIO(bytecode)
        
    def parse(self) -> GenericDict:
        class_info: GenericDict = {}

        class_info['magic'] = hex(self._read_bytes(4))
        class_info['minor_version'] = self._read_bytes(2)
        class_info['major_version'] = self._read_bytes(2)
        class_info['constant_pool_count'] = self._read_bytes(2)
        class_info['constant_pool'] = self._parse_constant_pool(class_info['constant_pool_count']-1)
        class_info['access_flags'] = self._decode_access_flags(self._read_bytes(2), ClassModifiers)
        class_info['this_class'] = self._read_bytes(2)
        class_info['super_class'] = self._read_bytes(2)
        class_info['interfaces_count'] = self._read_bytes(2)
        class_info['interfaces'] = [self._read_bytes(2) for _ in range(class_info['interfaces_count'])]
        class_info['fields_count'] = self._read_bytes(2)
        class_info['fields'] = self._parse_fields_or_methods(class_info['fields_count'], FieldModifiers)
        class_info['methods_count'] = self._read_bytes(2)
        class_info['methods'] = self._parse_fields_or_methods(class_info['methods_count'], MethodModifiers)
        class_info['attributes_count'] = self._read_bytes(2)
        class_info['attributes'] = self.parse_attributes(class_info['attributes_count'])

        self.stream.close()

        return class_info
    
    def _parse_fields_or_methods(self, size: int, access_flags_constants: Iterable) -> ListOfDict:

        elements: ListOfDict = []

        for _ in range(size):
            element: GenericDict = {}
            element['access_flags'] = self._decode_access_flags(self._read_bytes(2), access_flags_constants)
            element['name_index'] = self._read_bytes(2)
            element['descriptor_index'] = self._read_bytes(2)
            element['attributes_count'] = self._read_bytes(2)
            element['attributes'] = self.parse_attributes(element['attributes_count'])

            elements.append(element)

        return elements
    
    def parse_attributes(self, size: int) -> ListOfDict:
        attributes: ListOfDict = []
        
        for _ in range(size):
            attribute_name_index = self._read_bytes(2)
            attribute_length = self._read_bytes(4)

            attributes.append({
                'attribute_name_index': attribute_name_index,
                'attribute_length': attribute_length,
                'info': self.stream.read(attribute_length)
            })

        return attributes

    def _parse_constant_pool(self, size: int) -> ListOfDict:
        pool: ListOfDict = []

        for _ in range(size):
            tag: ConstantsTag = ConstantsTag(self._read_bytes(1))
            info: GenericDict = { 'tag': tag.name }

            if tag == ConstantsTag.CONSTANT_Class:
                info['name_index'] = self._read_bytes(2)
            elif tag in [ConstantsTag.CONSTANT_Fieldref, ConstantsTag.CONSTANT_Methodref, ConstantsTag.CONSTANT_InterfaceMethodref]:
                info['class_index'] = self._read_bytes(2)
                info['name_and_type_index'] = self._read_bytes(2)
            elif tag == ConstantsTag.CONSTANT_String:
                info['string_index'] = self._read_bytes(2)
            elif tag in [ConstantsTag.CONSTANT_Integer, ConstantsTag.CONSTANT_Float]:
                info['bytes'] = self.stream.read(4)
            elif tag in [ConstantsTag.CONSTANT_Long, ConstantsTag.CONSTANT_Double]:
                info['high_bytes'] = self.stream.read(4)
                info['low_bytes'] = self.stream.read(4)
            elif tag == ConstantsTag.CONSTANT_NameAndType:
                info['name_index'] = self._read_bytes(2)
                info['descriptor_index'] = self._read_bytes(2)
            elif tag == ConstantsTag.CONSTANT_Utf8:
                info['length'] = self._read_bytes(2)
                info['bytes'] = self.stream.read(info['length'])
            elif tag == ConstantsTag.CONSTANT_MethodHandle:
                info['reference_kind'] = self._read_bytes(1)
                info['reference_index'] = self._read_bytes(2)
            elif tag == ConstantsTag.CONSTANT_MethodType:
                info['descriptor_index'] = self._read_bytes(2)
            elif tag == ConstantsTag.CONSTANT_InvokeDynamic:
                info['bootstrap_method_attr_index'] = self._read_bytes(2)
                info['name_and_type_index'] = self._read_bytes(2)
            else:
                raise ValueError(f"Unexpected constant tag '{tag.name}'")

            pool.append(info)
            
        return pool

    def _decode_access_flags(self, access_flags: int, constants: Iterable) -> list[str]:
        modifiers: list[str] = []
        for modifier in constants:
            if (access_flags & modifier.value) != 0:
                modifiers.append(modifier.name)

        return modifiers

    def _read_bytes(self, n: int) -> int:
        return int.from_bytes(self.stream.read(n), 'big')

class BytecodeChecker:
    def __init__(self, class_info: GenericDict) -> None:
        self.class_info: GenericDict = class_info

    def check(self) -> bool:
        index: int = -1

        if int(self.class_info['magic'], 16) != 0xCAFEBABE:
            return False

        index = self.class_info['this_class']
        if not self._check_tag(index, ConstantsTag.CONSTANT_Class):
            return False

        index = self.class_info['super_class']
        if not self._check_tag(index, ConstantsTag.CONSTANT_Class):
            return False

        for info in self.class_info['constant_pool']:
            if not self._check_constant_pool_info(info):
                return False

        if not self._check_interfaces(self.class_info['interfaces']):
            return False

        if (
            not self._check_fields_or_methods(self.class_info['fields']) or
            not self._check_fields_or_methods(self.class_info['methods'])
        ):
            return False

        for attribute in self.class_info['attributes']:
            if not self._check_attribute(attribute):
                return False

        return True

    def _check_tag(self, index: int, tag: ConstantsTag) -> bool:
        info: GenericDict = self.class_info['constant_pool'][index-1]
        return info['tag'] == tag.name

    def _check_attribute(self, attribute: GenericDict) -> bool:
        return self._check_tag(attribute['attribute_name_index'], ConstantsTag.CONSTANT_Utf8)

    def _check_fields_or_methods(self, items: ListOfDict) -> bool:
        for item in items:
            if (
                not self._check_tag(item['name_index'], ConstantsTag.CONSTANT_Utf8) or
                not self._check_tag(item['descriptor_index'], ConstantsTag.CONSTANT_Utf8)
            ):
                return False

            for attr in item['attributes']:
                if not self._check_attribute(attr):
                    return False

        return True

    def _check_interfaces(self, interfaces_indexes: list[int]) -> bool:
        for index in interfaces_indexes:
            if not self._check_tag(index, ConstantsTag.CONSTANT_Class):
                return False

        return True

    def _check_constant_pool_info(self, info: GenericDict) -> bool:
        tag: ConstantsTag = ConstantsTag[info['tag']]

        if tag == ConstantsTag.CONSTANT_Class:
            if not self._check_tag(info['name_index'], ConstantsTag.CONSTANT_Utf8):
                return False
        elif tag in [ConstantsTag.CONSTANT_Fieldref, ConstantsTag.CONSTANT_Methodref, ConstantsTag.CONSTANT_InterfaceMethodref]:
            if not self._check_tag(info['class_index'], ConstantsTag.CONSTANT_Class):
                return False
            
            if not self._check_tag(info['name_and_type_index'], ConstantsTag.CONSTANT_NameAndType):
                return False
        elif tag == ConstantsTag.CONSTANT_String:
            if not self._check_tag(info['string_index'], ConstantsTag.CONSTANT_Utf8):
                return False
        elif tag == ConstantsTag.CONSTANT_NameAndType:
            if (
                not self._check_tag(info['name_index'], ConstantsTag.CONSTANT_Utf8) and 
                not self._check_tag(info['descriptor_index'], ConstantsTag.CONSTANT_Utf8)
            ):
                return False
        elif tag == ConstantsTag.CONSTANT_MethodHandle:

            # Documentation: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-4.html#jvms-4.4.8
            
            reference_kind: int = info['reference_kind']
            
            if reference_kind not in range(1, 10):
                return False
            
            index: int = info['reference_index']

            if reference_kind in range(1, 5):
                if not self._check_tag(index, ConstantsTag.CONSTANT_Fieldref):
                    return False
            elif reference_kind in range(5, 10):
                tag = ConstantsTag.CONSTANT_Methodref if reference_kind != 9 else ConstantsTag.CONSTANT_InterfaceMethodref
            
                if not self._check_tag(index, tag):
                    return False

                pool: ListOfDict = self.class_info['constant_pool']
                name_type_index: int = pool[index-1]['name_and_type_index']
                name_index: int = pool[name_type_index-1]['name_index']
                
                name: str = pool[name_index-1]['bytes'].decode('ascii')

                if reference_kind in [5, 6, 7, 9]:
                    if name in ['<init>', '<clinit>']:
                        return False
                else:
                    # In this case the only value is 8
                    if name != '<init>':
                        return False
        elif tag == ConstantsTag.CONSTANT_MethodType:
            if not self._check_tag(info['descriptor_index'], ConstantsTag.CONSTANT_Utf8):
                return False
        elif tag == ConstantsTag.CONSTANT_InvokeDynamic:
            if not self._check_tag(info['name_and_type_index'], ConstantsTag.CONSTANT_NameAndType):
                return False

        return True

def main() -> None:

    args_parser = argparse.ArgumentParser()
    
    args_parser.add_argument(
        "file", 
        help="Java compiled .class file",
        type=str
    )

    args_parser.add_argument(
        "-c", "--check",
        help="Check if parsing was successful",
        action="store_true"
    )

    args_parser.add_argument(
        "-d", "--dump", 
        help="Save output in a text file with same name of .class file",
        action="store_true"
    )

    args = args_parser.parse_args()

    try:
        if not args.file.endswith(".class"):
            raise ValueError("Invalid file (Wrong file format).")

        bytecode: bytes = read_class_file(args.file)
        bytecode_parser: BytecodeParser = BytecodeParser(bytecode)
        
        parsed_bytecode: GenericDict = bytecode_parser.parse()

        if args.check:
            bytecode_checker: BytecodeChecker = BytecodeChecker(parsed_bytecode)
            if not bytecode_checker.check():
                print("An error occurred during parsing, try to check if .class file isn't corrupted.")
                exit(-1)

        output: str = prettify(parsed_bytecode)

        if args.dump:
            filename: str = f"{args.file[:-5]}txt"
            with open(filename, "w") as f:
                f.write(output)
        else:
           print(output)

    except Exception as ex:
        print(sys.exc_info())
        print(str(ex))  

if __name__ == '__main__':
    main()
