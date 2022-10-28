from sys import argv
from typing import Any, List
from io import BytesIO
from enum import Enum

GenericDict = dict[str, Any]
Container = list|dict
ListOfDict = list[GenericDict]

# TODO: fix bugs with fields parser
#   -- Add a verifier who checks if indexes are valid in constant pool (maybe in a another module???? idk)
#   -- Write a "decoder" for access_flags
#       -- Add access_flags constants for fields

class ClassModifiers(Enum):
    ACC_PUBLIC = 0x0001
    ACC_FINAL = 0x0010
    ACC_SUPER = 0x0020
    ACC_INTERFACE = 0x0200
    ACC_ABSTRACT = 0x0400
    ACC_SYNTHETIC = 0x1000
    ACC_ANNOTATION = 0x2000
    ACC_ENUM = 0x4000

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

    def __get_pairs(self, data: Container):
        if isinstance(data, dict):
            return data.items()
        return enumerate(data)

    def __prettify(self, items: Container, level: int = 1) -> str:

        symbol = '[' if isinstance(items, list) else '{'
        end_symbol = ']' if symbol == '[' else '}'

        s = f"{symbol}\n"

        pairs = self.__get_pairs(items)

        for key, item in pairs:
            s += f"{' ' * (self.indent * level)}{key} -> "
            if isinstance(item, (list, dict)):
                s += f"{self.__prettify(item, level=level+1)},\n"
            else:    
                s += f"{item},\n"
        
        s += f"{' ' * (self.indent * (level-1))}{end_symbol}"
        return s

    def print(self, data: Any) -> None:
        print(self.__prettify(data))

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
        clazz['constant_pool'] = self.parse_constant_pool(clazz['constant_pool_count'])
        clazz['access_flags'] = hex(self.parse_bytes(2) )
        clazz['this_class'] = self.parse_bytes(2)
        clazz['super_class'] = self.parse_bytes(2)
        clazz['interfaces_count'] = self.parse_bytes(2)
        clazz['interfaces'] = [self.parse_bytes(2)-1 for _ in range(clazz['interfaces_count'])]
        clazz['fields_count'] = self.parse_bytes(2)
        clazz['fields'] = self.parse_fields(clazz['fields_count'])

        self.f.close()

        return clazz
        
    def parse_fields(self, size: int) -> ListOfDict:
        fields: ListOfDict = []

        for _ in range(size):
            field: GenericDict = {}
            field['access_flags'] = self.parse_bytes(2)
            field['name_index'] = self.parse_bytes(2)
            field['descriptor_index'] = self.parse_bytes(2)
            field['attributes_count'] = self.parse_bytes(2)
            field['attributes'] = self.parse_attributes(field['attributes_count'])

            fields.append(field)

        return fields
    
    def parse_attributes(self, size: int) -> ListOfDict:
        attributes: ListOfDict = []
        
        for _ in range(size):
            attribute_name_index = self.parse_bytes(2)
            attribute_length = self.parse_bytes(4)

            attributes.append(
                {
                    'attribute_name_index': attribute_name_index,
                    'attribute_length': attribute_length,
                    'info': [self.parse_bytes(1) for _ in range(attribute_length)]
                }
            )

        return attributes

    def parse_constant_pool(self, size) -> ListOfDict:
        pool: ListOfDict = []
        for _ in range(size - 1):
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

    def parse_bytes(self, n: int) -> int:
        return int.from_bytes(self.f.read(n), 'big')


def main(argv: list[str]) -> None:
    if len(argv) == 1:
        print(f"Usage: {argv[0]} <*.class file>")
        exit(-1)
    else:
        files = argv[1:]

        printer = CustomPrettyPrinter()

        for file in files:
            bytecode = read_class_file(file)
            analyzer = BytecodeAnalyzer(bytecode)
            printer.print(analyzer.analyze())
            

if __name__ == '__main__':
    main(argv)