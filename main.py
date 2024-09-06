from typing import Any, Iterable
from io import BytesIO
from enum import Enum
import argparse

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

    if len(data) == 0:
        return f"{paren}{end_paren}"

    output = f"{paren}\n"

    pairs = enumerate(data, start=1) if isinstance(data, list) else data.items()

    for key, item in pairs:
        output += f"{' ' * (indent * level)}{key} -> "
        if isinstance(item, (list, dict)):
            output += f"{prettify(item, indent=indent, level=level+1)},\n"
        else:    
            output += f"{item},\n"
    
    output += f"{' ' * (indent * (level-1))}{end_paren}"

    return output

def read_class_file(filename: str) -> bytes:
    with open(filename, mode="rb") as f:
        return f.read()

class BytecodeDisassembler:
    def __init__(self, bytecode: bytes) -> None:
        self.bytecode: bytes = bytecode
        self.offset: int = 0

    def dissassemble(self) -> list[str]:
        instructions: list[str] = []
        length: int = len(self.bytecode)

        while self.offset < length:
            inst = self._dissassemble_instruction()

            if inst != None:
                instructions.append(inst)

        return instructions

    def _dissassemble_instruction(self) -> str | None:
        match self._read_byte():
            case 0x32:
                return self._simple_instruction("aaload")
            case 0x53:
                return self._simple_instruction("aastore")
            case 0x01:
                return self._simple_instruction("aconst_null")
            case 0x19:
                return self._byte_instruction("aload")
            case 0x2a:
                return self._simple_instruction("aload_0")
            case 0x2b:
                return self._simple_instruction("aload_1")
            case 0x2c:
                return self._simple_instruction("aload_2")
            case 0x2d:
                return self._simple_instruction("aload_3")
            case 0xbd:
                return self._short_instruction("anewarray")
            case 0xb0:
                return self._simple_instruction("areturn")
            case 0xbe:
                return self._simple_instruction("arraylength")
            case 0x3a:
                return self._byte_instruction("astore")
            case 0x4b:
                return self._simple_instruction("astore_0")
            case 0x4c:
                return self._simple_instruction("astore_1")
            case 0x4d:
                return self._simple_instruction("astore_2")
            case 0x4e:
                return self._simple_instruction("astore_3")
            case 0xbf:
                return self._simple_instruction("athrow")
            case 0x33:
                return self._simple_instruction("baload")
            case 0x54:
                return self._simple_instruction("bastore")
            case 0x10:
                return self._byte_instruction("bipush")
            case 0xca:
                return self._simple_instruction("breakpoint")
            case 0x34:
                return self._simple_instruction("caload")
            case 0x55:
                return self._simple_instruction("castore")
            case 0xc0:
                return self._short_instruction("checkcast")
            case 0x90:
                return self._simple_instruction("d2f")
            case 0x8e:
                return self._simple_instruction("d2i")
            case 0x8f:
                return self._simple_instruction("d2l")
            case 0x63:
                return self._simple_instruction("dadd")
            case 0x31:
                return self._simple_instruction("daload")
            case 0x52:
                return self._simple_instruction("dastore")
            case 0x98:
                return self._simple_instruction("dcmpg")
            case 0x97:
                return self._simple_instruction("dcmpl")
            case 0x0e:
                return self._simple_instruction("dconst_0")
            case 0x0f:
                return self._simple_instruction("dconst_1")
            case 0x6f:
                return self._simple_instruction("ddiv")
            case 0x18:
                return self._byte_instruction("dload")
            case 0x26:
                return self._simple_instruction("dload_0")
            case 0x27:
                return self._simple_instruction("dload_1")
            case 0x28:
                return self._simple_instruction("dload_2")
            case 0x29:
                return self._simple_instruction("dload_3")
            case 0x6b:
                return self._simple_instruction("dmul")
            case 0x77:
                return self._simple_instruction("dneg")
            case 0x73:
                return self._simple_instruction("drem")
            case 0xaf:
                return self._simple_instruction("dreturn")
            case 0x39:
                return self._byte_instruction("dstore")
            case 0x47:
                return self._simple_instruction("dstore_0")
            case 0x48:
                return self._simple_instruction("dstore_1")
            case 0x49:
                return self._simple_instruction("dstore_2")
            case 0x4a:
                return self._simple_instruction("dstore_3")
            case 0x67:
                return self._simple_instruction("dsub")
            case 0x59:
                return self._simple_instruction("dup")
            case 0x5a:
                return self._simple_instruction("dup_x1")
            case 0x5b:
                return self._simple_instruction("dup_x2")
            case 0x5c:
                return self._simple_instruction("dup2")
            case 0x5d:
                return self._simple_instruction("dup2_x1")
            case 0x5e:
                return self._simple_instruction("dup2_x2")
            case 0x8d:
                return self._simple_instruction("f2d")
            case 0x8b:
                return self._simple_instruction("f2i")
            case 0x8c:
                return self._simple_instruction("f2l")
            case 0x62:
                return self._simple_instruction("fadd")
            case 0x30:
                return self._simple_instruction("faload")
            case 0x51:
                return self._simple_instruction("fastore")
            case 0x96:
                return self._simple_instruction("fcmpg")
            case 0x95:
                return self._simple_instruction("fcmpl")
            case 0x0b:
                return self._simple_instruction("fconst_0")
            case 0x0c:
                return self._simple_instruction("fconst_1")
            case 0x0d:
                return self._simple_instruction("fconst_2")
            case 0x6e:
                return self._simple_instruction("fdiv")
            case 0x17:
                return self._byte_instruction("fload")
            case 0x22:
                return self._simple_instruction("fload_0")
            case 0x23:
                return self._simple_instruction("fload_1")
            case 0x24:
                return self._simple_instruction("fload_2")
            case 0x25:
                return self._simple_instruction("fload_3")
            case 0x6a:
                return self._simple_instruction("fmul")
            case 0x76:
                return self._simple_instruction("fneg")
            case 0x72:
                return self._simple_instruction("frem")
            case 0xae:
                return self._simple_instruction("freturn")
            case 0x38:
                return self._byte_instruction("fstore")
            case 0x43:
                return self._simple_instruction("fstore_0")
            case 0x44:
                return self._simple_instruction("fstore_1")
            case 0x45:
                return self._simple_instruction("fstore_2")
            case 0x46:
                return self._simple_instruction("fstore_3")
            case 0x66:
                return self._simple_instruction("fsub")
            case 0xb4:
                return self._short_instruction("getfield")
            case 0xb2:
                return self._short_instruction("getstatic")
            case 0xa7:
                return self._short_instruction("goto")
            case 0xc8:
                return f"goto_w {self._read_int()}"
            case 0x91:
                return self._simple_instruction("i2b")
            case 0x92:
                return self._simple_instruction("i2c")
            case 0x87:
                return self._simple_instruction("i2d")
            case 0x86:
                return self._simple_instruction("i2f")
            case 0x85:
                return self._simple_instruction("i2l")
            case 0x93:
                return self._simple_instruction("i2s")
            case 0x60:
                return self._simple_instruction("iadd")
            case 0x2e:
                return self._simple_instruction("iaload")
            case 0x7e:
                return self._simple_instruction("iand")
            case 0x4f:
                return self._simple_instruction("iastore")
            case 0x02:
                return self._simple_instruction("iconst_m1")
            case 0x03:
                return self._simple_instruction("iconst_0")
            case 0x04:
                return self._simple_instruction("iconst_1")
            case 0x05:
                return self._simple_instruction("iconst_2")
            case 0x06:
                return self._simple_instruction("iconst_3")
            case 0x07:
                return self._simple_instruction("iconst_4")
            case 0x08:
                return self._simple_instruction("iconst_5")
            case 0x6c:
                return self._simple_instruction("idiv")
            case 0xa5:
                return self._short_instruction("if_acmpeq")
            case 0xa6:
                return self._short_instruction("if_acmpne")
            case 0x9f:
                return self._short_instruction("if_icmpeq")
            case 0xa2:
                return self._short_instruction("if_icmpge")
            case 0xa3:
                return self._short_instruction("if_icmpgt")
            case 0xa4:
                return self._short_instruction("if_icmple")
            case 0xa1:
                return self._short_instruction("if_icmplt")
            case 0xa0:
                return self._short_instruction("if_icmpne")
            case 0x99:
                return self._short_instruction("ifeq")
            case 0x9c:
                return self._short_instruction("ifge")
            case 0x9d:
                return self._short_instruction("ifgt")
            case 0x9e:
                return self._short_instruction("ifle")
            case 0x9b:
                return self._short_instruction("iflt")
            case 0x9a:
                return self._short_instruction("ifne")
            case 0xc7:
                return self._short_instruction("ifnonnull")
            case 0xc6:
                return self._short_instruction("ifnull")
            case 0x84:
                index: int = self._read_byte()
                count: int = self._read_byte()
                
                return f"iinc {index} {count}"
            case 0x15:
                return self._byte_instruction("iload")
            case 0x1a:
                return self._simple_instruction("iload_0")
            case 0x1b:
                return self._simple_instruction("iload_1")
            case 0x1c:
                return self._simple_instruction("iload_2")
            case 0x1d:
                return self._simple_instruction("iload_3")
            case 0xfe:
                return self._simple_instruction("impdep1")
            case 0xff:
                return self._simple_instruction("impdep2")
            case 0x68:
                return self._simple_instruction("imul")
            case 0x74:
                return self._simple_instruction("ineg")
            case 0xc1:
                return self._short_instruction("instanceof")
            case 0xba:
                index = self._read_short()
                return f"invokedynamic {index} {self._read_byte()} {self._read_byte()}"
            case 0xb9:
                index = self._read_short()
                count = self._read_byte()
                return f"invokeinterface {index} {count} {self._read_byte()}"
            case 0xb7:
                return self._short_instruction("invokespecial")
            case 0xb8:
                return self._short_instruction("invokestatic")
            case 0xb6:
                return self._short_instruction("invokevirtual")
            case 0x80:
                return self._simple_instruction("ior")
            case 0x70:
                return self._simple_instruction("irem")
            case 0xac:
                return self._simple_instruction("ireturn")
            case 0x78:
                return self._simple_instruction("ishl")
            case 0x7a:
                return self._simple_instruction("ishr")
            case 0x36:
                return self._byte_instruction("istore")
            case 0x3b:
                return self._simple_instruction("istore_0")
            case 0x3c:
                return self._simple_instruction("istore_1")
            case 0x3d:
                return self._simple_instruction("istore_2")
            case 0x3e:
                return self._simple_instruction("istore_3")
            case 0x64:
                return self._simple_instruction("isub")
            case 0x7c:
                return self._simple_instruction("iushr")
            case 0x82:
                return self._simple_instruction("ixor")
            case 0xa8:
                return self._short_instruction("jsr")
            case 0xc9:
                return f"jsr_w {self._read_int()}"
            case 0x8a:
                return self._simple_instruction("l2d")
            case 0x89:
                return self._simple_instruction("l2f")
            case 0x88:
                return self._simple_instruction("l2i")
            case 0x61:
                return self._simple_instruction("ladd")
            case 0x2f:
                return self._simple_instruction("laload")
            case 0x7f:
                return self._simple_instruction("land")
            case 0x50:
                return self._simple_instruction("lastore")
            case 0x94:
                return self._simple_instruction("lcmp")
            case 0x09:
                return self._simple_instruction("lconst_0")
            case 0x0a:
                return self._simple_instruction("lconst_1")
            case 0x12:
                return self._byte_instruction("ldc")
            case 0x13:
                return self._short_instruction("ldc_w")
            case 0x14:
                return self._short_instruction("ldc2_w")
            case 0x6d:
                return self._simple_instruction("ldiv")
            case 0x16:
                return self._byte_instruction("lload")
            case 0x1e:
                return self._simple_instruction("lload_0")
            case 0x1f:
                return self._simple_instruction("lload_1")
            case 0x20:
                return self._simple_instruction("lload_2")
            case 0x21:
                return self._simple_instruction("lload_3")
            case 0x69:
                return self._simple_instruction("lmul")
            case 0x75:
                return self._simple_instruction("lneg")
            case 0xab:
                
                for _ in range(self.offset % 4):
                    self._read_byte()

                default_byte: int = self._read_int()
                npairs: int = self._read_int()

                pairs: dict[int, int] = { 
                    self._read_int(): self._read_int() for _ in range(npairs)
                }
                    

                return f"lookupswitch {default_byte} {npairs} pairs: {str(pairs)}"

            case 0x81:
                return self._simple_instruction("lor")
            case 0x71:
                return self._simple_instruction("lrem")
            case 0xad:
                return self._simple_instruction("lreturn")
            case 0x79:
                return self._simple_instruction("lshl")
            case 0x7b:
                return self._simple_instruction("lshr")
            case 0x37:
                return self._byte_instruction("lstore")
            case 0x3f:
                return self._simple_instruction("lstore_0")
            case 0x40:
                return self._simple_instruction("lstore_1")
            case 0x41:
                return self._simple_instruction("lstore_2")
            case 0x42:
                return self._simple_instruction("lstore_3")
            case 0x65:
                return self._simple_instruction("lsub")
            case 0x7d:
                return self._simple_instruction("lushr")
            case 0x83:
                return self._simple_instruction("lxor")
            case 0xc2:
                return self._simple_instruction("monitorenter")
            case 0xc3:
                return self._simple_instruction("monitorexit")
            case 0xc5:
                index: int = self._read_short()
                dimensions: int = self._read_byte()

                return f"multianewarray {index} {dimensions}"
            case 0xbb:
                return self._short_instruction("new")
            case 0xbc:
                return self._byte_instruction("newarray")
            case 0x00:
                return self._simple_instruction("nop")
            case 0x57:
                return self._simple_instruction("pop")
            case 0x58:
                return self._simple_instruction("pop2")
            case 0xb5:
                return self._short_instruction("putfield")
            case 0xb3:
                return self._short_instruction("putstatic")
            case 0xa9:
                return self._byte_instruction("ret")
            case 0xb1:
                return self._simple_instruction("return")
            case 0x35:
                return self._simple_instruction("saload")
            case 0x56:
                return self._simple_instruction("sastore")
            case 0x11:
                return self._short_instruction("sipush")
            case 0x5f:
                return self._simple_instruction("swap")
            case 0xaa:
                
                for _ in range(self.offset % 4):
                    self._read_byte()

                default_byte: int = self._read_int()
                low: int = self._read_int()
                high: int = self._read_int()

                assert low <= high

                offsets_count: int = high - low + 1
                offsets: list[int] = [self._read_int() for _ in range(offsets_count)]

                return f"tableswitch {default_byte} {low} {high} offsets: {str(offsets)}"
            case 0xc4:

                # wide opcode documentation: https://docs.oracle.com/javase/specs/jvms/se7/html/jvms-6.html#jvms-6.5.wide

                opcode: int = self._read_byte()
                opcode_to_string_map: dict[int, str] = {
                    0x15: "iload",
                    0x17: "fload",
                    0x19: "aload",
                    0x16: "lload",
                    0x18: "dload",
                    0x36: "istore",
                    0x38: "fstore",
                    0x3a: "astore",
                    0x37: "lstore",
                    0x39: "dstore",
                    0xa9: "ret",
                    0x84: "iinc"
                }

                index: int = self._read_short()
                output = f"wide {opcode_to_string_map.get(opcode)} {index}"

                if opcode == 0x84:
                    output += f" {self._read_short()}"
                
                return output
            case _:
                return None

    def _short_instruction(self, name: str) -> str:
        return f"{name} {self._read_short()}"

    def _byte_instruction(self, name: str) -> str:
        return f"{name} {self._read_byte()}"
        
    def _simple_instruction(self, name: str) -> str:
        return name

    def _read_int(self) -> int:
        return (self._read_short() << 16) | self._read_short()

    def _read_short(self) -> int:
        return (self._read_byte() << 8) | self._read_byte()

    def _read_byte(self) -> int:
        byte: int = self.bytecode[self.offset]
        self.offset += 1

        return byte

class JavaClassParser:
    def __init__(self, bytecode: bytes) -> None:
        self.stream: BytesIO = BytesIO(bytecode)
        
    def parse(self) -> GenericDict:
        clazz: GenericDict = {}

        clazz['magic'] = hex(self._read_int())
        clazz['minor_version'] = self._read_short()
        clazz['major_version'] = self._read_short()
        clazz['constant_pool_count'] = self._read_short()
        clazz['constant_pool'] = self._parse_constant_pool(clazz['constant_pool_count']-1)
        clazz['access_flags'] = self._decode_access_flags(self._read_short(), ClassModifiers)
        clazz['this_class'] = self._read_short()
        clazz['super_class'] = self._read_short()
        clazz['interfaces_count'] = self._read_short()
        clazz['interfaces'] = [self._read_short() for _ in range(clazz['interfaces_count'])]
        clazz['fields_count'] = self._read_short()
        clazz['fields'] = self._parse_fields_or_methods(clazz['fields_count'], FieldModifiers, clazz['constant_pool'])
        clazz['methods_count'] = self._read_short()
        clazz['methods'] = self._parse_fields_or_methods(clazz['methods_count'], MethodModifiers, clazz['constant_pool'])
        clazz['attributes_count'] = self._read_short()
        clazz['attributes'] = self._parse_attributes(clazz['attributes_count'], clazz['constant_pool'])

        self.stream.close()

        return clazz
    
    def _parse_fields_or_methods(self, size: int, access_flags_constants: Iterable, constant_pool: ListOfDict) -> ListOfDict:

        elements: ListOfDict = []

        for _ in range(size):
            element: GenericDict = {}
            element['access_flags'] = self._decode_access_flags(self._read_short(), access_flags_constants)
            element['name_index'] = self._read_short()
            element['descriptor_index'] = self._read_short()
            element['attributes_count'] = self._read_short()
            element['attributes'] = self._parse_attributes(element['attributes_count'], constant_pool)

            elements.append(element)

        return elements
    
    def _parse_attributes(self, size: int, constant_pool: ListOfDict) -> ListOfDict:
        attributes: ListOfDict = []
        
        for _ in range(size):
            attribute_name_index = self._read_short()
            attribute_length = self._read_int()

            attr_kind: str = constant_pool[attribute_name_index - 1]['bytes']

            attributes.append({
                'attribute_name_index': attribute_name_index,
                'attribute_length': attribute_length,
                **self._parse_attribute(attr_kind, attribute_length, constant_pool)
            })

        return attributes

    def _parse_attribute(self, kind: str, length: int, constant_pool: ListOfDict) -> GenericDict:

        match kind:
            case 'ConstantValue':
                return { 'constantvalue_index': self._read_short() }
            case 'Code':

                max_stack: int = self._read_short()
                max_locals: int = self._read_short()

                code_length: int = self._read_int()
                code = BytecodeDisassembler(self._read_bytes(code_length)).dissassemble()
                exception_table_length = self._read_short()

                exception_table: ListOfDict = []
                for _ in range(exception_table_length):
                    exception_table.append({
                        'start_pc': self._read_short(),
                        'end_pc': self._read_short(),
                        'handler_pc': self._read_short(),
                        'catch_type': self._read_short()
                    })

                attributes_count: int = self._read_short()
                attributes: ListOfDict = self._parse_attributes(attributes_count, constant_pool)

                return {
                    'max_stack': max_stack,
                    'max_locals': max_locals,
                    'code_length': code_length,
                    'code': code,
                    'exception_table_length': exception_table_length,
                    'exception_table': exception_table,
                    'attributes_count': attributes_count,
                    'attributes': attributes
                }
            case 'Exceptions':
                number_of_exceptions: int = self._read_short()

                return {
                    'number_of_exceptions': number_of_exceptions,
                    'exception_index_table': [self._read_short() for _ in range(number_of_exceptions)]
                }
            case 'InnerClasses':
                number_of_classes: int = self._read_short()
                classes: ListOfDict = []

                for _ in range(number_of_classes):
                    classes.append({
                        'inner_class_info_index': self._read_short(),
                        'outer_class_info_index': self._read_short(),
                        'inner_name_index': self._read_short(),
                        'inner_class_access_flags': self._decode_access_flags(self._read_short(), ClassModifiers),
                    })

                return {
                    'number_of_classes': number_of_classes,
                    'classes': classes,
                }
            case 'EnclosingMethod':
                return {
                    'class_index': self._read_short(),
                    'method_index': self._read_short()
                }
            case 'Synthetic':
                return {}
            case 'Signature':
                return { 'signature_index': self._read_short() }
            case 'SourceFile':
                return { 'sourcefile_index': self._read_short() }
            case _:
                return {'info': self._read_bytes(length)}

    def _parse_constant_pool(self, size: int) -> ListOfDict:
        pool: ListOfDict = []

        i: int = 0
        while i < size:
            tag: ConstantsTag = ConstantsTag(self._read_byte())
            info: GenericDict = { 'tag': tag.name }

            match tag:
                case ConstantsTag.CONSTANT_Class:
                    info['name_index'] = self._read_short()
                case ConstantsTag.CONSTANT_Fieldref | ConstantsTag.CONSTANT_Methodref | ConstantsTag.CONSTANT_InterfaceMethodref:
                    info['class_index'] = self._read_short()
                    info['name_and_type_index'] = self._read_short()
                case ConstantsTag.CONSTANT_String:
                    info['string_index'] = self._read_short()
                case ConstantsTag.CONSTANT_Integer | ConstantsTag.CONSTANT_Float:
                    info['bytes'] = self._read_int()
                case ConstantsTag.CONSTANT_Long | ConstantsTag.CONSTANT_Double:
                    info['high_bytes'] = self._read_int()
                    info['low_bytes'] = self._read_int()

                    # According with the documentation the next cell is considered unusable
                    # https://docs.oracle.com/javase/specs/jvms/se8/html/jvms-4.html#jvms-4.4.5

                    pool.append(info)
                    pool.append({})
                    i += 2
                    continue
                case ConstantsTag.CONSTANT_NameAndType:
                    info['name_index'] = self._read_short()
                    info['descriptor_index'] = self._read_short()
                case ConstantsTag.CONSTANT_Utf8:
                    info['length'] = self._read_short()
                    info['bytes'] = self._read_bytes(info['length']).decode('utf-8')
                case ConstantsTag.CONSTANT_MethodHandle:
                    info['reference_kind'] = self._read_byte()
                    info['reference_index'] = self._read_short()
                case ConstantsTag.CONSTANT_MethodType:
                    info['descriptor_index'] = self._read_short()
                case ConstantsTag.CONSTANT_InvokeDynamic:
                    info['bootstrap_method_attr_index'] = self._read_short()
                    info['name_and_type_index'] = self._read_short()

            pool.append(info)
            i += 1
            
        return pool

    def _decode_access_flags(self, access_flags: int, constants: Iterable) -> list[str]:
        modifiers: list[str] = []
        for modifier in constants:
            if (access_flags & modifier.value) != 0:
                modifiers.append(modifier.name)

        return modifiers

    def _read_byte(self) -> int:
        return int.from_bytes(self._read_bytes(1), 'big')

    def _read_short(self) -> int:
        return int.from_bytes(self._read_bytes(2), 'big')

    def _read_int(self) -> int:
        return int.from_bytes(self._read_bytes(4), 'big')

    def _read_bytes(self, n: int) -> bytes:
        return self.stream.read(n)

def main() -> None:

    args_parser = argparse.ArgumentParser()
    
    args_parser.add_argument(
        "file", 
        help="Java compiled .class file",
        type=str
    )

    args_parser.add_argument(
        "-d", "--dump", 
        help="Save output in a text file with same name of .class file",
        action="store_true"
    )

    args = args_parser.parse_args()

    if not args.file.endswith(".class"):
        print("Invalid file (Wrong file format).")
        exit(-1)

    contents: bytes = read_class_file(args.file)
    java_class_parser: JavaClassParser = JavaClassParser(contents)
        
    parsed_class: GenericDict = java_class_parser.parse()
    output: str = prettify(parsed_class)

    if args.dump:
        filename: str = f"{args.file[:-5]}txt"
        with open(filename, "w") as f:
            f.write(output)
    else:
        print(output)


if __name__ == '__main__':
    main()
