__author__ = "Alekos Filini, Daniela Brozzoni"
__license__ = "BSD-3-Clause"
__version__ = "1.0"
__status__ = "Develop"

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def bold(msg):
    return  (bcolors.BOLD + msg + bcolors.ENDC)
def red(msg):
    return (bcolors.FAIL + msg + bcolors.ENDC)
def green(msg):
    return (bcolors.OKGREEN + msg + bcolors.ENDC)


class ASN1:
    """
    A tiny ASN1 parser which supports the BER format.
    """

    def __init__(self, data):
        """
        Default constructor, immediately parses the certs sent
        :param data: the array of integer representing a BER encoded tag
        """
        self.info  = None
        self.data = data
        self.root = []
        element, offset = self.parse()

        while (offset < len(self.data)):
            self.root += [element]
            element, offset = self.parse(offset)

    @staticmethod
    def get_meaning(tag_number):
        tag_map = {
            0x80 : 'Category Indicator',
            0x43 : 'Card Sercive Data Tag',
            0x46 : 'Pre Issuing-Do',
            0x47 : 'Card Capabilities',
            0x4f : 'Application Identifier',
            0x78 : 'Allocation Scheme Tag',
            0x82 : 'Status Indicator'
        }
        return tag_map.get(tag_number, 'Unknown')

    def get_class(self, offset):
        """
        Applies a bitmask to isolate the class
        :param offset: offset of the object
        :return: the extracted class
        """

        return self.data[offset] & 0b11000000



    def get_tag(self, offset):
        """
        Parses the tag value starting from offset
        :param offset: offset of the object
        :return: a tuple containing the tag value and the new offset
        """

        if self.data[offset] & 31 == 31:
            return self.get_next_bytes_tag(offset)

        # return self.certs[offset] & 31, offset + 1
        return self.data[offset] , offset + 1

    def get_next_bytes_tag(self, offsetStart):
        """
        Parses the tag in the "extended" form
        :param offsetStart: initial offset
        :return: a tuple containing the parsed tag value and the new offset
        """

        tag = 0
        count = 1
        while True:
            tag = tag | (self.data[offsetStart + count] & 0b01111111)

            if (self.data[offsetStart + count] & 0b10000000) == 0:
                break

            tag = tag << 7
            count += 1

        return tag, offsetStart + count + 1

    def parse_length(self, offset):
        """
        Extracts the length from the BER-encoded buffer
        :param offset: initial offset
        :return: a tuple containing the parsed length and the new offset
        """

        if self.data[offset] == 0x80: # unknown length
            count = 0
            while self.data[offset + count] != 0x00 and self.data[offset + count + 1] != 0x00:
                count += 1

            return count, offset + 1

        if self.data[offset] < 128:
            return self.data[offset], offset + 1

        lenBytes = self.data[offset] - 128
        len = 0

        for i in range(lenBytes):
            len = len << 8
            len = len | self.data[offset + i + 1]

        return len, offset + lenBytes + 1

    def get_bytes(self, offset, num):
        """
        Returns `num` bytes starting from `offset`
        :param offset: initial offset
        :param num: number of bytes
        :return: a tuple containing the bytes extracted and the new offset
        """

        return self.data[offset:offset + num], offset + num

    def parse(self, offset=0):
        """
        Parses the content of the buffer
        :param offset: initial offset, defaults to zero
        :return: a tuple containing the parsed buffer and the new offset
        """

        type = self.get_type(offset)
        tag, newOffset = self.get_tag(offset)
        length, newOffset = self.parse_length(newOffset)
        bytes, lastOffset = self.get_bytes(newOffset, length)

        children = []

        if type != 0: # structured
            childrenBytes = 0
            while childrenBytes < length:
                data, newChildrenOffset = self.parse(newOffset + childrenBytes)
                children.append(data)

                childrenBytes = newChildrenOffset - newOffset

        ans = {
            'tag': tag,
            'length': length,
            'bytes': bytes,
            'children': children,
            'verify': lambda d: d == bytes
        }

        return ans, lastOffset

    def parse_tag(self,offset=0):
        """
              Parses the content of the buffer
              :param offset: initial offset, defaults to zero
              :return: a tuple containing the parsed buffer and the new offset
              """
        if offset == 0 :
            type = self.get_type(offset)
            tag, newOffset = self.get_tag(offset)
            length, newOffset = self.parse_length(newOffset)
            bytes, lastOffset = self.get_bytes(newOffset, length)

            children = []

        if type != 0:  # structured
            childrenBytes = 0
            while childrenBytes < length:
                data, newChildrenOffset = self.parse_tag(newOffset + childrenBytes)
                children.append(data)

                childrenBytes = newChildrenOffset - newOffset

        ans = ASN1_Tag(tag,length,bytes,children)


        return ans, lastOffset

    def pretty_print(self, obj=None, indent=0):
        """
        Recursively prints the content of the tag
        :param obj: Entry point, defaults to pkcs7.root
        :param indent: Initial intendation level, defaults to 0
        """

        if obj is None:
            for e in self.root:
                self.pretty_print(e)
        else:
            print('  ' * indent + ('[Tag {}]: {}'.format(hex(obj['tag']), ASN1.get_meaning(obj['tag']))))
            if obj['bytes'] and not obj['children']:
                print('  ' * (indent + 1 ) + 'Bytes:')
                print('  ' * (indent + 1) + str(obj['bytes']) )


            if self.info is not None:
                print('  ' * (indent + 1 ) + 'Info:')
                print('  ' * (indent + 1) ).join(f"{k},{v}" for k,v in self.info)
            if len(obj['children']) > 0:

                print('  ' * (indent +1) + 'Children:')
            for c in obj['children']:
                self.pretty_print(c, indent + 2)
#
# class ASN1_Obj:
#     def __init__(self, buffer):
#
#         self.tags = [ ]
#
#         while buffer :
#             self.tags += [ASN1_Tag(buffer)]
#             last_tag = self.tags[-1]
#             buffer = last_tag.buffer
#
#     def __str__(self):
#         return '\n'.join(str(t) for t in self.tags)
#
#

class ASN1_Tag:
    def __init__(self, buffer, parent=None):
        self.tag = None
        self.length = None

        self.content = None
        self.children = []

        self.raw_buffer = buffer
        self.buffer = buffer
        self.parent = parent

        self.info = None

        self.parse()

    def __str__(self):
        lines = self.get_repr()
        return ('\n' ).join(lines)

    def parse(self):

        self.parse_tag()
        self.parse_length()
        self.parse_content()


    def get_repr(self, indent=0):
        head = '\t'*indent+ f"[TAG][Val: {hex(self.tag)}][Len: {str(self.length)}] {self.get_name()}"
        head = bold(head)
        lines = [ head ]
        indent += 1
        # lines += ['\t' * indent + 'Len: ' + str(self.length)]
        if self.structured:
            lines += ['\t'*indent+'Children:']
            for c in self.children:
                lines += c.get_repr(indent=indent)
        else:
            if self.info:
                lines += ['\t' * indent + i for i in self.info]
            elif self.content:
                  lines += ['\t' * indent + 'Bytes: ' + str(self.content)]



        return lines


    def parse_length(self):
        """
        Extracts the length from the BER-encoded buffer
        :param offset: initial offset
        :return: a tuple containing the parsed length and the new offset
        """
        count = 0
        len = 0
        buffer = self.buffer

        if buffer[0] == 0x80: # unknown length
            while buffer[count] != 0x00 and buffer[count + 1] != 0x00:
                count += 1
            len = count


        elif buffer[0] < 128:

            count = 1
            len = buffer[0]
        else:

            count = buffer[0] - 128

            for i in range(count):
                len = len << 8
                len = len | buffer[i+1]

            count +=1

        self.length = len
        self.buffer = self.buffer[count:]


    def parse_tag(self):
        """
        Parses the tag value starting from offset
        :param offset: offset of the object
        :return: a tuple containing the tag value and the new offset
        """
        buffer = self.buffer
        tag = 0
        count = 1
        self.structured = buffer[0] & 0b00100000

        tag = buffer[0]

        if (buffer[0] & 31) == 31:
            tag = tag << 8 | (buffer[count])
            while (buffer[count] & 0b10000000):
                count += 1
                tag = tag << 8 | (buffer[count] )
            count += 1








        self.tag = tag
        self.buffer = self.buffer[count:]

    def parse_content(self):
        if self.length > 0:
            self.content = self.buffer[:self.length]
            self.buffer = self.buffer[self.length:]
            if self.structured:
                buffer = self.content
                while buffer:
                    tag = ASN1_Tag(buffer)
                    buffer = tag.buffer
                    self.children += [tag]


    def get_name(self):
        sod_tag_map = {
            0x7F49: 'Public RSA Key certs',
            0x02: 'Integer',
            0x04: 'Octet String',
            0x06: 'Object Identifier',
            0x30: 'Sequence',
            0x31: 'Set',
            0x77: 'EF.SOD'
        }
        map = sod_tag_map
        return map.get(self.tag, 'Unknown')




card_service_table = '''b8 b7 b6 b5 b4 b3 b2 b1 Meaning
x x - - - - - - Application selection
1 - - - - - - - — by full DF name
- 1 - - - - - - — by partial DF name
- - x x - - - - BER-TLV certs objects available
- - 1 - - - - - — in EF.DIR (see 8.2.1.1)
- - - 1 - - - - — in EF.ATR (see 8.2.1.1)
- - - - x x x - EF.DIR and EF.ATR access services
- - - - 1 0 0 - — by the READ BINARY command (transparent structure)
- - - - 0 0 0 - — by the READ RECORD (S) command (record structure)
- - - - 0 1 0 - — by the GET DATA command (TLV structure)
- - - - - - - 0 Card with MF
- - - - - - - 1 Card without MF 
'''

card_software_func_one = '''b8 b7 b6 b5 b4 b3 b2 b1 Meaning
x x x x x - - - DF selection (see 5.3.1)
1 - - - - - - - — by full DF name
- 1 - - - - - - — by partial DF name
- - 1 - - - - - — by path
- - - 1 - - - - — by file identifier
- - - - 1 - - - Implicit DF selection
- - - - - 1 - - Short EF identifier supported
- - - - - - 1 - Record number supported
- - - - - - - 1 Record identifier supported '''

card_software_func_two= '''b8 b7 b6 b5 b4 b3 b2 b1 Meaning
1 - - - - - - - EFs of TLV structure supported
- x x - - - - - Behaviour of write functions
- 0 0 - - - - - — One-time write
- 0 1 - - - - - — Proprietary
- 1 0 - - - - - — Write OR
- 1 1 - - - - - — Write AND
- - - - x x x x Data unit size in quartets (from one to 32 768 quartets, i.e., 16 384 bytes)
- - - x - - - - Value 'FF' for the first byte of BER-TLV tag fields (see 5.2.2.1)
- - - 0 - - - - — Invalid (used for padding, default value)
- - - 1 - - - - — Valid (long private tags, constructed encoding) '''

table_amb='''B8 B7 B6 B5 B4 B3 B2 B1 MEANING
0 - - - - - - - Bits 7 to 1 according to this table
0 1 - - - - - - DELETE FILE (DF ITSELF)
0 - 1 - - - - - TERMINATE FILE
0 - - 1 - - - - ACTIVATE FILE
0 - - - 1 - - - DEACTIVATE FILE
0 - - - - 0 - - RFU
0 - - - - - 1 - CREATE FILE EF (EF CREATION)
0 - - - - - - 0 RFU 
'''

def parse_bytemap(byte, table ):
    lines = []
    properties = table.strip().split('\n')[1:]
    for p in properties:
        p = (p.split(' ',8))
        ok = True
        for pos,req_bit in enumerate(p[:8]):
            bit = test_bit(byte,pos)
            if req_bit == 'x' and bit:
                break
            elif req_bit == '1' and not bit:
                ok = False
                break
            elif req_bit == '0' and bit:
                ok = False
                break

        if ok:
            l = (green(p[-1]))

        else:
            l = (red(p[-1]))
        lines += [l]

    return lines

def test_bit(byte, pos):
    return bool(byte & (1 << (pos)))
