import struct

# Thanks to
# https://github.com/liwugang/android_properties/blob/master/jni/system_properties.cpp

class PropAreaGenerator:
    PROP_AREA_MAGIC = 0x504f5250    # "PROP"
    PROP_AREA_VERSION = 0xfc6ed0ab  # Android N compat
    PROP_VALUE_MAX = 92
    
    AREA_SIZE = 128 * 1024
    HEADER_SIZE = 128 # sizeof(prop_area) = 4*4 + 28*4
    
    def __init__(self):
        self.buffer = bytearray(self.AREA_SIZE)
        self.bytes_used = 0 # data[]
        
        # struct prop_area {
        #    uint32_t bytes_used;
        #    uint32_t serial;
        #    uint32_t magic;
        #    uint32_t version;
        #    uint32_t reserved[28];
        #    char data[0];
        # }
                
        # Serial
        struct.pack_into("<I", self.buffer, 4, 1) 
        
        # Magic & Version
        struct.pack_into("<I", self.buffer, 8, self.PROP_AREA_MAGIC)
        struct.pack_into("<I", self.buffer, 12, self.PROP_AREA_VERSION)
                
        # Root Node
        # C: prop_bt *prev_bt = get_prop_bt(area, 0);
        self.root_off = self.new_prop_bt("", 0)

    def align(self, size):
        # #define ALIGN(x, alignment) ((x) + (sizeof(alignment) - 1) & ~(sizeof(alignment) -1))
        # alignment = sizeof(uint32_t) = 4
        return (size + 3) & ~3

    def new_prop_bt(self, name, namelen):
        # uint32_t need_size = ALIGN(sizeof(prop_bt) + namelen + 1, sizeof(uint32_t));
        struct_size = 20
        need_size = self.align(struct_size + namelen + 1)
        
        if self.bytes_used + need_size > (self.AREA_SIZE - self.HEADER_SIZE):
            raise MemoryError("PropArea full!")
            
        off = self.bytes_used
        self.bytes_used += need_size
        
        struct.pack_into("<I", self.buffer, 0, self.bytes_used)
        
        abs_off = self.HEADER_SIZE + off
        
        # struct prop_bt layout:
        # +0: namelen (u8)
        # +1: reserved[3]
        # +4: prop (u32)
        # +8: left (u32)
        # +12: right (u32)
        # +16: children (u32)
        # +20: name...
        
        struct.pack_into("<B", self.buffer, abs_off, namelen)
        
        name_bytes = name.encode('utf-8')
        self.buffer[abs_off + 20 : abs_off + 20 + namelen] = name_bytes
        
        return off

    def new_prop_info(self, name, namelen, value):
        """
        Аналог: new_prop_info(...)
        """
        # uint32_t need_size = ALIGN(sizeof(prop_info) + namelen + 1, sizeof(uint32_t));
        # sizeof(prop_info) = 4 (serial) + 92 (value) = 96
        struct_size = 96
        need_size = self.align(struct_size + namelen + 1)
        
        if self.bytes_used + need_size > (self.AREA_SIZE - self.HEADER_SIZE):
            raise MemoryError("PropArea full!")
            
        off = self.bytes_used
        self.bytes_used += need_size
        struct.pack_into("<I", self.buffer, 0, self.bytes_used)
        
        abs_off = self.HEADER_SIZE + off
        
        # struct prop_info layout:
        # +0: serial (u32)
        # +4: value (char[92])
        # +96: name...
        
        val_bytes = value.encode('utf-8')
        if len(val_bytes) >= self.PROP_VALUE_MAX:
            val_bytes = val_bytes[:self.PROP_VALUE_MAX - 1]
        valuelen = len(val_bytes)
        
        serial = (valuelen << 24) & 0xFFFFFFFF
        struct.pack_into("<I", self.buffer, abs_off, serial)
        
        self.buffer[abs_off + 4 : abs_off + 4 + valuelen] = val_bytes
        
        name_bytes = name.encode('utf-8')
        self.buffer[abs_off + 96 : abs_off + 96 + namelen] = name_bytes
        
        return off

    def get_prop_bt_field(self, rel_off, field_offset):
        if rel_off == 0 and field_offset == 1000: return 0
        return struct.unpack_from("<I", self.buffer, self.HEADER_SIZE + rel_off + field_offset)[0]

    def set_prop_bt_field(self, rel_off, field_offset, value):
        struct.pack_into("<I", self.buffer, self.HEADER_SIZE + rel_off + field_offset, value)

    def get_prop_bt_name(self, rel_off):
        namelen = self.buffer[self.HEADER_SIZE + rel_off]
        name_bytes = self.buffer[self.HEADER_SIZE + rel_off + 20 : self.HEADER_SIZE + rel_off + 20 + namelen]
        return name_bytes.decode('utf-8'), namelen

    def cmp_prop_name(self, one, one_len, two, two_len):
        if one_len < two_len:
            return -1
        elif one_len > two_len:
            return 1
        else:
            if one < two: return -1
            if one > two: return 1
            return 0

    def add_property(self, key, value):
        prev_bt_off = 0 # Root
        
        segments = key.split('.')
        
        for i, segment in enumerate(segments):
            is_last = (i == len(segments) - 1)
            seg_len = len(segment)
            
            p_bt_off = self.get_prop_bt_field(prev_bt_off, 16)
            
            current_node_off = 0
            
            if p_bt_off == 0:
                new_off = self.new_prop_bt(segment, seg_len)
                self.set_prop_bt_field(prev_bt_off, 16, new_off) # prev->children = new
                p_bt_off = new_off
            
            # BST Traversal (while (p_bt != NULL))
            curr_off = p_bt_off
            
            while True:
                node_name, node_namelen = self.get_prop_bt_name(curr_off)
                
                ret = self.cmp_prop_name(segment, seg_len, node_name, node_namelen)
                
                if ret == 0:
                    current_node_off = curr_off
                    break
                elif ret < 0:
                    left = self.get_prop_bt_field(curr_off, 8)
                    if left == 0:
                        new_off = self.new_prop_bt(segment, seg_len)
                        self.set_prop_bt_field(curr_off, 8, new_off)
                        current_node_off = new_off
                        break
                    else:
                        curr_off = left
                else:
                    right = self.get_prop_bt_field(curr_off, 12)
                    if right == 0:
                        new_off = self.new_prop_bt(segment, seg_len)
                        self.set_prop_bt_field(curr_off, 12, new_off)
                        current_node_off = new_off
                        break
                    else:
                        curr_off = right
            
            if is_last:
                prop_off = self.get_prop_bt_field(current_node_off, 4)
                if prop_off == 0:
                    info_off = self.new_prop_info(key, len(key), value)
                    self.set_prop_bt_field(current_node_off, 4, info_off)
                else:
                    print(f"Warning: Duplicate property {key}")
            else:
                prev_bt_off = current_node_off

    def save(self, filename):
        with open(filename, 'wb') as f:
            f.write(self.buffer)
        print(f"Saved {filename}. Total size: {self.AREA_SIZE}, Used data: {self.bytes_used}")

def parse_prop_file(filepath):
    props = {}
    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            if '=' in line:
                key, val = line.split('=', 1)
                props[key.strip()] = val.strip()
    return props