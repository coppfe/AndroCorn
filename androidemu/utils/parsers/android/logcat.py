import struct

class LogCatParser:
    def __init__(self):
        self.buf = b''
        self.entries = []

    def feed(self, block):
        self.buf += block
        while True:
            if len(self.buf) < 12:
                return

            log_id = self.buf[0]

            tid = struct.unpack_from('<H', self.buf, 1)[0]

            sec, nsec = struct.unpack_from('<II', self.buf, 3)

            priority = self.buf[11]

            tag_start = 12
            tag_end = self.buf.find(b'\x00', tag_start)
            if tag_end == -1:
                return
            tag = self.buf[tag_start:tag_end].decode('utf-8', errors='replace')

            msg_start = tag_end + 1
            msg_end = self.buf.find(b'\x00', msg_start)
            if msg_end == -1:
                return
            message = self.buf[msg_start:msg_end].decode('utf-8', errors='replace')

            self.entries.append({
                'log_id': log_id,
                'tid': tid,
                'sec': sec,
                'nsec': nsec,
                'priority': priority,
                'tag': tag,
                'message': message
            })

            self.buf = self.buf[msg_end+1:]

    def get_entries(self, clear=False):
        result = self.entries
        self.entries = []
        if clear:
            self.clear()
        return result
    
    def clear(self):
        self.entries = []