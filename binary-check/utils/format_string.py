from __future__ import print_function
import re
import pprint

class FormatStringItem(object):
    def __init__(self, index, size, start, fstr):
        self.index = index
        self.size  = size
        self.start = start
        self.fstr  = fstr
    
    def __str__(self):
        return '<FormatStringItem : index=%d, size=%d, start=%d, fstr=%s>' % (
            self.index,
            self.size,
            self.start,
            self.fstr
        )
    
    def __repr__(self):
        return str(self)


cfmt='''\
(                                  # start of capture group 1
%                                  # literal "%"
(?:                                # first option
(?:[-+0 #]{0,5})                   # optional flags
(?:\d+|\*)?                        # width
(?:\.(?:\d+|\*))?                  # precision
(?:h|l|ll|w|I|I32|I64)?            # size
[cCdiouxXeEfgGaAnpsSZ]             # type
) |                                # OR
%%)                                # literal "%%"
'''

convertTable = {
    'c' : 1,
    'C' : 1,
    'd' : 4,
    'i' : 4,
    'o' : 4,
}

def parseItemSize(s):
    if s == r'%%':
        return 0
    
    '''
    enough?
    '''
    return 4

def parseFormatStringItem(s):
    items = []
    index = 0
    for m in re.finditer(cfmt, s, flags=re.X):
        start = m.start(1)
        fstr  = m.group(1)
        size  = parseItemSize(fstr)
        if size == 0:
            continue
        
        entry = FormatStringItem(index, size, start, fstr)
        items.append(entry)
        index += 1
    
    return items
        
