#!/usr/bin/env python

import sys
import pefile

pe = pefile.PE(sys.argv[1])
for section in pe.sections:
    if (section.Characteristics & 0x20) != 0:
        print("%s: changing section %s to be non-pageable (attr: 0x%08X)" % (sys.argv[0], section.Name,
            section.Characteristics))
        section.Characteristics |= 0x08000000

pe.write(sys.argv[1])
print("%s: wrote %s" % (sys.argv[0], sys.argv[1]))

