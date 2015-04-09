#Utililites for DNS 
import sys
import socket
import time
import datetime
import struct
from string import ascii_letters, digits, punctuation

# Parses names from DNS compression format
def parse(packet, offset, max_offset):
  zero_byte = struct.pack('!h', 0)[1]
  byte = packet[offset]
  byte = struct.unpack('!h', zero_byte + byte)[0]

  # if null byte, base case
  if byte == 0:
    return ('', offset + 1, max(max_offset, offset + 1))

  # if length and label, read
  if byte > 0 and byte < 64:
    string = packet[offset + 1 : offset + byte + 1]
    (remaining,new_offset, max_offset) = parse(packet, offset + byte + 1, max_offset)

    if remaining == '':
      return (string, new_offset, max(new_offset, max_offset))
    else:
      return (string + '.' + remaining, new_offset, max(new_offset, max_offset))
  
  # If pointer, follow
  if byte >= 192:
    value = struct.unpack('!H', packet[offset:offset+2])[0]

    mask = 0
    mask = (1 << 15) | mask
    mask = (1 << 14) | mask
    pointer = value ^ mask

    return parse(packet, pointer, max(max_offset, offset + 2))


# Takes a list of arguments from sys.argv
# returns tuple in form (ip, port, query)
# STRING ip, INT port, STRING query (a, mx, ns)
def parseArguments(args):
  #if arguments not 3 or 4 throw error

  if len(args) == 3:
    domain = args[2]
    adress = args[1]
    qtype = 'a'
  
  if len(args) == 4:
    domain = args[3]
    adress = args[2]
    qtype = args[1][1:]
  
  adress = adress.split(':')
  ip = adress[0][1:]
  
  if len(adress) == 1:
    port = 53
  else:
    port = int(adress[1])

  return (ip, port, domain, qtype)


def log(string):
  sys.stderr.write(datetime.datetime.now().strftime("%H:%M:%S.%f") + " " + string + "\n")

def chunks(packet):
  for i in xrange(0, len(packet), 16):
    yield packet[i:i+16]

def toascii(char):
  if char == "  ":
    return ""
  if char in ascii_letters or char in digits or char in punctuation or char == ' ':
    return char
  return '.'

# DUMP THE PACKET
def dump_packet(packet):
  lineno = 0
  for line in list(chunks(packet)):
    larr = list("{:02X}".format(ord(x)) for x in line)
    while len(larr) < 16:
      larr.append("  ")

    r = "[%04x]   " % (lineno)
    r = r + " ".join(larr[0:8]) + "   "
    r = r + " ".join(larr[8:16]) + "   "
    r = r + ("".join(toascii(x) for x in line[0:8]))
    if len(line) > 8:
      r = r + " " + ("".join(toascii(x) for x in line[8:16]))
    lineno += 16
    print r