import pyshark
def id(packet: pyshark.packet.packet.Packet):
    """:param packet: pyshark parsed packet"""
    print(packet.sip.call_id_generated)