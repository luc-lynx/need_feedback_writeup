import struct
import channel

for s in range(0,20):
    with open("./rec/part%02d" % s, "rb") as fl:
        bts = fl.read()
        firstPacket = True

        while len(bts) > 0:
            l = struct.unpack("<I", bts[:4])[0]
            print("Len: ", l)
            bts = bts[4:]

            m = channel.KappaMsg.Deserialize(bts[:l])
            if m.typ == channel.MsgType.reseed:
                raise Exception

            if firstPacket:
                print(m.data)
                firstPacket = False
            else:
                with open("./rec/part%s_raw" % s, "ab") as f2:
                    f2.write(m.data)
            bts = bts[l:]
