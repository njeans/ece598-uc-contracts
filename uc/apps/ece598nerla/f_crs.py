from ast import literal_eval
from uc import UCFunctionality
from uc.utils import read_one, read
import logging
from secp256k1 import *

log = logging.getLogger(__name__)


class F_CRS(UCFunctionality):
    def __init__(self, k, bits, crupt, sid, channels, pump):
        UCFunctionality.__init__(self, k, bits, crupt, sid, channels, pump)
        self.ssid,sid = sid

        self.output_value = None

        self.party_msgs['value'] = self.value
        self.party_msgs['sendmsg'] = self.sendmsg
        self.adv_msgs['value'] = self.avalue

    def value(self, sender):
        # print("f_crs value")
        if self.output_value is None:
            g1 = make_random_point()
            g2 = make_random_point()
            self.output_value = self.keygen_pub(g1, g2)
        self.write( 'f2p', (sender, (self.output_value,)) )

    def avalue(self):
        # print("f_crs avalue")
        if self.output_value is None:
            g1 = make_random_point()
            g2 = make_random_point()
            self.output_value = self.keygen_pub(g1, g2)
        self.write( ch='f2a', msg=self.output_value  )


    def sendmsg(self, sender, to, msg):
        self.write(
            ch='f2p',
            msg=(to, ('recvmsg', sender, msg)),
        )

    def keygen_pub(self, g1, g2):
        x1 = Fp(uint256_from_str(os.urandom(32)))
        x2 = Fp(uint256_from_str(os.urandom(32)))
        y1 = Fp(uint256_from_str(os.urandom(32)))
        y2 = Fp(uint256_from_str(os.urandom(32)))
        z = Fp(uint256_from_str(os.urandom(32)))

        c = g1*int(x1) + g2*int(x2)
        d = g1*int(y1) + g2*int(y2)
        h = g1*int(z)

        rho = Fp(uint256_from_str(os.urandom(32)))
        h1 = g1*rho
        h2 = g2*rho

        return (g1, g2, c, d, h , h1, h2)
