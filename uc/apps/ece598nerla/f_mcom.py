from ast import literal_eval
from uc import UCFunctionality
from collections import defaultdict

class F_Mcom(UCFunctionality):
    def __init__(self, k, bits, crupt, sid, channels, pump):
        UCFunctionality.__init__(self, k, bits, crupt, sid, channels, pump)
        self.ssid = sid[0]
        sid = literal_eval(sid[1])

        self.msg = {}
        self.state = defaultdict(int)

        self.party_msgs['commit'] = self.commit
        self.party_msgs['reveal'] = self.reveal
        self.adv_msgs['commit'] = self.commit
        self.adv_msgs['reveal'] = self.reveal

    def commit(self, sender, receiver, cid, msg):
        # print("F_Mcom commit")
        ins = str(sender)+str(receiver)+cid
        if self.state[ins] == 0:
            self.msg[ins] = msg
            self.write('f2p', (receiver, ('commit', sender, cid)))
            self.state[ins] = 1
        else: self.pump.write('')

    def reveal(self, sender, receiver, cid):
        # print("F_Mcom reveal")
        ins = str(sender)+str(receiver)+cid
        if self.state[ins] == 1:
            self.write('f2p', (receiver, ('open', sender, cid , self.msg[ins])))
            self.state[ins] = 2
        else: self.pump.write('')
