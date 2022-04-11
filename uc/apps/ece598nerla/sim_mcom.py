from uc import UCAdversary
from ast import literal_eval
from prot_mcom import MCommitment_Prot
from secp256k1 import *
from utils import *
from collections import defaultdict

class Sim_MCom(UCAdversary):
    def __init__(self, k, bits, crupt, sid, pid, channels, pump):
        self.ssid,rest = sid
        self.parties = literal_eval(rest)
        self.input_sid = sid
        UCAdversary.__init__(self, k, bits, crupt, sid, pid, channels, pump)

        self.party_msgs['recvmsg'] = self.recvmsg
        self.party_msgs['commit'] = self.recv_commit
        self.party_msgs['open'] = self.recv_open

        self.env_msgs['value'] = self.value
        self.z2a2f_msgs['value'] = self.env_value

        self.z2a2p_msgs['sendmsg'] = self.commit_send
        self.z2a2p_msgs['value'] = self.value

        self.commitment = {}
        self.m = {}
        self.sid = {}
        self.state = defaultdict(int)
        self.honest = {}
        self.step_b ={}

        self.g1 = make_random_point()
        self.g2 = make_random_point()
        self.output_value = self.keygen_pub(self.g1, self.g2)

    def value(self, to):
        self.write('a2z', ('P2A', (to, ((self.output_value),))))

    def env_value(self):
        self.write('a2z', ('F2A', (self.output_value)) )

    def keygen_pub(self, g1, g2):
        x1 = Fp(uint256_from_str(os.urandom(32)))
        x2 = Fp(uint256_from_str(os.urandom(32)))
        y1 = Fp(uint256_from_str(os.urandom(32)))
        y2 = Fp(uint256_from_str(os.urandom(32)))
        z = Fp(uint256_from_str(os.urandom(32)))

        self.sk = (x1, x2, y1, y2, z)

        c = g1*int(x1) + g2*int(x2)
        d = g1*int(y1) + g2*int(y2)
        h = g1*int(z)

        self.h=h
        self.c=c
        self.d=d

        self.rho = Fp(uint256_from_str(os.urandom(32)))
        h1 = g1*self.rho
        h2 = g2*self.rho

        return (g1, g2, c, d, h , h1, h2)

    def recvmsg(self, to, fro, msg):
        self.write('a2z', ('P2A', (to, ('recvmsg', fro, msg))) )

    def commit_send(self, to, fro, msg):
        cmd = msg[0]
        cid = msg[1][0]

        if cmd not in ["commit","reveal","b","d"]:
            ins = str(to) + str(fro) + str(cid)
        else:
            ins =  str(fro) + str(to) + str(cid)

        # print("commit_send",to, fro,cmd,ins,self.state[ins])
        if self.state[ins] == 0 and cmd == "commit":
            cid,sid,c = msg[1]
            self.sid[ins]=sid
            (u1,u2,e,v) = c
            self.commitment[ins] = c
            mrecv = decrypt(self.sk,c)
            self.m[ins] = mrecv
            baserecv = Ginv(mrecv)

            i = bytes(str(to),"utf-8")
            j = bytes(str(fro),"utf-8")
            # x = bytes(msg,"utf-8")
            ssid = bytes(cid,"utf-8")
            basecalc = ssid + i + j
            if sid != baserecv[:len(sid)] and basecalc not in baserecv:
                self.write('a2f', msg=('commit',to,fro,cid,""))
            else:
                x = baserecv[baserecv.find(basecalc)+len(basecalc):]
                self.write('a2f', msg=('commit',to,fro,cid,x))
            self.state[ins] = 1
        elif self.state[ins] == 1 and cmd == "reveal":
            self.honest[ins] = MCommitment_Prot(0,None,self.input_sid,fro,{'z2p':None,'f2p':None},self.pump)
            self.honest[ins]._crs(self.output_value)
            self.honest[ins].output_err = lambda m: self._error_handle(fro, m)
            step_e_ins = str(to) + str(fro) + str(cid)
            self.honest[ins].commitment[step_e_ins] = self.commitment[ins]
            self.honest[ins].m[step_e_ins] = self.m[ins]
            self.honest[ins].sid[step_e_ins] = self.sid[ins]
            res=self.honest[ins].proof_a(to, cid, step_e_ins, msg[1][1], self.sid[ins])
            if res is not None:
                self._forward_to_z(to,fro,res)
                self.state[ins] = 2
            # self.pump.write('dump')
        elif self.state[ins] == 2 and cmd == "b":
            step_e_ins = str(to) + str(fro) + str(cid)
            res=self.honest[ins].proof_c(fro, cid, step_e_ins, msg[1][1])
            if res is not None:
                self._forward_to_z(to,fro,res)
                self.state[ins] = 3
            # else:
            #     self.pump.write('dump')
        elif self.state[ins] == 3 and cmd == "d":
            step_e_ins = str(to) + str(fro) + str(cid)
            res=self.honest[ins].proof_e(fro, cid, step_e_ins, msg[1][1])
            if res is not None:
                self._forward_to_z(to,fro,res)
                self.state[ins] = 4
        elif self.state[ins] == 2 and cmd == "a":
            cprime = msg[1][1]
            chal = dual_decrypt(self.rho,cprime)
            epsilon = Ginv(chal)
            epsilon_num = uint256_from_str(epsilon)
            (u1, u2, e, v) = self.commitment[ins]
            z = Fp(uint256_from_str(os.urandom(32)))

            alpha = (self.g1*z)-(u1*epsilon_num)
            beta = (self.g2*z)-(u2*epsilon_num)
            gamma=(self.h*z)-((e-self.m[ins]))
            w = hash(bytes(str(u1),'utf-8')+bytes(str(u2),'utf-8')+bytes(str(e),'utf-8'))
            delta = (self.c+(self.d*w))*z - (v*epsilon_num)
            resp = ('b', (cid,(alpha, beta, gamma, delta)))
            self.step_b[ins]=[(alpha, beta, gamma, delta),cprime,z]
            self._forward_to_z(to,fro,resp)
            self.state[ins] = 3
        elif self.state[ins] == 3 and cmd == "c":
            Rprime,Sprime,epsilonprime = msg[1][1]
            chalprime = G(inp=epsilonprime)
            cprimecheck = dual_encrypt(self.output_value,chalprime, Rprime, Sprime)
            cprime = self.step_b[ins][1]
            if cprime != cprimecheck:
                self._error_handle(fro,"cprimecheck")
            else:
                z=self.step_b[ins][2]
                resp=('d', (cid,z))
                self._forward_to_z(to,fro,resp)
        else:
            self._error_handle(to, msg)
            self.pump.write('dump')

    def recv_commit(self, fro, to, cid):
        ins =  str(fro) + str(to) + str(cid)
        # print("recv_commit",ins,self.state[ins])
        if self.state[ins] == 0:
            i = bytes(str(to),"utf-8")
            j = bytes(str(fro),"utf-8")
            x = bytes("","utf-8")
            ssid = bytes(cid,"utf-8")
            base = ssid + i + j + x
            self.m[ins],sid,_ = G(base=base)
            R=Fp(uint256_from_str(os.urandom(32)))
            c=encrypt(self.output_value,R,self.m[ins])
            self.commitment[ins] = c
            resp = ('commit', (cid, sid, c))
            # self._forward_to_z(to,fro,resp)
            self.write('a2z', ('P2A',(fro, resp)))
            self.state[ins] = 1
        else:
            self.pump.write('dump')

    def recv_open(self, fro, to,cid, m):
        ins =  str(fro) + str(to) + str(cid)
        # print("recv_open",ins,self.state[ins])
        if self.state[ins] == 1:
            resp = (cid,m)
            self._forward_to_z(to,fro,resp)
            self.state[ins] = 2

    def _forward_to_z(self,fro ,to,res):
        self.write('a2z', ('P2A',(fro, ('recvmsg', to, res))))

    def _error_handle(self,i,m):
        self.write( 'a2z', msg=(i,('error', m)) )
