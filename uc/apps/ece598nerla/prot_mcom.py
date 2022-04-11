import os
from ast import literal_eval
from uc import UCProtocol
from uc.utils import waits, wait_for
from collections import defaultdict
import secp256k1 as secp
from secp256k1 import *
import logging
import math
import traceback

log = logging.getLogger(__name__)

class MCommitment_Prot(UCProtocol):
    def __init__(self, k, bits, sid, pid, channels, pump):
        UCProtocol.__init__(self, k, bits, sid, pid, channels, pump)
        self.ssid,sid = sid
        self.parties = literal_eval(sid)
        self.pid = pid
        self.env_msgs['commit'] = self.env_commit
        self.env_msgs['reveal'] = self.env_reveal
        self.func_msgs['recvmsg'] = self.func_receive

        self.msg = {}
        self.m = {}
        self.randomness = {}
        self.commitment = {}
        self.step_a = {}
        self.step_b = {}
        self.step_c = {}
        self.sid = {}
        self.first = True
        self.state = defaultdict(int)
        self.output_err = self._default_error#lambda m: self.write( 'p2z', msg=('error', m) )

    def env_commit(self, receiver, cid, msg):
        if self.first:
            m = self.write_and_wait_for('p2f', ('value',), 'f2p')[0]
            self._crs(m)
        ins = str(receiver) + str(self.pid) + str(cid)
        # print("prot_mcom env_commit",ins,msg,self.state[ins])
        if self.state[ins] == 0:
            i = bytes(str(self.pid),"utf-8")
            j = bytes(str(receiver),"utf-8")
            x = bytes(msg,"utf-8")
            ssid = bytes(cid,"utf-8")
            base = ssid + i + j + x
            res = self.G(base=base)
            if res is None:
                self.pump.write('dump')
                return
            self.m[ins],sid,_ = res
            self.sid[ins] = sid
            self.msg[ins] = msg
            self.randomness[ins] = Fp(uint256_from_str(os.urandom(32)))

            self.commitment[ins] = self._encrypt(self.randomness[ins], self.m[ins])
            self.write('p2f', ('sendmsg', receiver, ('commit', (cid, sid, self.commitment[ins]))))
            self.state[ins] = 1
        else:
            self.pump.write('dump')

    def env_reveal(self, receiver, cid):
        ins = str(receiver) + str(self.pid)  + str(cid)
        # print("prot_mcom env_commit",ins,self.state[ins])
        if self.state[ins] == 1:
            self.write( 'p2f', ('sendmsg', receiver, ('reveal', (cid, self.msg[ins]))) )
            self.state[ins] = 2
        else:
            self.pump.write('dump')

    def proof_a(self, fro, cid, ins, msg, sid):
        #print("proof_a")
        j = bytes(str(self.pid),"utf-8")
        i = bytes(str(fro),"utf-8")
        x = bytes(msg,"utf-8")
        self.msg[ins]=msg
        ssid = bytes(cid,"utf-8")

        base = ssid + i + j + x
        res = self.G(base=base, extra=sid)
        if res is None:
            return None

        self.m[ins],_,_= res

        res = self.G(base=b'')
        if res is None:
            return
        chal,p1,p2 = res
        epsilon = p1+p2
        R=Fp(uint256_from_str(os.urandom(32)))
        S=Fp(uint256_from_str(os.urandom(32)))
        cprime = self.dual_encrypt(chal, R, S)
        self.step_a[ins] = (R,S,epsilon)
        return ('a', (cid, cprime))

    def proof_b(self, fro, cid, ins, cprime):
        #print("proof_b")
        s = Fp(uint256_from_str(os.urandom(32)))
        alpha = self.g1 * s
        beta = self.g2 * s
        gamma = self.h * s

        u1 = self.g1*self.randomness[ins]
        u2 = self.g2*self.randomness[ins]
        e = self.h*self.randomness[ins] + self.m[ins]
        w = hash(bytes(str(u1),'utf-8')+bytes(str(u2),'utf-8')+bytes(str(e),'utf-8'))
        delta = (self.c + (self.d*w))*s

        self.step_b[ins] = [(alpha, beta, gamma, delta),cprime,s]
        return ('b', (cid, self.step_b[ins][0]))

    def proof_c(self, fro, cid, ins, msg):
        #print("proof_c")
        self.step_c[ins] = msg
        return ('c', (cid, self.step_a[ins]))

    def proof_d(self, fro, cid, ins, msg):
        #print("proof_d")
        cprime = self.step_b[ins][1]
        s = self.step_b[ins][2]
        R,S,epsilon = msg
        chal = self.G(inp=epsilon)
        if chal is None:
            return
        cprimecheck = self.dual_encrypt(chal, R, S)
        if cprime!=cprimecheck:
            self.output_err("cprimecheck")
            return
        epsilon_num = secp.uint256_from_str(epsilon)
        z=s+(epsilon_num*self.randomness[ins])

        return ('d', (cid, z))

    def proof_e(self, fro, cid, ins, z):
        #print("proof_e")
        alpha, beta, gamma, delta = self.step_c[ins]
        R,S,epsilon = self.step_a[ins]
        epsilon_num = secp.uint256_from_str(epsilon)
        u1,u2,e,v=self.commitment[ins]

        g1z = self.g1*z
        g1zcheck = alpha + (u1*epsilon_num)
        if g1z!=g1zcheck:
            self.output_err("g1zcheck")
            return

        g2z = self.g2*z
        g2zcheck = beta + (u2*epsilon_num)
        if g2z!=g2zcheck:
            self.output_err("g2zcheck")
            return

        edivm = e - self.m[ins]
        hz = self.h*z
        hzcheck = gamma + (edivm*epsilon_num)

        if hz!=hzcheck:
            self.output_err("hzcheck")
            return

        w = hash(bytes(str(u1),'utf-8')+bytes(str(u2),'utf-8')+bytes(str(e),'utf-8'))
        cdwz = (self.c+(self.d*w))*z
        cdwzcheck = delta + (v*epsilon_num)
        if cdwz!=cdwzcheck:
            self.output_err("cdwzcheck")
        return ('open', fro, cid, self.msg[ins])

    def _make_step_e_inp(self, ins):
        return self.commitment[ins],self.step_a[ins],self.step_c[ins],self.m[ins],self.msg[ins]

    def func_receive(self, fro, msg):
        cmd = msg[0]
        cid = msg[1][0]
        ins = str(fro) + str(self.pid) + str(cid)
        if self.state[ins] == 0 and cmd == 'commit':
            self.sid[ins] = msg[1][1]
            self.commitment[ins] = msg[1][2]
            self.state[ins] = 1
            self.write('p2z', msg=('commit',fro, cid))
        elif self.state[ins] == 1 and cmd == 'reveal':
            if self.first:
                m = self.write_and_wait_for('p2f', ('value',), 'f2p')[0]
                self._crs(m)
            resp = self.proof_a(fro, cid, ins, msg[1][1],self.sid[ins])
            # print("resp proof_a",resp)
            self._respond(fro, ins, resp, 2)
        elif self.state[ins] == 2 and cmd == 'a':
            resp = self.proof_b(fro, cid, ins, msg[1][1])
            self._respond(fro, ins, resp, 3)
        elif self.state[ins] == 2 and cmd == 'b':
            resp = self.proof_c(fro, cid, ins, msg[1][1])
            self._respond(fro, ins, resp, 3)
        elif self.state[ins] == 3 and cmd == 'c':
            resp = self.proof_d(fro, cid, ins, msg[1][1])
            self._respond(fro, ins, resp, 4)
        elif self.state[ins] == 3 and cmd == 'd':
            resp = self.proof_e(fro, cid, ins, msg[1][1])
            if resp is not None:
                self.write( 'p2z', msg=resp)
                self.state[ins] = 4
        else:
            self.output_err( str(msg) )


    def G(self, inp=None, base=None, extra=None):
        if inp is not None:
            x = secp.uint256_from_str(inp)
            try:
                point = secp.solve(secp.Fq(x))
            except:
                self.output_err("G")
                return None
            return point

        total_len = 32
        len_extra = 2
        desired_base_len = total_len - len_extra
        if len(base) > desired_base_len:
            desired_base = base[:desired_base_len]
        else:
            desired_base = self._pad(base,desired_base_len)

        if extra is None:
            while True:
                extra = os.urandom(len_extra)
                x = secp.uint256_from_str(extra+desired_base)
                try:
                    point = secp.solve(secp.Fq(x))
                    # print("a",extra+desired_base)
                    break
                except ValueError:
                    continue
        else:
            x = secp.uint256_from_str(extra+desired_base)
            # print("b",extra+desired_base)
            try:
                point = secp.solve(secp.Fq(x))
            except:
                self.output_err("G")
                return None
        return point,extra,desired_base

    def _crs(self,m):
        if self.first:
            self.g1 = m[0]
            self.g2 = m[1]
            self.c = m[2]
            self.d = m[3]
            self.h = m[4]
            self.h1 = m[5]
            self.h2 = m[6]
            self.first = False

    def _encrypt(self, R, m):
        u1 = self.g1*R
        u2 = self.g2*R
        e = self.h*R + m
        w = hash(bytes(str(u1),'utf-8')+bytes(str(u2),'utf-8')+bytes(str(e),'utf-8'))
        v = self.c*R + (self.d * R * w)
        return (u1,u2,e,v)

    def _pad(self, x,l):
        return (b'-' * (l-len(x)))+x

    def dual_encrypt(self, m, R, S):
        u = self.g1*R + self.g2*S
        v = self.h1*R + self.h2*S + m
        return (u, v)

    def _default_error(self, err):
        self.write( 'p2z', msg=('error', err) )

    def _respond(self, fro, ins, resp, state):
        if resp is not None:
            self.write('p2f', ('sendmsg', fro, resp))
            self.state[ins] = state
