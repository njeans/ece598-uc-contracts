from uc.utils import waits, collectOutputs
import gevent
from secp256k1 import *
from utils import *

"""
This files contains several environments that are run by execUC a the
bottom of the files. All environments conform to some default behavior:
  1. Setting the SID of this session. The SID often encodes protocol parameters.
  2. The list of corrupt parties. This is the static corruptions model.
  3. Return some transcript of the communication from the honest parties and the
    adversary.
"""

def env(k, static, z2p, z2f, z2a, a2z, f2z, p2z, pump):
    print('\033[94m[ env_honest ]\033[0m')

    # The SID is encoded, ideally, as a tupe of strings. In reality
    # you can encode it however you want as long as the protocols/functionalities
    # you are running know how to parse it for information. The string is the
    # easiest as it works well with the multisession extension. ITMs then parse
    # the SID using `literal_eval` from the `ast` python package. In this example
    # the SID encodes some string to identify the session and the two PIDs of the
    # parties in this protocol: 1 and 2.
    # See prot_com and F_com for how the SID is parsed.
    sid = ('one', "1, 2, 3, 4")

    # The static channel is given by `execUC` which waits to read the sid
    # and the set of crupt parties. In this case there are no crupt parties
    # hence nothing after `crupt`.
    static.write( (('sid',sid), ('crupt',)))

    # these two functions simply wait to read on the p2z and a2z channels
    # of the environment and append the message to a transcript that is returned
    # at the end of the environment code. Often times, when there are corrupt
    # parties you'll want to manually read from the a2z channel or p2z channel
    # and use the information in a meaningful way. (See other environments in this
    # and other apps.
    transcript = []
    def _a2z():
        while True:
            m = waits(a2z)
            transcript.append('a2z: ' + str(m))
            pump.write('dump')

    def _p2z():
        while True:
            m = waits(p2z)
            transcript.append('p2z: ' + str(m))
            pump.write('dump')

    # spawn the functions
    g1 = gevent.spawn(_a2z)
    g2 = gevent.spawn(_p2z)


    # party 1 commit to party 2 val="m:1to2" w/ ssid "a"
    z2p.write( (1, ('commit',2,"a","m:1to2")))
    waits(pump)
    # waits(pump)

    z2p.write( (2, ('commit',3,"a","m:2to3")))
    waits(pump)
    # the `pump` channel is given to ALL ITMs and it is used for them to
    # forfeit control back to the environment. An ITM may either write
    # to another ITM or return control to the environment through `pump`.

    z2p.write( (2, ('reveal',3,"a")))
    waits(pump)

    z2p.write( (1, ('reveal',2,"a")))
    waits(pump)


    # kill the two threads
    gevent.kill(g1)
    gevent.kill(g2)

    # return the transcript
    print('transcript', transcript)
    return transcript

def env_committer_crupt_bad_c(k, static, z2p, _, z2a, a2z, f2z, p2z, pump):
    print('\033[94m[ env_committer_crupt_bad_c ]\033[0m')

    sid = ('one', "1, 2")

    static.write( (('sid',sid), ('crupt', 1)))

    transcript = []
    def _p2z():
        while True:
            m = waits(p2z)
            #transcript.append('p2z: ' + str(m.msg))
            transcript.append(m)
            print('p2z: ' + str(m))
            try:
                pump.write('')
            except:
                pass
    def _a2z():
        while True:
            print("wait _a2z")
            m = waits(a2z)
            print("recv _a2z")
            #transcript.append('p2z: ' + str(m.msg))
            transcript.append(m)
            print('a2z: ' + str(m))
            try:
                pump.write('')
            except:
                pass

    gevent.spawn(_p2z)

    print("env call value")

    z2a.write( ('A2F', ('value',)))
    res = waits(a2z)
    pk = res[1]

    rand_x =Fq(64507471261611761880264178918529909889494982960490464220285243851186690568124)
    _m = solve(rand_x)
    # _m = make_random_point()
    # print("_m.x",_m.x)
    _sid = Ginv(_m)[:2]
    rand_str =  b'E\x18 \xfa\xe0\xb9\xfe\xd9\xa2\x89\x88\xc9\xdfE\xec\xa4\xa4\xbc\xc5\xea\xa8s(\n\xe4\xda\xa19)\xbe\x11x'
    # print("rand_str",rand_str)
    _r = Fp(uint256_from_str(rand_str))
    _c = encrypt(pk, _r, _m)
    _cid = "k"
    _ssid = bytes(_cid,"utf-8")

    z2a.write( ('A2P', (1, ('sendmsg', 2, ('commit',(_cid, _sid,_c))))))
    waits(pump)

    z2a.write( ('A2P', (1, ('sendmsg', 2, ('reveal',(_cid, "fake"))))))
    _,res = waits(a2z)
    print("cprime res",res)
    cprime=res[1][2][1][1]

    rand_str2 = b"\xb6Qv\xe1>iV\xfcss\x0b\x9f\xde\x89}\xe6\xe2\x7f1\xf5\xe4/\x1a\xe0\xf8\xed\x16\xb5'\xca\xa0\x9d"
    _s = Fp(uint256_from_str(rand_str2))
    _alpha = pk[0] * _s
    _beta = pk[1] * _s
    _gamma = pk[4] * _s
    _u1 = pk[0]* _r
    _u2 = pk[1] * _r
    _e= pk[4] * _r + _m
    _w = hash(bytes(str(_u1),'utf-8')+bytes(str(_u2),'utf-8')+bytes(str(_e),'utf-8'))
    _delta = (pk[2] + (pk[3]*_w))*_s
    step_b_msg = (_cid,(_alpha, _beta, _gamma, _delta))

    z2a.write( ('A2P', (1, ('sendmsg', 2, ('b',step_b_msg)))))
    _,res = waits(a2z)
    gevent.spawn(_a2z)


    res = res[1][2][1][1]
    _R,_S,_epsilon= res

    _chal = G(inp=_epsilon)
    _epsilon_num = uint256_from_str(_epsilon)

    _z = _s + (_epsilon_num+_r)
    z2a.write( ('A2P', (1, ('sendmsg', 2, ('d',(_cid,_z))))))

    waits(pump)
    # waits(pump)
    return transcript

def env_committer_crupt_bad_a(k, static, z2p, z2f, z2a, a2z, f2a, p2z, pump):
    print('\033[94m[ env_committer_crupt_bad_a ]\033[0m')
    sid = ('one', "1, 2")
    static.write( (('sid',sid), ('crupt', 1)))

    transcript = []
    def _p2z():
        while True:
            m = waits(p2z)
            #transcript.append('p2z: ' + str(m.msg))
            transcript.append(m)
            print('p2z: ' + str(m))
            try:
                pump.write('')
            except:
                pass
    def _a2z():
        while True:
            m = waits(a2z)
            #transcript.append('p2z: ' + str(m.msg))
            transcript.append(m)
            print('a2z: ' + str(m))
            try:
                pump.write('')
            except:
                pass

    gevent.spawn(_p2z)

    z2a.write( ('A2F', ('value',)))
    res = waits(a2z)
    pk = res[1]

    _x = b'real'
    _i = bytes(str(1),"utf-8")
    _j = bytes(str(2),"utf-8")
    _cid = "b"
    _ssid = bytes(_cid,"utf-8")
    base = _ssid + _i + _j + _x
    _sid = b'\x94\x81'
    _m,_,_ = G(base=base, extra=_sid)
    rand_str=b"|F\xe4\x86\x1bu\x02\xeeg\xaeZ\x90\x9b\xfee(\x96\xb4\xd5'\x19yX\xc8\xeac\x8b\x18_\x95\xe1t"
    _r = Fp(uint256_from_str(rand_str))
    _c = encrypt(pk, _r, _m)

    gevent.spawn(_a2z)

    z2a.write( ('A2P', (1, ('sendmsg', 2, ('commit',(_cid, _sid,_c))))))
    waits(pump)

    z2a.write( ('A2P', (1, ('sendmsg', 2, ('reveal',(_cid, "fake"))))))
    waits(pump)

    return transcript

def env_receiver_crupt(k, static, z2p, z2f, z2a, a2z, f2z, p2z, pump):
    print('\033[94m[ env_receiver_crupt ]\033[0m')
    sid = ('one', "1, 2")

    # same SID but now PID=2 is crupt
    static.write( (('sid',sid), ('crupt', 2)))

    transcript = []
    def _p2z():
        while True:
            m = waits(p2z)
            #transcript.append('p2z: ' + str(m.msg))
            transcript.append(m)
            print('p2z: ' + str(m))
            try:
                pump.write('')
            except:
                pass
    def _a2z():
        while True:
            m = waits(a2z)
            #transcript.append('p2z: ' + str(m.msg))
            transcript.append(m)
            print('a2z: ' + str(m))
            try:
                pump.write('')
            except:
                pass

    gevent.spawn(_p2z)

    print("env call value")

    z2a.write( ('A2F', ('value',)))
    res = waits(a2z)
    pk = res[1]

    cid="a"
    msg="m:1to2"
    z2p.write( (1, ('commit',2,cid,msg)))
    res=waits(a2z)
    z2p.write( (1, ('reveal',2,cid)))
    res=waits(a2z)

    chal,p1,p2 = G(base=b'')
    epsilon = p1+p2
    R=Fp(uint256_from_str(os.urandom(32)))
    S=Fp(uint256_from_str(os.urandom(32)))
    cprime = dual_encrypt(pk,chal, R, S)

    z2a.write( ('A2P', (2, ('sendmsg', 1, ('a',(cid,cprime))))))
    res=waits(a2z)

    chalhat,p1hat,p2hat = G(base=b'')
    epsilonhat = p1hat+p2hat
    Rhat=Fp(uint256_from_str(os.urandom(32)))
    Shat=Fp(uint256_from_str(os.urandom(32)))
    cprimehat = dual_encrypt(pk,chalhat, Rhat, Shat)

    z2a.write( ('A2P', (2, ('sendmsg', 1, ('c',(cid,(Rhat,Shat,epsilonhat)))))))
    gevent.spawn(_a2z)
    waits(pump)
    return transcript

# Distinguisher might be a bad name here, this just prints the
# transcripts in a pretty way and compares them with direct
# equality. In reality many times with protocols that sample
# random information like the pedersen commitment, the transcripts
# ay never be equal.
def distinguisher(t_ideal, t_real):
    print('\n\t\033[93m Ideal transcript\033[0m')
    for i in t_ideal: print(str(i))

    print('\n\t\033[93m real transcript\033[0m')
    for i in t_real: print(str(i))

    if t_ideal == t_real:
        print("\033[92m[Distinguisher] They're the same\033[0m")
    else:
        print("\033[91m[Distinguisher] They're different\033[0m")

from uc.adversary import DummyAdversary
from f_crs import F_CRS
from prot_mcom import MCommitment_Prot
from uc.execuc import execUC
from f_mcom import F_Mcom
from sim_mcom import Sim_MCom
from uc.protocol import DummyParty, protocolWrapper

if __name__=='__main__':
    # run the ideal execution first with the dummy parties
    # and the simulator that we created

    print('ideal: honest')
    tideal_honest = execUC(
        256,
        env,
        F_Mcom,
        DummyParty,
        Sim_MCom,
    )
    print('\nreal: honest')

    treal_honest = execUC(
        256,
        env,
        F_CRS,
        MCommitment_Prot,
        DummyAdversary,
    )

    distinguisher(tideal_honest, treal_honest)

    print('\nideal: corrupt commit fail proof step a')

    tideal_committer_crupt_bad_a = execUC(
        256,
        env_committer_crupt_bad_a,
        F_Mcom,
        DummyParty,
        Sim_MCom,
    )

    print('\nreal: corrupt commit fail proof step a')

    treal_committer_crupt_bad_a = execUC(
        256,
        env_committer_crupt_bad_a,
        F_CRS,
        MCommitment_Prot,
        DummyAdversary
    )

    distinguisher(tideal_committer_crupt_bad_a, treal_committer_crupt_bad_a)

    print('\nreal: corrupt commit fail proof step c')

    treal_committer_crupt_bad_c = execUC(
        256,
        env_committer_crupt_bad_c,
        F_CRS,
        MCommitment_Prot,
        DummyAdversary
    )


    print('\nideal: corrupt commit fail proof step c')

    tideal_committer_crupt_bad_c = execUC(
        256,
        env_committer_crupt_bad_c,
        F_Mcom,
        DummyParty,
        Sim_MCom,
    )

    distinguisher(tideal_committer_crupt_bad_c, treal_committer_crupt_bad_c)

    print('\nreal: receiver corrupt')

    treal_recv_corrupt = execUC(
        256,
        env_receiver_crupt,
        F_CRS,
        MCommitment_Prot,
        DummyAdversary
    )


    print('\nideal: receiver corrupt')

    tideal_recv_corrupt = execUC(
        256,
        env_receiver_crupt,
        F_Mcom,
        DummyParty,
        Sim_MCom,
    )

    distinguisher(tideal_recv_corrupt, treal_recv_corrupt)
