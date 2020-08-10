import comm
import gevent
from itm import ITM
from gevent.queue import Queue, Channel, Empty
from gevent.event import AsyncResult
class DummyAdversary(ITM):
    '''Implementation of the dummy adversary. Doesn't do anything locally,
     just forwards all messages to the intended party. Z communicates with
     corrupt parties through dummy adversary'''
    #def __init__(self, sid, pid, z2a, a2z, p2a, a2p, a2f, f2a):
    def __init__(self, sid, pid, channels, pum, poly, importargs):
        UCAdversary.__init__(self, sid, pif, channels, poly, importargs)
    
    def __str__(self):
        return str(self.F)

    def read(self, fro, msg):
        print(u'{:>20} -----> {}, msg={}'.format(str(fro), str(self), msg))

    def input_corrupt(self, pid):
        comm.corrupt(self.sid, pid)

    def env_msg(self, d):
        msg = d.msg
        imp = d.imp
        if msg[0] == 'A2F':
            t,msg,iprime = msg
            self.write('a2f', msg, iprime )
        elif msg[0] == 'A2P':
            t,msg,iprime = msg
            self.write('a2p', msg, iprime )
        elif msg[0] == 'corrupt':
            self.input_corrupt(msg[1])
        else: 
            self.pump.write("dump")

    def party_msg(self, d):
        msg = d.msg
        imp = d.imp
        assert imp == 0
        self.channels['a2z'].write( msg )

    def func_msg(self, d):
        msg = d.msg
        imp = d.imp
        assert imp == 0
        self.channels['a2z'].write(msg)


    '''
        Instead of waiting for a party to write to the adversary
        the adversary checks leak queues of all the parties in 
        a loop and acts on the first message that is seen. The
        environment can also tell the adversary to get all of the
        messages from a particular ITM.
    '''
    def run(self):
        while True:
            ready = gevent.wait(
                objects=[self.z2a, self.f2a, self.p2a],
                count=1
            )
            r = ready[0]
            if r == self.z2a:
                msg = r.read()
                self.z2a.reset()
                if msg[0] == 'A2F':
                    t,msg = msg
                    if msg[0] == 'get-leaks':
                        self.getLeaks(msg[1])
                    else:
                        self.a2f.write( msg )
                elif msg[0] == 'A2P':
                    t,msg = msg
                    self.a2p.write( msg )
                elif msg[0] == 'corrupt':
                    self.input_corrupt(msg[1])
            elif r == self.p2a:
                msg = r.read()
                self.p2a.reset()
                print('Go back from party', msg)
                self.a2z.write( msg )
            elif r == self.f2a:
                msg = r.read()
                self.f2a.reset()
                self.a2z.write(msg)
            else:
                print('else dumping right after leak'); dump.dump()


class DummyWrappedAdversary(ITM):
    '''Implementation of the dummy adversary. Doesn't do anything locally,
     just forwards all messages to the intended party. Z communicates with
     corrupt parties through dummy adversary'''
    def __init__(self, sid, pid, channels, pump, poly, importargs):
        self.sid = sid
        self.pid = pid
        self.pump = pump
        self.sender = (sid,pid)
    
        handlers = {
            channels['f2a']: self.func_msg,
            channels['z2a']: self.env_msg,
            channels['p2a']: self.party_msg,
            channels['w2a']: self.wrapper_msg,
        }
        
        ITM.__init__(self, sid, pid, channels, handlers, poly, importargs)

        self.input = AsyncResult()
        self.leak = AsyncResult()
        self.leakbuffer = []
    
    def __str__(self):
        return str(self.F)

    def read(self, fro, msg):
        print(u'{:>20} -----> {}, msg={}'.format(str(fro), str(self), msg))

    def input_corrupt(self, pid):
        comm.corrupt(self.sid, pid)


    '''
        Messages from the environment inteded for the dummy address can 
        carry import and also specify in the message body how much import 
        to forward with the message being sent. Dummy adversary as specified
        in the UC paper accepts messages of the form (i, (msg, ..., i')) where 
        i is the import sent to the dummy and i' is the import to be sent by
        the dummy to other parties.
    '''
    def env_msg(self, d):
        msg = d.msg
        imp = d.imp
        if msg[0] == 'A2F':
            t,msg,iprime = msg
            self.write('a2f', msg, iprime )
        elif msg[0] == 'A2P':
            t,msg,iprime = msg
            self.write('a2p', msg, iprime )
        elif msg[0] == 'A2W':
            t,msg,iprime = msg
            self.write('a2w', msg, iprime )
        elif msg[0] == 'corrupt':
            self.input_corrupt(msg[1])
        else: self.pump.write("dump")#dump.dump()

    def party_msg(self, d):
        msg = d.msg
        imp = d.imp
        assert imp == 0
        self.channels['a2z'].write( msg )

    def func_msg(self, d):
        msg = d.msg
        imp = d.imp
        assert imp == 0
        self.channels['a2z'].write(msg)

    def wrapper_msg(self, d):
        msg = d.msg
        imp = d.imp
        assert imp == 0
        self.channels['a2z'].write(msg)

