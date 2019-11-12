import gevent
import random
import dump
import comm
from itm import ITMFunctionality
from utils import print
from hashlib import sha256
from g_ledger import Ledger_Functionality
from collections import defaultdict
from gevent.event import AsyncResult
from gevent.queue import Channel, Queue


'''
    Sits between the parties and the g_ledger functionality. It creates
    and stores the mapping between sid,pid and pseudonym. The purpose of
    this distinction is so that the ideal world doesn't have to try to 
    match the address of the real world contract that was deployed.
    Example: since the environment can assign public keys to each itm that
    is deployed, it can give real world and ideal world difference public
    keys. Then the contract address is different, so contract can be distinguished
    since information about nonces and address is known

    sid access is also restricted. Only those in the same sid can access a
    private contracts. 

    Q: Why is it necessary to have this extra layer if all it does is translate
        sid,pid pairs into addresses? Couldn't you just have g_ledger deal with
        only sid,pid pairs?
    A: No, you can't because in the real world a contract is deployed to the 
        blockchain that is not a functionality or an itm and hence has no
        sid,pid assigned to it. If a random one is assigned, the environment
        can clearly see one case where all txs go to/from an sid,pid pair in the
        ideal world and the other case where a random generated addresses
        is used, essentially revealing which one is the real world or ideal world.
'''
class Protected_Wrapper(object):
    def __init__(self, ledger):
        self.ledger = ledger
        self.addresses = {}
        self.raddresses = {}
        self.private = {}
        self.clock = None; self.c2c = None

        self.outputs = self.ledger.outputs
        self.adversary_out = self.ledger.adversary_out
        
        self.DELTA = self.ledger.DELTA

    def __str__(self):
        return str(self.ledger)

    def iscontract(self, addr):
        return addr in self.ledger.contracts

    def set_clock(self, c2c, clock):
        self.c2c = c2c; self.clock = clock

    '''
        All honest parties must access the protected mode.
        This means that they can only see sid,pid combos and no actual mapping between
        then and pseudonyms in the underlying blockchain
    '''

    def input_msg(self, sender, _msg):
        sid,pid = None,None
        if sender:
            sid,pid = sender
            #if sender not in self.addresses:
            #    a = self.subroutine_genym(sender)
        
        # if functionality, it can choose wrapper/no-wrapper
        # adversary can also decide which he wants to talk to
        if comm.isf(sid,pid) or comm.isadversary(sid,pid):
            print('msg', _msg)
            wrapper,msg = _msg
        else:
            msg = _msg
            wrapper = True
    
        if not wrapper:
            if msg[0] == 'tick' and comm.isadversary(sid,pid):
                self.ledger.adversary_msg(sender, msg)
            else:
                self.ledger.input_msg(sender, msg)
        else:
            if msg[0] == 'transfer':
                _,_to,_val,_data,_fro = msg
                '''Special rules for contracts'''
                if self.iscontract(_to):
                    '''Contracts that are private and accessed by other sid
                    can only receive money from them, no execution'''
                    if _to in self.private and sid != self.private[_to]:
                        data = ()
                ''' Only a functionality can send a transaction FROM a random address.'''
                if comm.isf(sid,pid):
                    fro = _fro
                else:
                    fro = sender
                msg = (msg[0], _to, _val, _data, fro)
            elif msg[0] == 'tick':
                _,_sender = msg
                msg = (msg[0], _sender)
            elif msg[0] == 'contract-create':
                _,_addr,_val,_data,_private,_fro = msg
                if comm.isf(sid,pid):
                    fro = _fro
                else:
                    fro = sender
                ''' No translation necessary for the address '''
                if _private: self.private[_addr] = sid
                msg = (msg[0],_addr,_val,_data,_private,fro)
                print('Contract create, private:', _private)

            self.ledger.input_msg(sender,msg)

    def genym(self, key):
        if key not in self.addresses:
            return self.subroutine_genym(key)
        else:
            return self.addresses[key]

    def rgenym(self, image):
        assert image in self.raddresses, "{} no in self.raddresses {}".format(image, self.raddresses)
        return self.raddresses[image]

    def subroutine_genym(self, key):
        p = str(key).encode()
        h = sha256(p).hexdigest()[24:]
        #print('[PROTECTED]', 'new pseudonym ( %s, %s )' % (key, h))
        self.addresses[key] = h
        self.raddresses[h] = key
        return self.addresses[key]

    def subroutine_gettx(self, addr, to, fro):
        #assert to >= fro, 'to:%s   fro:%s' % (to, fro)
        if fro >= to: return []
        output = []
        '''Need to include 'to' in the range'''
        for blockno in range(fro,to+1):
            txqueue = self.ledger.txqueue[blockno]
            for tx in txqueue:
                if tx[0] == 'transfer':
                    to,val,data,fro,nonce = tx[1:]
                    if to == addr or fro == addr:
                        output.append((to, fro, val))  # Append (sender, amount)

        ''' Convert all addresses to sid,pid shit'''
        for i in range(len(output)):
            to,fro,val = output[i]
            output[i] = (self.rgenym(to), self.rgenym(fro), val)
        return output

    def subroutine_get_addr(self, sid, pid, key):
        if not comm.isf(sid,pid) and not comm.isadversary(sid,pid) and (sid,pid) != key:
            return None

        if key in self.addresses:
            return self.addresses[key]
        else:
            return None
    '''
        So far subroutine messages are only for the ledger
        so they are passed through all of the time
    '''
    def subroutine_msg(self, sender, _msg):
        sid,pid = sender

        if comm.isf(sid,pid) or comm.isadversary(sid,pid):
            try:
                wrapper,msg = _msg
            except ValueError:
                msg = _msg
                wrapper = False
        else:
            msg = _msg
            wrapper = True

        if wrapper:
            if msg[0] == 'genym':
                return self.genym((sid,pid))
            elif msg[0] == 'getbalance':
                _,_addr = msg
                addr = _addr
                msg = (msg[0], addr)
                return self.ledger.subroutine_msg(sender,msg)
            elif msg[0] == 'get-caddress':
                addr = (sid,pid)
                msg = (msg[0], addr)
                return self.ledger.subroutine_msg(sender,msg)
            elif msg[0] == 'compute-caddress':
                addr = self.genym((sid,pid))
                addr = (sid,pid)
                msg = (msg[0], addr, msg[1])
                return self.ledger.subroutine_msg(sender, msg)
            elif msg[0] == 'get-nonce':
                print('\n\tNONCE', msg)
                #addr = self.genym((sid,pid))
                addr = (sid,pid)
                msg = (msg[0], addr)
                return self.ledger.subroutine_msg(sender, msg)
            elif msg[0] == 'get-addr':# and (comm.isf(*sender) or comm.isadversary(*sender)):
                return self.subroutine_get_addr(sid, pid, msg[1])
            elif msg[0] == 'get-txs':
                # TODO will cause problems
                _,_addr,blockto,blockfro = msg
                #if self.iscontract(_addr): addr = _addr
                #else: addr = self.genym(_addr)
                addr = _addr
                print('\t\t\t_addr={}\tblockto={}\tblockfro={}\n\t\t\taddr={}'.format(_addr,blockto,blockfro,addr))
                txs = self.ledger.subroutine_msg(sender, ('get-txs',addr,blockto,blockfro))
                o = []
                for tx in txs:
                    to,fro,val,data,nonce = tx
                    #if not self.iscontract(to): self.rgenym(to)
                    #if not self.iscontract(fro): fro = self.rgenym(fro)
                    o.append( (to,fro,val,data,nonce)  )
                return o
            elif msg[0] == 'read-output':
                _,_outputs = msg
                outputs = []
                for o in _outputs:
                    _sender,_nonce = o
                    #outputs.append( (self.genym(sender), _nonce))
                    outputs.append( (_sender, _nonce) )
                msg = (msg[0], outputs)
                return self.ledger.subroutine_msg(sender, msg)
            elif msg[0] == 'contract-ref':
                _,_addr = msg
                if self.iscontract(_addr):
                    if _addr in self.private:
                        if sid == self.private[to]:
                            return self.ledger.subroutine_msg(sender,msg)
                    else:
                        return self.ledger.subroutine_msg(sender,msg)
            else:
                return self.ledger.subroutine_msg(sender, msg)
        else:
            return self.ledger.subroutine_msg(sender, msg)

    '''
        Unlike honest parties, adversary doesn't need to use the protected
        mode.
    '''
    def adversary_msg(self, _msg):
        #sid,pid = sender
        #print('PROTECTED MODE MESSAGE', _msg)
        wrapper,msg = _msg
        #print('DEBUG: adversary msg', msg)
        if not wrapper:
            self.ledger.adversary_msg(msg)
        else:
            if msg[0] == 'tick':
                addr = self.genym(sender)
                msg = (msg[0], addr, msg[1])
            self.ledger.adversary_msg(msg)

class Protected_Wrapper2(object):
    def __init__(self, ledger):
        self.ledger = ledger
        self.addresses = {}
        self.raddresses = {}
        self.private = {}
        self.clock = None; self.c2c = None

        self.outputs = self.ledger.outputs
        self.adversary_out = self.ledger.adversary_out
        
        self.DELTA = self.ledger.DELTA

    def __str__(self):
        return str(self.ledger)

    def iscontract(self, addr):
        return addr in self.ledger.contracts

    def set_clock(self, c2c, clock):
        self.c2c = c2c; self.clock = clock

    '''
        All honest parties must access the protected mode.
        This means that they can only see sid,pid combos and no actual mapping between
        then and pseudonyms in the underlying blockchain
    '''

    def input_msg(self, sender, _msg):
        sid,pid = None,None
        print("PROTECTED MSG", sender, _msg)
        if sender:
            sid,pid = sender
            #if sender not in self.addresses:
            #    a = self.subroutine_genym(sender)
        
        # if functionality, it can choose wrapper/no-wrapper
        # adversary can also decide which he wants to talk to
        if comm.isf(sid,pid) or comm.isadversary(sid,pid):
            print('msg', _msg)
            wrapper,msg = _msg
        else:
            msg = _msg
            wrapper = True
    
        if not wrapper:
            if msg[0] == 'tick' and comm.isadversary(sid,pid):
                self.ledger.adversary_msg(sender, msg)
            else:
                self.ledger.input_msg(sender, msg)
        else:
            # transfer
            if msg[0] == 'transfer':
                _,_to,_val,_data,_fro = msg
                '''Special rules for contracts'''
                if self.iscontract(_to):
                    '''Contracts that are private and accessed by other sid
                    can only receive money from them, no execution'''
                    if _to in self.private and sid != self.private[_to]:
                        data = ()
                ''' Only a functionality can send a transaction FROM a random address.'''
                if comm.isf(sid,pid):
                    fro = _fro
                else:
                    fro = sender
                msg = (msg[0], _to, _val, _data, fro)
            # tick
            elif msg[0] == 'tick':
                _,_sender = msg
                msg = (msg[0], _sender)
            # contract-create
            elif msg[0] == 'contract-create':
                _,_addr,_val,_data,_private,_fro = msg
                if comm.isf(sid,pid):
                    fro = _fro
                else:
                    fro = sender
                ''' No translation necessary for the address '''
                if _private: self.private[_addr] = sid
                msg = (msg[0],_addr,_val,_data,_private,fro)
                print('Contract create, private:', _private)
            # get-caddress
            elif msg[0] == 'get-caddress':
                msg = (msg[0], sender)
            # get-txs
            elif msg[0] == 'get-txs':
                _,_addr,blockto,blockfro = msg
                addr = _addr
                print('\t\t\t_addr={}\tblockto={}\nblockfro={}\n\t\t\taddr={}'.format(_addr,blockto,blockfro,addr))
                txs = self.ledger.input_msg(sender, ('get-txs', addr, blockto, blockfro))
                #txs = self.ledger.subroutine_msg(sender, ('get-txs', addr, blockto, blockfro))
                #o = []
                #for tx in txs:
                #    to,fro,val,data,nonce = tx
                #    o.append( (to,fro,val,data,nonce) )
                #self.f2_.write( ((sid,pid), o) )
                return
            elif msg[0] == 'block-number':
                self.ledger.input_msg( (sid,pid), ('block-number',))
                #self.f2_.write( ((sid,pid), self.ledger.round) )
                return
            self.ledger.input_msg(sender,msg)

    def genym(self, key):
        if key not in self.addresses:
            return self.subroutine_genym(key)
        else:
            return self.addresses[key]

    def rgenym(self, image):
        assert image in self.raddresses, "{} no in self.raddresses {}".format(image, self.raddresses)
        return self.raddresses[image]

    def subroutine_genym(self, key):
        p = str(key).encode()
        h = sha256(p).hexdigest()[24:]
        #print('[PROTECTED]', 'new pseudonym ( %s, %s )' % (key, h))
        self.addresses[key] = h
        self.raddresses[h] = key
        return self.addresses[key]

    def subroutine_gettx(self, addr, to, fro):
        #assert to >= fro, 'to:%s   fro:%s' % (to, fro)
        if fro >= to: return []
        output = []
        '''Need to include 'to' in the range'''
        for blockno in range(fro,to+1):
            txqueue = self.ledger.txqueue[blockno]
            for tx in txqueue:
                if tx[0] == 'transfer':
                    to,val,data,fro,nonce = tx[1:]
                    if to == addr or fro == addr:
                        output.append((to, fro, val))  # Append (sender, amount)

        ''' Convert all addresses to sid,pid shit'''
        for i in range(len(output)):
            to,fro,val = output[i]
            output[i] = (self.rgenym(to), self.rgenym(fro), val)
        return output

    def subroutine_get_addr(self, sid, pid, key):
        if not comm.isf(sid,pid) and not comm.isadversary(sid,pid) and (sid,pid) != key:
            return None

        if key in self.addresses:
            return self.addresses[key]
        else:
            return None
    '''
        So far subroutine messages are only for the ledger
        so they are passed through all of the time
    '''
    def subroutine_msg(self, sender, _msg):
        sid,pid = sender

        if comm.isf(sid,pid) or comm.isadversary(sid,pid):
            try:
                wrapper,msg = _msg
            except ValueError:
                msg = _msg
                wrapper = False
        else:
            msg = _msg
            wrapper = True

        if wrapper:
            if msg[0] == 'genym':
                return self.genym((sid,pid))
            elif msg[0] == 'getbalance':
                _,_addr = msg
                addr = _addr
                msg = (msg[0], addr)
                return self.ledger.subroutine_msg(sender,msg)
            elif msg[0] == 'get-caddress':
                addr = (sid,pid)
                msg = (msg[0], addr)
                return self.ledger.subroutine_msg(sender,msg)
            elif msg[0] == 'compute-caddress':
                addr = self.genym((sid,pid))
                addr = (sid,pid)
                msg = (msg[0], addr, msg[1])
                return self.ledger.subroutine_msg(sender, msg)
            elif msg[0] == 'get-nonce':
                #addr = self.genym((sid,pid))
                addr = (sid,pid)
                msg = (msg[0], addr)
                return self.ledger.subroutine_msg(sender, msg)
            elif msg[0] == 'get-addr':# and (comm.isf(*sender) or comm.isadversary(*sender)):
                return self.subroutine_get_addr(sid, pid, msg[1])
            elif msg[0] == 'get-txs':
                # TODO will cause problems
                _,_addr,blockto,blockfro = msg
                #if self.iscontract(_addr): addr = _addr
                #else: addr = self.genym(_addr)
                addr = _addr
                print('\t\t\t_addr={}\tblockto={}\tblockfro={}\n\t\t\taddr={}'.format(_addr,blockto,blockfro,addr))
                txs = self.ledger.subroutine_msg(sender, ('get-txs',addr,blockto,blockfro))
                o = []
                for tx in txs:
                    to,fro,val,data,nonce = tx
                    #if not self.iscontract(to): self.rgenym(to)
                    #if not self.iscontract(fro): fro = self.rgenym(fro)
                    o.append( (to,fro,val,data,nonce)  )
                return o
            elif msg[0] == 'read-output':
                _,_outputs = msg
                outputs = []
                for o in _outputs:
                    _sender,_nonce = o
                    #outputs.append( (self.genym(sender), _nonce))
                    outputs.append( (_sender, _nonce) )
                msg = (msg[0], outputs)
                return self.ledger.subroutine_msg(sender, msg)
            elif msg[0] == 'contract-ref':
                _,_addr = msg
                if self.iscontract(_addr):
                    if _addr in self.private:
                        if sid == self.private[to]:
                            return self.ledger.subroutine_msg(sender,msg)
                    else:
                        return self.ledger.subroutine_msg(sender,msg)
            else:
                return self.ledger.subroutine_msg(sender, msg)
        else:
            return self.ledger.subroutine_msg(sender, msg)

    '''
        Unlike honest parties, adversary doesn't need to use the protected
        mode.
    '''
    def adversary_msg(self, _msg):
        #sid,pid = sender
        #print('PROTECTED MODE MESSAGE', _msg)
        wrapper,msg = _msg
        if not wrapper: 
            self.ledger.adversary_msg(msg)
        else:
            if msg[0] == 'tick':
                addr = self.genym(sender)
                msg = (msg[0], addr, msg[1])
            self.ledger.adversary_msg(msg)
from comm import Channel
def ProtectedITM(sid,pid, G, a2f, f2f, p2f):
    p = Protected_Wrapper(G)
    p_itm = ITMFunctionality(sid,pid,a2f,f2f,p2f)
    p_itm.init(p)
    return p, p_itm
