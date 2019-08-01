import dump
import comm
import gevent
from itm import ITMFunctionality, ITMPassthrough, ITMAdversary, createParties, ITMPrinterAdversary, ITMProtocol
from utils import z_mine_blocks, z_send_money, z_get_balance, z_get_leaks, z_tx_leak, z_tx_leaks, z_delay_tx, z_set_delays, z_deploy_contract, z_mint, z_start_ledger, z_ideal_parties, z_sim_party, z_genym, z_real_parties, z_mint_mine, z_prot_input, z_instant_input, z_inputs, z_tx_inputs, z_ping, print
from g_ledger import Ledger_Functionality, LedgerITM
from collections import defaultdict
from gevent.queue import Queue, Channel
from f_state import StateChannel_Functionality, StateITM, Sim_State
from pay_protocol import Contract_Pay, Pay_Protocol, Adv, U_Pay
from protected_wrapper import Protected_Wrapper, ProtectedITM

def exe(result): 
    dump.dump_wait()

'''Blockchain Functionality'''
g_ledger, protected, ledger_itm = z_start_ledger('sid1',0,Ledger_Functionality,ProtectedITM)
comm.setFunctionality(ledger_itm)
'''sim'd party'''
simparty = z_sim_party('sid2',23,ITMPassthrough,ledger_itm)
comm.setParty(simparty)
caddr = simparty.subroutine_call( ('get-caddress',) )
'''State Functionality'''
idealf, state_itm = StateITM('sid2', 1, ledger_itm, caddr, U_Pay, 2,3)
comm.setFunctionality(state_itm)
gevent.spawn(state_itm.run)
''' Parites'''
rparties = z_real_parties('sid2', [2,3], ITMProtocol, Pay_Protocol, state_itm, ledger_itm, caddr)
comm.setParties(rparties)
pl = rparties[0]; pr = rparties[1]
'''Adversary'''
adversary = Adv('sid', 7, ledger_itm, state_itm, pr, Contract_Pay)
advitm = ITMAdversary('sid', 7)
advitm.init(adversary)
comm.setAdversary(advitm)
gevent.spawn(advitm.run)

pladdr = z_genym((pl.sid,pl.pid), ledger_itm)
praddr = z_genym((pr.sid,pr.pid),ledger_itm)
print('pladdr', pladdr, 'praddr', praddr)
'''Deploy Contract_Pay'''
caddr = z_deploy_contract(simparty, advitm, ledger_itm, Contract_Pay, pladdr, praddr)
gevent.spawn(state_itm.run)

z_inputs(('input',([],0)), pl, pr)
z_ping(pl)
z_mint_mine(simparty, advitm, ledger_itm, pl, pr)
z_tx_inputs(advitm, ledger_itm, ('deposit', 10), simparty, pl, pr)
z_inputs(('pay', 2), pl)
z_mine_blocks(8, simparty, ledger_itm)
z_ping(pl)
z_mine_blocks(1, simparty, ledger_itm)
z_inputs(('withdraw',5), pr)
z_inputs(('pay', 2), pr)
z_ping(pr)
z_mine_blocks(9, simparty, ledger_itm)
z_ping(pr)

#print('outputs outputs', state_itm.outputs)
