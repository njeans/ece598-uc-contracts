import os
from secp256k1 import *

def encrypt(pk, R, m):
    g1 = pk[0]
    g2 = pk[1]
    c = pk[2]
    d = pk[3]
    h = pk[4]
    u1 = g1*R
    u2 = g2*R
    e = h*R + m
    w = hash(bytes(str(u1),'utf-8')+bytes(str(u2),'utf-8')+bytes(str(e),'utf-8'))
    v = c*R + (d * R * w)
    return (u1,u2,e,v)

def decrypt(sk, c):
    x1, x2, y1, y2, z = sk
    u1, u2, e, v = c
    w = hash(bytes(str(u1),'utf-8')+bytes(str(u2),'utf-8')+bytes(str(e),'utf-8'))
    assert (u1*x1 + u2*x2 + ((u1*y1 + u2*y2)*w)) == v
    m = e - (u1*z)
    return m

def Ginv(point):
    return uint256_to_str(int(point.x))

def G(inp=None, base=None, extra=None):
    if inp is not None:
        x = uint256_from_str(inp)
        point = solve(Fq(x))
        return point

    total_len = 32
    len_extra = 2
    desired_base_len = total_len - len_extra
    if len(base) > desired_base_len:
        desired_base = base[:desired_base_len]
    else:
        desired_base = pad(base,desired_base_len)

    if extra is None:
        while True:
            extra = os.urandom(len_extra)
            x = uint256_from_str(extra+desired_base)
            try:
                point = solve(Fq(x))
                break
            except ValueError:
                continue
    else:
        x = uint256_from_str(extra+desired_base)
        point = solve(Fq(x))
    return point,extra,desired_base

def pad(x,l):
    return (b'-' * (l-len(x)))+x

def dual_decrypt(rho, c):
    (u,v) = c
    m = v - (u*rho)
    return m

def dual_encrypt(pk, m, R, S):
    g1=pk[0]
    g2=pk[1]
    h1=pk[5]
    h2=pk[6]

    u = g1*R + g2*S
    v = h1*R + h2*S + m
    return (u, v)
