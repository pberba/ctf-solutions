import gmpy2
from math import gcd

from Crypto.Util.number import isPrime, getPrime, bytes_to_long
from Crypto.Util.number import bytes_to_long, long_to_bytes, inverse

n = 13382530295713917123015356265347321094256226566257623545889573061147938007171086142592829334764528434702825531635566369283255332692678671260069812638573184350572810970644394853227367978599113205187410151008372135364394060295976954722797560959041525038250922497629995447141186387045145641624575553004116393538045115640382007521177506372844356599515221123769808759792921557288910541261662071330605482964244218808384883839567178211155363863011452476524600201011039875767940325127282609196357565459539854467622590648672354346990722180911082058098493886116049202007545709584770864598362673608862923836981014279206273097017
e1 = 65537
d1 = 11569455444932772576648367415079245594982518040054082958680004127416877055866142769229969703359760929755598958930190874633423572023464427060332872186341753191857337442586174582207855332582641194737450361411604871225045984226459287130693565601375936121842940123452710408534497128602222588204605057938374149336484991344046184969452360503325068483025278799356513681880021469192847751113510298088839230617951595758843109007278029595681232283778797485901135862107038739149351060518772094867682593519162349240597142862357240797932956424470777291496596508787661226345849862222655652073745922761860271975329314656555016312713
e2 = 78697
ct = 4461852328415864419743101452420387961651156933673863713694420947402421429869721670364426655092362407263142072234174378248471219392117855386367222894744130407609532370830178750575600387702022233241268782964579737764081573978397550577590335855096601816184948403341545535505335757184765869011562485472974997984468216491217981788679749360213892759733091674873206632032015518889157979003123181968736952658371579666643477038906444823824649861271863876401740198790710014620615022343576676868923683803704170440327497263852960257492740456717562069360762813846260931117680928543379201453514283942164106220549947266176556883803

k = (e1*d1) // n + 1
assert (e1 * d1 - 1) % k == 0

# pq = N

# e1*d1 = (p-1)*(q-1) * k + 1
# (e1 * d1 - 1) / k = (p-1)*(q-1)
# (e1 * d1 - 1) / k = p*q - q - p + 1
# (e1 * d1 - 1) / k = N - q - p + 1
# (e1 * d1 - 1) / k - 1 - N  = - q - p
# p + q = N + 1 - (e1 * d1 - 1) / k  = X


X = n + 1 - (e1*d1 - 1) // k

# assert p + q == X


# p = X - q
# n = q * (X - q)
# 0 = X*q - q*q - n
# q*q - X*q + n = 0

# a = 1
# b = X
# c = n

a = 1
b = X
c = n

p = -(-b + gmpy2.isqrt(b**2 - 4*a*c)) // (2*a)
assert n % p == 0
q = n // p

assert (p*q) == n 
assert isPrime(p) 
assert isPrime(q)

phi = (p-1)*(q-1)


print((e1*d1)%phi)
d2 = inverse(e2, phi)
assert (e2*d2)%phi == 1
assert (e1*d1)%phi == 1

temp = 42
_temp = pow(temp, e1, n)
assert pow(_temp, d1, n) == temp

temp = 42
_temp = pow(temp, e2, n)
assert pow(_temp, d2, n) == temp






pt = pow(ct, d2, n)
print(long_to_bytes(pt))


# HTB{tw4s_4-b3d_1d34_t0_us3-th4t_m0dulu5_4g41n-w45nt_1t...}