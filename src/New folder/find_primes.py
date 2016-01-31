#################### is_prime from lecture ####################
import random
 
def is_prime(m, show_witness=False, sieve=False):
    """ probabilistic test for m's compositeness 
    adds a trivial sieve to quickly eliminate divisibility
    by small primes """
    if sieve:
        for prime in [2,3,5,7,11,13,17,19,23,29]:
            if m % prime == 0:
                return False
    for i in range(0,100):
        a = random.randint(1,m-1) # a is a random integer in [1..m-1]
        if pow(a,m-1,m) != 1:
            if show_witness:  # caller wishes to see a witness
                print(m,"is composite","\n",a,"is a witness, i=",i+1)
            return False
    return True
 
 
def find_prime_pair(start,with_sieve=True):
    """ find the first pair of primes q, 2q+1 with q >= start """
    k=random.randint(start,2*start)
#    for i in range(2*k+1,4*k,2):
    if start % 2 == 0:  
        start=start+1
    for i in range(start,2*k,2):
        if is_prime(i,sieve=with_sieve) and is_prime(2*i+1,sieve=with_sieve):
            print(i-start) # how far did we have to go
            return i,2*i+1