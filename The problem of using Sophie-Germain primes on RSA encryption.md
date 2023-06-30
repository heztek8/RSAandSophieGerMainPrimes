
Written by: Jorge Hristovsky
LinkedIn - linkedin.com/in/jorge-hristovsky
Email - jchyo@iscte-iul.pt

Feel free to reach out!


## Introduction

This small "paper" goes over a challenge I encountered on a CTF. I decided to do some research in hopes of finding some sort of pattern. This can be interpreted as "fragmented" 
thoughts with just a small "conclusion".



## Problem

Without going too much in-depth Sofie-Germain primes are prime numbers that, with a prime number p :

$$2p + 1$$ 
is also prime.

For example, the number 2. 
- Is a prime? Yes.
- $2p+1$ is also a prime?Yes, $2*2+1$ = 5 and 5 is a prime.

Therefore 2 is a Sophie-Germain prime.
We can also say 5 is a safe prime of 2 or associated prime of 2.

Seems easy enough right? Not so fast, things started getting complicated with big numbers.

Imagine instead of 2, we use a prime with 300 digits. Well, doing $2p+1$ is fairly easy, the problem comes when we want to factorize the generated prime.

Factorizing modestly big primes is alredy a difficult process, but we have serious problems when they are very big. If we keep appending digits to the original prime using the Sophie-Germain "algorithm" the result prime numbers will be bigger and in extension, harder to factorize.

In other words, after doing the simple sum and multiplication, we got either a 300 digit number or a 301 digit number. If the number is even, it's very easy to say if it's prime or not (it's not), but if it is odd we need to do the primality test. If we repeat this process over and over to get new primes eventually we will have very big digit primes that are computationally difficult to factorize.

This is good right? Well for cryptographers it is very good indeed, the computationally difficulty of factorizing  two primes is the whole basis of RSA, but for people that want to crack RSA (us) this is not very good.

Well do not worry, I have come to the rescue.

There are very serious problems with Sophie-Germain primes:

- **They give a numerical relationship between q and p therefore if you are able to crack p, you can easily calculate q.**


Example in CTF:

```
e = 65537
phi = 245339427517603729932268783832064063730426585298033269150632512063161372845397117090279828761983426749577401448111514393838579024253942323526130975635388431158721719897730678798030368631518633601688214930936866440646874921076023466048329456035549666361320568433651481926942648024960844810102628182268858421164
ct = 37908069537874314556326131798861989913414869945406191262746923693553489353829208006823679167741985280446948193850665708841487091787325154392435232998215464094465135529738800788684510714606323301203342805866556727186659736657602065547151371338616322720609504154245460113520462221800784939992576122714196812534


from Crypto.Util.number import getStrongPrime, isPrime, inverse, bytes_to_long as b2l

FLAG = open('flag.txt', 'r').read()

while True:
    q = getStrongPrime(512)
    p = 2*q + 1
    if (isPrime(p)):
        break

n = p*q
phi = (p-1)*(q-1)
e = 0x10001
d = inverse(e, phi)

pt = b2l(FLAG.encode())
ct = pow(pt,e,n)

open('output.txt', 'w').write(f'e: {e}\nd: {d}\nphi: {phi}\nct: {ct}')
```


With a quick glance we can see that this challenge, is a simple RSA implementation but with Sophie-Germain primes instead of regular primes. Let's do a quick recap of what we have:

- We have $phi$, where $\Phi = (p-1) * (q-1)$.
- We also have the exponent (e = 65537).
- And we have the encrypted message ct.

Let's try to get q, since we can easily get p knowing q.

$$\Phi(n) = (q - 1)  * (p-1) (=)$$
$$\Phi(n) = qp - q - p + 1 (=)$$
Since $p = q*q+1$, then:

$$\Phi(n) = q*(2*q+1) - q - (2*q+1) + 1$$
$$\Phi(n) = 2q²+q-q-2q-1$$
$$\Phi(n) = 2q²-2q-1 + 1$$
$$\Phi(n) = 2q² - 2q$$
Solved for q:

$$ 2q² - 2q - \Phi(n) = 0$$


After taking a look at this equation we can quickly conclude that given phi, we can compute p and q therefore breaking the encryption.

I know what you are thinking, if given phi even if we were using big and randomly generated primes we could break encryption. And you are indeed correct.

My main point is the problem of existing a mathematical relation of p and q, therefore if you bruteforce p you do not need to bruteforce q, you can simply calculate it.

Let's get the flag:

```
from Crypto.Util.number import long_to_bytes, bytes_to_long, inverse
from sympy import *

e = 65537
phi = 245339427517603729932268783832064063730426585298033269150632512063161372845397117090279828761983426749577401448111514393838579024253942323526130975635388431158721719897730678798030368631518633601688214930936866440646874921076023466048329456035549666361320568433651481926942648024960844810102628182268858421164
ct = 37908069537874314556326131798861989913414869945406191262746923693553489353829208006823679167741985280446948193850665708841487091787325154392435232998215464094465135529738800788684510714606323301203342805866556727186659736657602065547151371338616322720609504154245460113520462221800784939992576122714196812534

#Calculate q with the above formula
var('q')

#Since this is a quadratic function, there will be 2 correct answers, we obviously want the positive integer

sol = solve(2*q*(-2q)-phi,q)

#Max to get the positive number
q = max(sol)

p = 2*q + 1

N = p * q
d = inverse(e,phi)

#Check if our calculations are correct
assert phi == (q-1) * (p-1)


decoded_message = long_to_bytes(pow(ct, d , N)
print(decoded_message)

```

**flag**: `flag{8b76b85e7f450c39502e71c215f6f1fe}`

## Conclusion

Even though Sophie-Germain primes can be used against certain types of attacks, it's generally not a good ideia to use them for RSA encryption this is because of their mathematical relationship where if we bruteforce just one of the components of N (p or q) we can easily crack the encryption. This is why is always recommended to use **big** and **randomly** generated primes.






















