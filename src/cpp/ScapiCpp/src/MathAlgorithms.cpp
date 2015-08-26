#include "../include/MathAlgorithms.hpp"

biginteger modInverse(biginteger a, biginteger m)
{
	biginteger b0 = m, t, q;
	biginteger x0 = 0, x1 = 1;
	if (m == 1) return 1;
	while (a > 1) {
		q = a / m;
		t = m, m = a % m, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}

biginteger MathAlgorithms::chineseRemainderTheorem(vector<biginteger> congruences, vector<biginteger> moduli)
{
	biginteger retval = 0;
	biginteger all = 1;
	for (int i = 0; i < moduli.size(); i++)
		all *= moduli[i];
	//all = all.multiply((BigInteger)moduli.elementAt(i));
	for (int i = 0; i < moduli.size(); i++)
	{
		biginteger a = moduli[i];
		biginteger b = 1 / a; //all.divide(a);
		biginteger b_ = modInverse(b, a);// b.modInverse(a);
		biginteger tmp = b*b_; // b.multiply(b_);
		tmp *= congruences[i]; //tmp = tmp.multiply((BigInteger)congruences.elementAt(i));
		retval += tmp; // retval.add(tmp);
	}
	return retval % all; //return retval.mod(all);
}

///**
//* Computes n!  (n factorial)
//* @param n
//* @return n!
//*/
//public static int factorial(int n) {
//	int fact = 1; // this  will be the result 
//	for (int i = 1; i <= n; i++) {
//		fact *= i;
//	}
//	return fact;
//}
//
///**
//* Computes n!  (n factorial)
//* @param n
//* @return n! as a BigInteger
//*/
//public static BigInteger factorialBI(int n) {
//	BigInteger fact = BigInteger.ONE; // this  will be the result 
//	for (int i = 1; i <= n; i++) {
//		//fact *= i;
//		fact = fact.multiply(BigInteger.valueOf(i));
//	}
//	return fact;
//}
//
MathAlgorithms::SquareRootResults MathAlgorithms::sqrtModP_3_4(biginteger z, biginteger p) {
	//We assume here (and we do not check for efficiency reasons) that p is a prime
	//We do check that the prime p = 3 mod 4, if not throw exception 
	if (p%4 != 3)
		throw invalid_argument("p has to be a prime such that p = 3 mod 4");

	biginteger exponent = (p + 1) / 4;
	biginteger x = mp::powm(z, exponent, p);  // z.modPow(exponent, p);
	return SquareRootResults(x, (-x) % p);// x.negate().mod(p));
}

/*-------------------------------------------------------------*/
//}