
using System.Numerics;

public static class NumberTheoryService {
    public static int LegendreSymbol( BigInteger a, BigInteger p ) {
        if( p <= 2 || p % 2 == 0 )
            throw new ArgumentException( "p must be an odd prime greater than 2.", nameof( p ) );

        a %= p;
        if( a < 0 ) a += p;
        if( a <= 1 ) return (int)a;

        BigInteger exponent = (p - 1) >> 1;
        BigInteger result = ModPow( a, exponent, p );

        if( result == 1 ) return 1;
        if( result == p - 1 ) return -1;

        throw new ArgumentException( "p is not prime (Euler's criterion failed).", nameof(p) );
    }

    public static int JacobiSymbol( BigInteger a, BigInteger n ) {
        if( n <= 0 || n % 2 == 0 )
            throw new ArgumentException( "n must be a positive odd integer.", nameof( n ) );

        a %= n;
        if( a < 0 ) a += n;
        int t = 1;

        while( a != 0 ) {
            while( (a & 1) == 0 ) {
                a >>= 1;
                BigInteger r = n & 7;
                if( r == 3 || r == 5 ) t = -t;
            }

            (a, n) = (n, a);

            if( (a & 3) == 3 && (n & 3) == 3 ) t = -t;
            a %= n;
        }

        return n == 1 ? t : 0;
    }

    public static BigInteger Gcd( BigInteger a, BigInteger b ) {
        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);

        while( b != 0 ) {
            (a, b) = (b, a % b);
        }

        return a;
    }

    public static ( BigInteger gcd, BigInteger x, BigInteger y ) ExtendedGcd( BigInteger a, BigInteger b ) {
        bool negA = a < 0;
        bool negB = b < 0;
        a = BigInteger.Abs(a);
        b = BigInteger.Abs(b);

        BigInteger x0 = 1, x1 = 0;
        BigInteger y0 = 0, y1 = 1;

        while( b != 0 ) {
            BigInteger q = a / b;
            (a, b) = (b, a - q * b);
            (x0, x1) = (x1, x0 - q * x1);
            (y0, y1) = (y1, y0 - q * y1);
        }

        if( negA ) x0 = -x0;
        if( negB ) y0 = -y0;

        return (a, x0, y0);
    }

    public static BigInteger ModPow( BigInteger a, BigInteger b, BigInteger m ) {
        if( m == 1 ) return 0;
        if( b < 0 )
            throw new ArgumentException( "Exponent must be non-negative.", nameof( b ) );

        a %= m;
        if( a < 0 ) a += m;
        BigInteger res = 1;

        while( b > 0 ) {
            if( (b&1) != 0 ) res = (res * a) % m;
            a = (a * a) % m;
            b >>= 1;
        }

        return res;
    }
}