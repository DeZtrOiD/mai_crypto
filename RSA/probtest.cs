
using System.Numerics;
using System.Security.Cryptography;


namespace RSA {
    public interface IProbabilisticPrimalityTest {
        bool IsPrime( BigInteger number, double confidence );
    }

    public abstract class ProbabilisticPrimalityTestBase : IProbabilisticPrimalityTest {
        private readonly RandomNumberGenerator _rng = RandomNumberGenerator.Create();
        protected abstract double GetProb();
        public bool IsPrime( BigInteger number, double confidence ) {
            if( confidence < 0.5 || confidence >= 1.0 )
                throw new ArgumentException( "Confidence must be in [0.5, 1)." );

            if( number < 2 || number % 2 == 0 ) return number == 2;

            int iterations = CalculateIterationsFromConfidence( confidence, GetProb() );
            return RunTest( number, iterations );
        }

        protected abstract bool RunSingleIteration( BigInteger number );

        private bool RunTest( BigInteger number, int iterations ) {
            for( int i = 0; i < iterations; i++ ) {
                if( !RunSingleIteration( number ) ) return false;
            }
            return true;
        }

        public int CalculateIterationsFromConfidence( double confidence, double probability ) {
            if( confidence <= 0.5 ) return 1;

            double errorProbability = 1.0 - confidence;
            int iterations = (int)Math.Ceiling( Math.Log( errorProbability, probability ) );
            return Math.Max( 1, Math.Min( iterations, 100 ) );
        }

        protected BigInteger GenerateRandomInRange( BigInteger min, BigInteger max ) {
            var range = max - min;
            var rangeBytes = range.ToByteArray( isUnsigned: true, isBigEndian: true );
            BigInteger randomValue;

            do {
                _rng.GetBytes( rangeBytes );
                randomValue = new BigInteger( rangeBytes, isUnsigned: true, isBigEndian: true );
                if( randomValue.Sign < 0 )
                    randomValue = -randomValue;

                randomValue %= range;
            } while( randomValue >= range );

            return min + randomValue;
        }
    }

    public sealed class FermatPrimalityTest : ProbabilisticPrimalityTestBase {
        private const double _probability=0.5;
        protected override double GetProb() => _probability;
        protected override bool RunSingleIteration( BigInteger n ) {
            var a = GenerateRandomInRange( 2, n - 1 );
            return NumberTheoryService.ModPow( a, n - 1, n ) == 1;
        }
    }

    public sealed class MillerRabinPrimalityTest : ProbabilisticPrimalityTestBase {
        private const double _probability=0.25;
        protected override double GetProb() => _probability;
        protected override bool RunSingleIteration( BigInteger n ) {
            var d = n - 1;
            var s = 0;
            while( d % 2 == 0 ) {
                d /= 2;
                s++;
            }

            var a = GenerateRandomInRange( 2, n - 1 );
            var x = NumberTheoryService.ModPow( a, d, n );
            if( x == 1 || x == n - 1 )
                return true;

            for( int r = 1; r < s; r++ ) {
                x = NumberTheoryService.ModPow( x, 2, n );
                if( x == n - 1 )
                    return true;
            }

            return false;
        }
    }

    public sealed class SolovayStrassenPrimalityTest : ProbabilisticPrimalityTestBase {
        private const double _probability=0.5;
        protected override double GetProb() => _probability;
        protected override bool RunSingleIteration( BigInteger n ) {
            var a = GenerateRandomInRange( 2, n - 1 );
            var x = NumberTheoryService.ModPow( a, ( n - 1 ) / 2, n );
            var jacobi = NumberTheoryService.JacobiSymbol( a, n );
            var jacobiMod = jacobi % n;
            
            if( jacobiMod < 0 ) jacobiMod += n;

            return x == jacobiMod;
        }
    }
}
