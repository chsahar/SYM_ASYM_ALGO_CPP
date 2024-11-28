#include <iostream>
#include <vector>
#include <cmath>
#include <random>
#include <numeric>
#include <algorithm>

long long modInverse(long long a, long long m) {
    long long m0 = m, t, q;
    long long x0 = 0, x1 = 1;

    if (m == 1)
        return 0;

    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m, a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }

    if (x1 < 0)
        x1 += m0;

    return x1;
}

long long power(long long x, unsigned long long y, long long p) {
    long long res = 1;
    x %= p;

    while (y > 0) {
        if (y & 1)
            res = (res * x) % p;

        y >>= 1;
        x = (x * x) % p;
    }
    return res;
}
int main() {
    std::vector<long long> primes = {
            1000003, 1000033, 1000037, 1000039, 1000081, 1000099, 1000117, 1000121, 1000133, 1000151, 1000159, 1000171, 1000183, 1000187, 1000193, 1000199, 1000211, 1000213, 1000231, 1000249, 1000253, 1000273, 1000289, 1000291, 1000303, 1000313, 1000333, 1000357, 1000367, 1000381, 1000393, 1000397, 1000403, 1000409, 1000423, 1000427, 1000429, 1000453, 1000457, 1000493, 1000499, 1000513, 1000537, 1000541, 1000547, 1000577, 1000589, 1000591, 1000607, 1000619, 1000627, 1000637, 1000651, 1000667, 1000669, 1000679, 1000681, 1000697, 1000721, 1000723, 1000763, 1000777, 1000793, 1000811, 1000813, 1000829, 1000847, 1000849, 1000859, 1000861, 1000867, 1000873, 1000901, 1000907, 1000919, 1000921, 1000931, 1000963, 1000981, 1000999, 1001003, 1001017, 1001033, 1001047, 1001069, 1001083, 1001089, 1001093, 1001117, 1001159, 1001161, 1001173, 1001177, 1001191, 1001197, 1001219, 1001237, 1001267, 1001279, 1001291, 1001303, 1001311, 1001323, 1001327, 1001347, 1001359, 1001363, 1001371, 1001381, 1001387, 1001389, 1001401, 1001413, 1001437, 1001441, 1001449, 1001459, 1001467, 1001491, 1001501, 1001527, 1001531, 1001549, 1001551, 1001563, 1001567, 1001569, 1001593, 1001621, 1001623, 1001639, 1001659, 1001669, 1001683, 1001687, 1001713, 1001723, 1001741, 1001747, 1001759, 1001761, 1001777, 1001783, 1001789, 1001801, 1001807, 1001809, 1001821, 1001831, 1001839, 1001867, 1001891, 1001893, 1001903, 1001917, 1001933, 1001941, 1001947, 1001953, 1001971, 1001977, 1001987, 1001989, 1002013, 1002023, 1002049, 1002061, 1002071, 1002077, 1002083, 1002091, 1002101, 1002109, 1002121, 1002133, 1002149, 1002151, 1002173, 1002187, 1002203, 1002221, 1002223, 1002241, 1002247, 1002257, 1002259, 1002263, 1002289, 1002299, 1002307, 1002311, 1002331, 1002347, 1002349, 1002359, 1002361, 1002379, 1002383, 1002397, 1002401, 1002419, 1002437, 1002451, 1002469, 1002481, 1002487, 1002493, 1002503, 1002511, 1002517, 1002523, 1002539, 1002547, 1002553, 1002569, 1002577, 1002583, 1002611, 1002619, 1002637, 1002649, 1002661, 1002673, 1002677, 1002689, 1002703, 1002707, 1002721, 1002727, 1002739, 1002749, 1002757, 1002767, 1002769, 1002773, 1002787, 1002797, 1002809, 1002817, 1002821, 1002853, 1002857, 1002863, 1002871, 1002893, 1002899, 1002917, 1002923, 1002929, 1002937, 1002941, 1002967, 1002973, 1002997, 1003019, 1003031, 1003037, 1003061, 1003067, 1003093, 1003103, 1003109, 1003121, 1003133, 1003139, 1003163, 1003169, 1003171, 1003193, 1003199, 1003201, 1003243, 1003247, 1003253, 1003259, 1003273, 1003277, 1003279, 1003291, 1003301, 1003303, 1003309, 1003319, 1003327, 1003331, 1003343, 1003349, 1003357, 1003363, 1003367, 1003369, 1003381, 1003397, 1003411, 1003427, 1003433, 1003441, 1003447, 1003463, 1003469, 1003483, 1003499, 1003501, 1003519,

            1003529, 1003547, 1003549, 1003559, 1003573, 1003579, 1003589, 1003597, 1003613, 1003621, 1003627, 1003633, 1003637, 1003643, 1003651, 1003693, 1003711, 1003723, 1003733, 1003741, 1003747, 1003757, 1003763, 1003777, 1003787, 1003793, 1003817, 1003823, 1003829, 1003837, 1003841, 1003871, 1003873, 1003891, 1003897, 1003901, 1003927, 1003931, 1003943, 1003949, 1003967, 1003973, 1003993, 1004009, 1004017, 1004029, 1004033, 1004053, 1004057, 1004069, 1004077, 1004083, 1004107, 1004117, 1004119, 1004123, 1004131, 1004141, 1004153, 1004161, 1004167, 1004201, 1004203, 1004213, 1004231, 1004237, 1004249, 1004257, 1004263, 1004281, 1004287, 1004293, 1004303, 1004311, 1004321, 1004347, 1004353, 1004369, 1004401, 1004407, 1004411, 1004413, 1004423, 1004429, 1004443, 1004459, 1004467, 1004477, 1004489, 1004497, 1004503, 1004507, 1004509, 1004519, 1004527, 1004537, 1004549, 1004563, 1004573, 1004579, 1004593, 1004597, 1004599, 1004623, 1004627, 1004653, 1004657, 1004669, 1004671, 1004677, 1004687, 1004723, 1004729, 1004731, 1004737, 1004741, 1004743, 1004749, 1004767, 1004777, 1004783, 1004797, 1004819, 1004831, 1004837, 1004861, 1004879, 1004887, 1004891, 1004899, 1004909, 1004911, 1004917, 1004963, 1004981, 1004999, 1005013, 1005019, 1005029, 1005037, 1005059, 1005073, 1005097, 1005101, 1005103, 1005107, 1005139, 1005143, 1005157, 1005167, 1005187, 1005197, 1005209, 1005221, 1005229, 1005239, 1005253, 1005269, 1005281, 1005283, 1005293, 1005311, 1005313, 1005317, 1005331, 1005337, 1005349, 1005353, 1005361, 1005383, 1005409, 1005413, 1005421, 1005437, 1005439, 1005443, 1005451, 1005467, 1005491, 1005503, 1005509, 1005523, 1005533, 1005547, 1005553, 1005559, 1005569, 1005577, 1005583, 1005587, 1005599, 1005607, 1005613, 1005619, 1005629, 1005637, 1005641, 1005647, 1005653, 1005661, 1005673, 1005677, 1005683, 1005689, 1005701, 1005709, 1005743, 1005751, 1005763, 1005787, 1005793, 1005799, 1005817, 1005821, 1005827, 1005839, 1005841, 1005853, 1005859, 1005863, 1005877, 1005883, 1005901, 1005917, 1005919, 1005937, 1005953, 1005973, 1005979, 1006003, 1006013, 1006033, 1006037, 1006051, 1006057, 1006073, 1006093, 1006103, 1006109, 1006117, 1006133, 1006139, 1006151, 1006159, 1006163, 1006169, 1006171, 1006177, 1006183, 1006201, 1006213, 1006217, 1006231, 1006241, 1006247, 1006253, 1006261, 1006267, 1006273, 1006297, 1006309, 1006313, 1006333, 1006339, 1006351, 1006361, 1006367, 1006391, 1006393, 1006399, 1006409, 1006421, 1006423, 1006427, 1006441, 1006447, 1006463, 1006469, 1006493, 1006499, 1006501, 1006511, 1006517, 1006559, 1006567, 1006571, 1006597, 1006609, 1006613, 1006619, 1006621
    };

    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dis(0, primes.size() - 1);
    int idx1 = dis(gen);
    int idx2 = dis(gen);
    while (idx1 == idx2) {
        idx2 = dis(gen);
    }
    long long p = primes[idx1];
    long long q = primes[idx2];

    long long n = p * q;
    long long phi = (p - 1) * (q - 1);

    long long e = 2; // Start with 2 as the smallest prime number
    while (std::gcd(e, phi) != 1) {
        e = primes[dis(gen)];
    }
    long long d = modInverse(e, phi);
    std::cout << "Selected primes: " << p << ", " << q << std::endl;//hayda just for the sake of the demo.
    std::cout << "Public key (e, n): (" << e << ", " << n << ")" << std::endl;
    std::cout << "Private key (d, n): (" << d << ", " << n << ")" << std::endl;
    return 0;
}
