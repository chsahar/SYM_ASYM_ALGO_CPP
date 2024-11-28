#include <iostream>
#include <vector>
#include <cstdlib>
#include <cmath>
#include <ctime>
long long generate_prime(std::vector<long long> &prime)
{
    int index = rand() % prime.size();
    return prime[index];
}
long long gcd(long long a , long long b)
{
    while(b)
    {
        long temp = b;
        b = a % b;//The algorithm repeatedly divides the larger number by the smaller number and replaces the larger number with the remainder until the remainder is zero.
        // The GCD is the non-zero remainder obtained at the end of the process.
        a = temp;
    }
    return a;
}
//now implement a function that denotes the least common multiple(lcm)
long long lcm(long a , long b)
{
    return abs(a*b)/gcd(a,b);
}
//to calculate g , first : we need a function that checks if two numbers are comprime , premier entre eux
bool areComprime(long long a , long long b)
{
    return gcd(a,b)==1;
}
//this function generates a random generator g in the range (1,n^2)
long long generate_g(long long n)
{
    long long g;
    do
    {
        g = rand() %(n*n-1)+1;//ensures that g is in the range (1,n^2) the reason for substracting 1 is to exclude n^2 itself from the range
    }while(!areComprime(g,n*n));//here to check if g is comprime with n^2
    return g;
}
//a function get the ascii code
std::vector<int>get_ascii_codes(const std::string & word)
{
    std::vector<int>ascii_codes;
    for(char c : word)
    {
        ascii_codes.push_back(static_cast<int>(c));//casting operator used to convert one data type to another.
    }
    return ascii_codes;
}
long long mod_pow(long long base, long long exponent, long long modulus) {
    long long result = 1;
    base = base % modulus; // Ensure base is within modulus range

    while (exponent > 0) {
        // If exponent is odd, multiply result with base and take modulo
        if (exponent % 2 == 1) {
            result = (result * base) % modulus;
        }

        // Halve the exponent
        exponent = exponent >> 1; // Equivalent to exponent /= 2

        // Square the base and take modulo
        base = (base * base) % modulus;
    }
    return result;
}

//la formule d'encryption
long long encrypt(long long plaintext , long long n , long long g)//when we want to encrypt the plain text , we take the plain text , n , and g
{
    //first we have to generate r between 0 and n
    long long r = rand() % (n-1)+1;
    //r = static_cast<long long>(r) * (n + 1) / (RAND_MAX + 1); //n+1 is the disred range , (RAND_MAX + 1) represents the maximum possible value that rand() can return, incremented by 1. This ensures that we cover the entire range of possible values returned by rand().
    //here we write the formula
    //long long c = (int)(pow(g,plaintext) * pow(r,n)) % (int)pow(n,2);
    long long ciphertext = (mod_pow(g, plaintext, n * n) * mod_pow(r, n, n * n)) % (n * n);
    return ciphertext;
}
long long decrypt(long long ciphertext , long long n , long long LCM)
{
    long long r = mod_pow(ciphertext, LCM, n * n);
    long long plaintext = (r - 1 + n) / n; // Adjust for negative numbers and add n before dividing
    return plaintext;
}
int main() {
    //KEY GENERATION PART

    //Choose tow large prime numbers p and q randomly with the same size
    srand(time(0));
    std::vector<long long> primes = {{2, 7, 13, 19, 23, 29, 37, 43, 47, 53, 61, 71, 73, 79, 89, 97, 101}};
    long long p = generate_prime(primes);
    std::cout<<"the first prime number p : "<<p<<std::endl;
    long long q = generate_prime(primes);
    std::cout<<"the second prime number q : "<<q<<std::endl;
    while(q == p)
    {
        q = generate_prime(primes);
    }
    //compute n
    long long n = p * q;
    std::cout<<"n : p*q = : "<<n<<std::endl;
    //compute lcm(p-1,q-1) , this is the private key
    long long LCM = lcm(p-1,q-1);
    std::cout<<"LCM : "<<LCM<<std::endl;
    //choose g , where g is in the group of Zn^2
    long long g = generate_g(n);
    std::cout<<"g : "<<g<<std::endl;

    //Print : print the private and the public key
    //the public key is (n,g)
    std::cout<<"Public Key : " <<n,g;
    std::cout<<std::endl;
    std::cout<<"Private Key : "<<LCM;

    std::cout<<std::endl;

    //THE ENCRYPTION PART , USE THE PUBLIC KEY
    std::string plaintext = "Hello";
    std::vector<int>ascii_codes = get_ascii_codes(plaintext);
    std::vector<long long>ciphertexts;
    for(int ascii_code : ascii_codes)
    {
        long long ciphertext = encrypt(ascii_code , n , g);
        ciphertexts.push_back(ciphertext);
    }
    std::cout<<"Plain Text : "<<plaintext<<std::endl;
    std::cout<<"Cipher Text : "<<std::endl;
    for(long long ciphertext : ciphertexts)
    {
        std::cout<<" "<<ciphertext;
    }
    std::cout<<std::endl;

    //THE DECRYPTION PART , USE THE PRIVATE KEY
    std::vector<long long>decrypted_plaintexts;
    for(long long ciphertext : ciphertexts)
    {
        long long plaintext = decrypt(ciphertext,n,LCM);
        decrypted_plaintexts.push_back((plaintext));
    }
    std::cout<<"Decrypted Plaintexts : "<<std::endl;
    for(long long plaintext : decrypted_plaintexts)
    {
        std::cout<<plaintext<<" ";
    }
    std::cout<<std::endl;
//    std::string decrypted_message;
//    for(long plaintext : decrypted_plaintexts)
//    {
//        decrypted_message += static_cast<char>(plaintext);
//    }
//    std::cout<<"Decrypted Message : "<<decrypted_message<<std::endl;
    return 0;
}