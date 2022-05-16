#include "binfhecontext.h"

using namespace lbcrypto;
using namespace std;

// function checking the quality between two vectors of ciphertext
// The first two arguments must have at least one element each.
template <typename ContextType>
LWECiphertext are_equal(vector<LWECiphertext> &c1, vector<LWECiphertext> &c2, ContextType &cc) 
{

    // if the messages have different lengths, return an encryption of `false`
    if (c1.size() != c2.size()) 
        return cc.EvalBinGate(XOR, c1[0], std::make_shared<LWECiphertextImpl>(*c1[0]));
    
    // component-wise comparison
    vector<LWECiphertext> c3(c1.size());
    for (unsigned int i=0; i<c1.size(); i++) 
        c3[i] = cc.EvalBinGate(XNOR, c1[i], c2[i]);

    // chech if all elements of c3 encrypt `true`
    LWECiphertext res = c3[0];
    for (unsigned int i=1; i<c3.size(); i++)
        res = cc.EvalBinGate(AND, res, c3[i]);

    return res;
}

int main() {
  
    // set the CryptoContext with 128 bits of security
    cout << "Generating the CryptoContext..." << endl;
    auto cc = BinFHEContext();
    cc.GenerateBinFHEContext(STD128);
  
    // generate the secret key
    cout << "Generating the secret key..." << endl;
    auto sk = cc.KeyGen();
  
    // generate the bootstrapping key
    cout << "Generating the bootstrapping key..." << endl;
    cc.BTKeyGen(sk);

    // get the messages from the user
    vector<bool> m1, m2;
    string m1_s, m2_s;
    cout << "Message 1: ";
    getline(cin, m1_s);
    for (unsigned int i=0; i<m1_s.size(); i++) {
        m1.push_back(m1_s[i] & 1);
        m1.push_back(m1_s[i] & 2);
        m1.push_back(m1_s[i] & 4);
        m1.push_back(m1_s[i] & 8);
        m1.push_back(m1_s[i] & 16);
        m1.push_back(m1_s[i] & 32);
        m1.push_back(m1_s[i] & 64);
        m1.push_back(m1_s[i] & 128);
    }
    cout << "Message 2: ";
    getline(cin, m2_s);
    for (unsigned int i=0; i<m2_s.size(); i++) {
        m2.push_back(m2_s[i] & 1);
        m2.push_back(m2_s[i] & 2);
        m2.push_back(m2_s[i] & 4);
        m2.push_back(m2_s[i] & 8);
        m2.push_back(m2_s[i] & 16);
        m2.push_back(m2_s[i] & 32);
        m2.push_back(m2_s[i] & 64);
        m2.push_back(m2_s[i] & 128);
    }

    // encrypt the messages
    vector<shared_ptr<LWECiphertextImpl>> c1, c2;
    for (bool b: m1) 
        c1.push_back(cc.Encrypt(sk, b));
    for (bool b: m2)
        c2.push_back(cc.Encrypt(sk, b));
        
    // check the equality
    LWECiphertext res_encrypted = are_equal(c1, c2, cc);

    // decrypt the result
    LWEPlaintext res; 
    cc.Decrypt(sk, res_encrypted, &res);

    if (res)
        cout << "The messages are equal" << endl;
    else 
        cout << "The messages are different" << endl;

    return 0;
}
