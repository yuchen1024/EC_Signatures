/****************************************************************************
this hpp implements standard ElGamal PKE scheme
*****************************************************************************
* @author     developed by Yu Chen
* @copyright  MIT license (see LICENSE file)
*****************************************************************************/
#include "../global/global.hpp"
#include "../depends/hash.hpp"
#include "../depends/print.hpp"
#include "../depends/routines.hpp"

// define the structure of PP
struct Schnorr_PP
{  
    EC_POINT *g; 
};


// define keypair 
struct Schnorr_KP
{
    EC_POINT *pk; // define pk
    BIGNUM *sk;   // define sk
};

// define signature 
struct Schnorr_SIG
{
    EC_POINT *A; 
    BIGNUM *z;
};


/* allocate memory for PP */ 
void Schnorr_PP_new(Schnorr_PP &pp)
{ 
    pp.g = EC_POINT_new(group);  
}

/* free memory of PP */ 
void Schnorr_PP_free(Schnorr_PP &pp)
{ 
    EC_POINT_free(pp.g);
}

void Schnorr_KP_new(Schnorr_KP &keypair)
{
    keypair.pk = EC_POINT_new(group); 
    keypair.sk = BN_new(); 
}

void Schnorr_KP_free(Schnorr_KP &keypair)
{
    EC_POINT_free(keypair.pk); 
    BN_free(keypair.sk);
}

void Schnorr_SIG_new(Schnorr_SIG &SIG)
{
    SIG.A = EC_POINT_new(group); 
    SIG.z = BN_new();
}

void Schnorr_SIG_free(Schnorr_SIG &SIG)
{
    EC_POINT_free(SIG.A); 
    BN_free(SIG.z);
}


void Schnorr_PP_print(Schnorr_PP &pp)
{
    ECP_print(pp.g, "pp.g"); 
} 

void Schnorr_KP_print(Schnorr_KP &keypair)
{
    ECP_print(keypair.pk, "pk"); 
    BN_print(keypair.sk, "sk"); 
} 

void Schnorr_SIG_print(Schnorr_SIG &SIG)
{
    ECP_print(SIG.A, "SIG.A");
    BN_print(SIG.z, "SIG.z");
} 


void Schnorr_SIG_serialize(Schnorr_SIG &SIG, ofstream &fout)
{
    ECP_serialize(SIG.A, fout); 
    BN_serialize(SIG.z, fout); 
} 

void Schnorr_SIG_deserialize(Schnorr_SIG &SIG, ifstream &fin)
{
    ECP_deserialize(SIG.A, fin); 
    BN_deserialize(SIG.z, fin); 
} 


/* Setup algorithm */ 
void Schnorr_Setup(Schnorr_PP &pp)
{ 
    EC_POINT_copy(pp.g, generator); 

    #ifdef DEBUG
    cout << "generate the public parameters for Schnorr Signature >>>" << endl; 
    Schnorr_PP_print(pp); 
    #endif
}

/* KeyGen algorithm */ 
void Schnorr_KeyGen(Schnorr_PP &pp, Schnorr_KP &keypair)
{ 
    BN_random(keypair.sk); // sk \sample Z_p
    EC_POINT_mul(group, keypair.pk, keypair.sk, NULL, NULL, bn_ctx); // pk = g^sk  

    #ifdef DEBUG
    cout << "key generation finished >>>" << endl;  
    Schnorr_KP_print(keypair); 
    #endif
}


/* This function takes as input a message, returns a signature. */
void Schnorr_Sign(Schnorr_PP &pp, BIGNUM *&sk, string &message, Schnorr_SIG &SIG)
{
    Schnorr_SIG sig; // define the signature
    BIGNUM *r = BN_new();
    BN_random(r);  

    EC_POINT_mul(group, SIG.A, r, NULL, NULL, bn_ctx); // A = g^r

    // compute e = H(A||m)
    BIGNUM *e = BN_new();
    Hash_ECP_and_string_to_BN(SIG.A, message, e);

    BN_mul(e, sk, e, bn_ctx); 
    BN_mod_add(SIG.z, r, e, order, bn_ctx); // z = r + sk*e; 

    #ifdef DEBUG
        cout << "Schnorr signature generation finishes >>>" << endl;
        Schnorr_SIG_print(SIG);  
    #endif

    BN_free(r); 
    BN_free(e); 
}


/* This function verifies the signature is valid for the message "msg_file" */

bool Schnorr_Verify(Schnorr_PP &pp, EC_POINT *&pk, string &message, Schnorr_SIG &SIG)
{
    bool Validity;       

    // compute e = H(A||m)
    BIGNUM *e = BN_new(); 
    Hash_ECP_and_string_to_BN(SIG.A, message, e);
    
    EC_POINT *LEFT = EC_POINT_new(group);
    EC_POINT *RIGHT = EC_POINT_new(group);

    EC_POINT_mul(group, LEFT, SIG.z, NULL, NULL, bn_ctx); // LEFT = g^z 
    EC_POINT_mul(group, RIGHT, NULL, pk, e, bn_ctx);   // RIGHT = pk^e
    EC_POINT_add(group, RIGHT, RIGHT, SIG.A, bn_ctx);        // RIGHT += A

    if(EC_POINT_cmp(group, LEFT, RIGHT, bn_ctx) == 0){
        Validity = true; 
    }
    else Validity = false; 
 
    #ifdef DEBUG
    if (Validity)
    {
        cout << "Signature is Valid >>>" << endl;
    }
    else
    {
        cout << "Signature is Invalid >>>" << endl;
    }
    #endif

    BN_free(e); 
    EC_POINT_free(LEFT);
    EC_POINT_free(RIGHT);  

    return Validity;
}