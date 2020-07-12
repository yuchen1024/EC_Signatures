#define DEBUG

#include "../src/schnorr.hpp"

void test_schnorr()
{
    cout << "begin the basic correctness test >>>" << endl; 
    
    Schnorr_PP pp; 
    Schnorr_PP_new(pp); 
    Schnorr_Setup(pp); 

    Schnorr_KP keypair;
    Schnorr_KP_new(keypair); 
    auto start_time = chrono::steady_clock::now(); 
    Schnorr_KeyGen(pp, keypair); 
    auto end_time = chrono::steady_clock::now(); 
    auto running_time = end_time - start_time;
    cout << "key generation takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;

    Schnorr_SIG SIG; 
    Schnorr_SIG_new(SIG); 

    string message = "hahaha";  

    start_time = chrono::steady_clock::now(); 
    Schnorr_Sign(pp, keypair.sk, message, SIG);
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "sign message takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;


    start_time = chrono::steady_clock::now(); 
    Schnorr_Verify(pp, keypair.pk, message, SIG);
    end_time = chrono::steady_clock::now(); 
    running_time = end_time - start_time;
    cout << "verify signature takes time = " 
    << chrono::duration <double, milli> (running_time).count() << " ms" << endl;
 
    Schnorr_PP_free(pp); 
    Schnorr_KP_free(keypair); 
    Schnorr_SIG_free(SIG); 
}


int main()
{  
    global_initialize(NID_X9_62_prime256v1);   
    //global_initialize(NID_X25519);

    SplitLine_print('-'); 
    cout << "Schnorr Signature test begins >>>>>>" << endl; 
    SplitLine_print('-'); 

    test_schnorr();

    SplitLine_print('-'); 
    cout << "Schnorr Signature test finishes <<<<<<" << endl; 
    SplitLine_print('-'); 

    global_finalize();
    
    return 0; 
}



