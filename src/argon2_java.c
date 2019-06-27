#include <jni.h>
#include <stdlib.h>
#include <argon2.h>

#define UNUSED_PARAM(var) (void)var

JNIEXPORT jint JNICALL Java_com_mblsft_common_crypto_Argon2_hashi(JNIEnv* env, jclass c, jint iter, jint mem, jint cores, jbyteArray jpwd, jbyteArray jsalt, jbyteArray jhash)
{
    UNUSED_PARAM(c);
    const size_t pwdlen = (*env)->GetArrayLength(env, jpwd);
    const size_t saltlen = (*env)->GetArrayLength(env, jsalt);
    const size_t hashlen = (*env)->GetArrayLength(env, jhash);
    void* pwd = pwdlen ? malloc(pwdlen) : NULL;
    void* salt = saltlen ? malloc(saltlen) : NULL;
    void* hash = hashlen ? malloc(hashlen) : NULL;
    if (pwdlen) {
        (*env)->GetByteArrayRegion(env, jpwd, 0, pwdlen, (jbyte*) pwd);
    }
    if (saltlen) {
        (*env)->GetByteArrayRegion(env, jsalt, 0, saltlen, (jbyte*) salt);
    }

    int result = argon2i_hash_raw(iter, mem, cores, pwd, pwdlen, salt, saltlen, hash, hashlen);
    
    if (result == ARGON2_OK) {
        (*env)->SetByteArrayRegion(env, jhash, 0, hashlen, (jbyte*) hash);
    }
    
    free(pwd);
    free(salt);
    free(hash);

    return result;
}

JNIEXPORT jint JNICALL Java_com_mblsft_common_crypto_Argon2_hashd(JNIEnv* env, jclass c, jint iter, jint mem, jint cores, jbyteArray jpwd, jbyteArray jsalt, jbyteArray jhash)
{
    UNUSED_PARAM(c);
    const size_t pwdlen = (*env)->GetArrayLength(env, jpwd);
    const size_t saltlen = (*env)->GetArrayLength(env, jsalt);
    const size_t hashlen = (*env)->GetArrayLength(env, jhash);
    void* pwd = pwdlen ? malloc(pwdlen) : NULL;
    void* salt = saltlen ? malloc(saltlen) : NULL;
    void* hash = hashlen ? malloc(hashlen) : NULL;
    if (pwdlen) {
        (*env)->GetByteArrayRegion(env, jpwd, 0, pwdlen, (jbyte*) pwd);
    }
    if (saltlen) {
        (*env)->GetByteArrayRegion(env, jsalt, 0, saltlen, (jbyte*) salt);
    }

    int result = argon2d_hash_raw(iter, mem, cores, pwd, pwdlen, salt, saltlen, hash, hashlen);
    
    if (result == ARGON2_OK) {
        (*env)->SetByteArrayRegion(env, jhash, 0, hashlen, (jbyte*) hash);
    }
    
    free(pwd);
    free(salt);
    free(hash);

    return result;
}

JNIEXPORT jint JNICALL Java_com_mblsft_common_crypto_Argon2_hashid(JNIEnv* env, jclass c, jint iter, jint mem, jint cores, jbyteArray jpwd, jbyteArray jsalt, jbyteArray jhash)
{
    UNUSED_PARAM(c);
    const size_t pwdlen = (*env)->GetArrayLength(env, jpwd);
    const size_t saltlen = (*env)->GetArrayLength(env, jsalt);
    const size_t hashlen = (*env)->GetArrayLength(env, jhash);
    void* pwd = pwdlen ? malloc(pwdlen) : NULL;
    void* salt = saltlen ? malloc(saltlen) : NULL;
    void* hash = hashlen ? malloc(hashlen) : NULL;
    if (pwdlen) {
        (*env)->GetByteArrayRegion(env, jpwd, 0, pwdlen, (jbyte*) pwd);
    }
    if (saltlen) {
        (*env)->GetByteArrayRegion(env, jsalt, 0, saltlen, (jbyte*) salt);
    }

    int result = argon2id_hash_raw(iter, mem, cores, pwd, pwdlen, salt, saltlen, hash, hashlen);
    
    if (result == ARGON2_OK) {
        (*env)->SetByteArrayRegion(env, jhash, 0, hashlen, (jbyte*) hash);
    }
    
    free(pwd);
    free(salt);
    free(hash);

    return result;
}


