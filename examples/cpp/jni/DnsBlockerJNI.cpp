/**
 * JNI - Game Config Module
 */

#include <jni.h>
#include <string>
#include <memory>
#include <unordered_map>
#include <mutex>

#include "../DnsBlockerClient.hpp"

static std::unordered_map<jlong, std::unique_ptr<GameConfig::ConfigMgr>> g_mgrs;
static std::mutex g_mtx;
static jlong g_id = 1;

static GameConfig::ConfigMgr* getMgr(jlong h) {
    std::lock_guard<std::mutex> l(g_mtx);
    auto it = g_mgrs.find(h);
    return (it != g_mgrs.end()) ? it->second.get() : nullptr;
}

static std::string toStr(JNIEnv* e, jstring s) {
    if (!s) return "";
    const char* c = e->GetStringUTFChars(s, nullptr);
    std::string r(c);
    e->ReleaseStringUTFChars(s, c);
    return r;
}

static jstring toJStr(JNIEnv* e, const std::string& s) {
    return e->NewStringUTF(s.c_str());
}

extern "C" {

// com.game.config.ConfigNative

JNIEXPORT jlong JNICALL
Java_com_game_config_ConfigNative_create(JNIEnv* e, jclass, jstring url) {
    std::string u = toStr(e, url);
    if (u.empty()) return 0;
    
    auto mgr = std::make_unique<GameConfig::ConfigMgr>(u);
    std::lock_guard<std::mutex> l(g_mtx);
    jlong h = g_id++;
    g_mgrs[h] = std::move(mgr);
    return h;
}

JNIEXPORT void JNICALL
Java_com_game_config_ConfigNative_destroy(JNIEnv*, jclass, jlong h) {
    std::lock_guard<std::mutex> l(g_mtx);
    g_mgrs.erase(h);
}

JNIEXPORT jboolean JNICALL
Java_com_game_config_ConfigNative_init(JNIEnv*, jclass, jlong h) {
    auto* m = getMgr(h);
    return (m && m->init()) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jboolean JNICALL
Java_com_game_config_ConfigNative_check(JNIEnv* e, jclass, jlong h, jstring key) {
    auto* m = getMgr(h);
    if (!m) return JNI_FALSE;
    return m->check(toStr(e, key)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT jstring JNICALL
Java_com_game_config_ConfigNative_query(JNIEnv* e, jclass, jlong h, jstring key) {
    auto* m = getMgr(h);
    if (!m) return toJStr(e, "");
    auto r = m->query(toStr(e, key));
    return toJStr(e, (r.status == 1) ? "0.0.0.0" : r.value);
}

JNIEXPORT jboolean JNICALL
Java_com_game_config_ConfigNative_checkLocal(JNIEnv* e, jclass, jlong h, jstring key) {
    auto* m = getMgr(h);
    if (!m) return JNI_FALSE;
    return m->checkLocal(toStr(e, key)) ? JNI_TRUE : JNI_FALSE;
}

JNIEXPORT void JNICALL
Java_com_game_config_ConfigNative_addFilter(JNIEnv* e, jclass, jlong h, jstring key) {
    auto* m = getMgr(h);
    if (m) m->addFilter(toStr(e, key));
}

JNIEXPORT void JNICALL
Java_com_game_config_ConfigNative_setTimeout(JNIEnv*, jclass, jlong h, jint ms) {
    auto* m = getMgr(h);
    if (m) m->setTimeout(ms);
}

JNIEXPORT jboolean JNICALL
Java_com_game_config_ConfigNative_isActive(JNIEnv*, jclass, jlong h) {
    auto* m = getMgr(h);
    return (m && m->isActive()) ? JNI_TRUE : JNI_FALSE;
}

}
