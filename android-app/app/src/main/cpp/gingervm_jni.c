#include <jni.h>
#include <stddef.h>
#include <stdint.h>

extern int32_t gingervm_android_run_init(const char *rootfs_path,
                                         char *output,
                                         size_t output_capacity);
extern int32_t gingervm_android_run_init_simulated(const char *rootfs_path,
                                                   char *output,
                                                   size_t output_capacity);

static jstring run_init(JNIEnv *env, jstring rootfs_path, int simulate_event) {
    if (rootfs_path == NULL) {
        return (*env)->NewStringUTF(env, "GingerVM init test failed: missing rootfs path");
    }
    const char *path = (*env)->GetStringUTFChars(env, rootfs_path, NULL);
    if (path == NULL) {
        return NULL;
    }
    char report[8192] = {0};
    int32_t status = simulate_event
            ? gingervm_android_run_init_simulated(path, report, sizeof(report))
            : gingervm_android_run_init(path, report, sizeof(report));
    (*env)->ReleaseStringUTFChars(env, rootfs_path, path);
    if (report[0] == '\0') {
        if (status == -2) {
            return (*env)->NewStringUTF(env, "GingerVM report was truncated.");
        }
        return (*env)->NewStringUTF(env, "GingerVM init test failed without a report.");
    }
    return (*env)->NewStringUTF(env, report);
}

JNIEXPORT jstring JNICALL
Java_dev_gingervm_mobile_MainActivity_nativeRunInit(JNIEnv *env,
                                                     jobject activity,
                                                     jstring rootfs_path) {
    (void)activity;
    return run_init(env, rootfs_path, 0);
}

JNIEXPORT jstring JNICALL
Java_dev_gingervm_mobile_MainActivity_nativeRunInitSimulated(JNIEnv *env,
                                                             jobject activity,
                                                             jstring rootfs_path) {
    (void)activity;
    return run_init(env, rootfs_path, 1);
}
