#ifndef GINGERVM_GUEST_IDENTITY_COMPAT_H
#define GINGERVM_GUEST_IDENTITY_COMPAT_H

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#define GUEST_ID_INVALID UINT32_MAX
#define GUEST_ID_MAX_SUPPLEMENTARY_GROUPS 64u
#define GUEST_ID_AID_GRAPHICS 1003u

/* Guest-only credentials. These values never alter the app process credentials. */
struct guest_identity_state {
    uint32_t ruid, euid, suid;
    uint32_t rgid, egid, sgid;
    uint32_t fsuid, fsgid;
    uint32_t group_count;
    uint32_t groups[GUEST_ID_MAX_SUPPLEMENTARY_GROUPS];
};

static inline void guest_identity_init(struct guest_identity_state *state) {
    if (!state) return;
    memset(state, 0, sizeof(*state));
}

static inline int guest_identity_has_group(const struct guest_identity_state *state,
                                           uint32_t gid) {
    if (!state) return 0;
    if (state->egid == gid) return 1;
    for (uint32_t i = 0; i < state->group_count; ++i)
        if (state->groups[i] == gid) return 1;
    return 0;
}

static inline int guest_identity_setuid(struct guest_identity_state *state,
                                        uint32_t uid) {
    if (!state) return -EINVAL;
    if (state->euid == 0u) {
        state->ruid = state->euid = state->suid = uid;
        state->fsuid = uid;
        return 0;
    }
    if (uid != state->ruid && uid != state->euid && uid != state->suid)
        return -EPERM;
    state->euid = state->fsuid = uid;
    return 0;
}

static inline int guest_identity_setgid(struct guest_identity_state *state,
                                        uint32_t gid) {
    if (!state) return -EINVAL;
    if (state->euid == 0u) {
        state->rgid = state->egid = state->sgid = gid;
        state->fsgid = gid;
        return 0;
    }
    if (gid != state->rgid && gid != state->egid && gid != state->sgid)
        return -EPERM;
    state->egid = state->fsgid = gid;
    return 0;
}

static inline int guest_identity_setresuid(struct guest_identity_state *state,
                                           uint32_t ruid, uint32_t euid,
                                           uint32_t suid) {
    if (!state) return -EINVAL;
    if (state->euid != 0u) {
        const uint32_t requested[] = {ruid, euid, suid};
        const uint32_t permitted[] = {state->ruid, state->euid, state->suid};
        for (size_t i = 0; i < 3; ++i) {
            if (requested[i] == GUEST_ID_INVALID) continue;
            int allowed = 0;
            for (size_t j = 0; j < 3; ++j) allowed |= requested[i] == permitted[j];
            if (!allowed) return -EPERM;
        }
    }
    if (ruid != GUEST_ID_INVALID) state->ruid = ruid;
    if (euid != GUEST_ID_INVALID) state->euid = euid;
    if (suid != GUEST_ID_INVALID) state->suid = suid;
    if (euid != GUEST_ID_INVALID) state->fsuid = euid;
    return 0;
}

static inline int guest_identity_setresgid(struct guest_identity_state *state,
                                           uint32_t rgid, uint32_t egid,
                                           uint32_t sgid) {
    if (!state) return -EINVAL;
    if (state->euid != 0u) {
        const uint32_t requested[] = {rgid, egid, sgid};
        const uint32_t permitted[] = {state->rgid, state->egid, state->sgid};
        for (size_t i = 0; i < 3; ++i) {
            if (requested[i] == GUEST_ID_INVALID) continue;
            int allowed = 0;
            for (size_t j = 0; j < 3; ++j) allowed |= requested[i] == permitted[j];
            if (!allowed) return -EPERM;
        }
    }
    if (rgid != GUEST_ID_INVALID) state->rgid = rgid;
    if (egid != GUEST_ID_INVALID) state->egid = egid;
    if (sgid != GUEST_ID_INVALID) state->sgid = sgid;
    if (egid != GUEST_ID_INVALID) state->fsgid = egid;
    return 0;
}

static inline int guest_identity_setreuid(struct guest_identity_state *state,
                                          uint32_t ruid, uint32_t euid) {
    if (!state) return -EINVAL;
    uint32_t old_ruid = state->ruid, old_euid = state->euid, old_suid = state->suid;
    if (state->euid != 0u) {
        if (ruid != GUEST_ID_INVALID && ruid != old_ruid && ruid != old_euid)
            return -EPERM;
        if (euid != GUEST_ID_INVALID && euid != old_ruid && euid != old_euid && euid != old_suid)
            return -EPERM;
    }
    if (ruid != GUEST_ID_INVALID) state->ruid = ruid;
    if (euid != GUEST_ID_INVALID) state->euid = state->fsuid = euid;
    if (ruid != GUEST_ID_INVALID && ruid != old_ruid &&
        (euid == GUEST_ID_INVALID || euid != old_euid))
        state->suid = state->euid;
    else if (euid != GUEST_ID_INVALID && euid != old_euid)
        state->suid = euid;
    return 0;
}

static inline int guest_identity_setregid(struct guest_identity_state *state,
                                          uint32_t rgid, uint32_t egid) {
    if (!state) return -EINVAL;
    uint32_t old_rgid = state->rgid, old_egid = state->egid, old_sgid = state->sgid;
    if (state->euid != 0u) {
        if (rgid != GUEST_ID_INVALID && rgid != old_rgid && rgid != old_egid)
            return -EPERM;
        if (egid != GUEST_ID_INVALID && egid != old_rgid && egid != old_egid && egid != old_sgid)
            return -EPERM;
    }
    if (rgid != GUEST_ID_INVALID) state->rgid = rgid;
    if (egid != GUEST_ID_INVALID) state->egid = state->fsgid = egid;
    if (rgid != GUEST_ID_INVALID && rgid != old_rgid &&
        (egid == GUEST_ID_INVALID || egid != old_egid))
        state->sgid = state->egid;
    else if (egid != GUEST_ID_INVALID && egid != old_egid)
        state->sgid = egid;
    return 0;
}

static inline int guest_identity_setgroups(struct guest_identity_state *state,
                                           uint32_t caller_euid,
                                           const uint32_t *groups,
                                           uint32_t count) {
    if (!state) return -EINVAL;
    if (caller_euid != 0u) return -EPERM;
    if (count > GUEST_ID_MAX_SUPPLEMENTARY_GROUPS || (count && !groups)) return -EINVAL;
    if (count) memcpy(state->groups, groups, (size_t)count * sizeof(groups[0]));
    if (count < GUEST_ID_MAX_SUPPLEMENTARY_GROUPS)
        memset(state->groups + count, 0,
               (GUEST_ID_MAX_SUPPLEMENTARY_GROUPS - count) * sizeof(state->groups[0]));
    state->group_count = count;
    return 0;
}

static inline int guest_identity_getgroups_count(const struct guest_identity_state *state,
                                                 uint32_t size) {
    if (!state) return -EINVAL;
    if (size != 0u && size < state->group_count) return -EINVAL;
    return (int)state->group_count;
}

static inline int guest_identity_setfsuid(struct guest_identity_state *state,
                                          uint32_t uid) {
    if (!state) return -EINVAL;
    uint32_t old = state->fsuid;
    if (state->euid == 0u || uid == state->ruid || uid == state->euid || uid == state->suid)
        state->fsuid = uid;
    return (int)old;
}

static inline int guest_identity_setfsgid(struct guest_identity_state *state,
                                          uint32_t gid) {
    if (!state) return -EINVAL;
    uint32_t old = state->fsgid;
    if (state->euid == 0u || gid == state->rgid || gid == state->egid || gid == state->sgid)
        state->fsgid = gid;
    return (int)old;
}

static inline int guest_identity_fb0_access(const struct guest_identity_state *state,
                                            int open_flags) {
    if (!state) return -EINVAL;
    unsigned access = (unsigned)open_flags & 3u; /* O_ACCMODE: RDONLY=0, WRONLY=1, RDWR=2 */
    if (access == 3u) return -EINVAL;
    if (state->fsuid == 0u) return 0;
    int allowed = state->fsgid == GUEST_ID_AID_GRAPHICS ||
                  guest_identity_has_group(state, GUEST_ID_AID_GRAPHICS);
    if (!allowed) return -EACCES;
    return 0;
}

#endif
