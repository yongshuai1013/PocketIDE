#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>

#include "../app/src/main/cpp/guest_identity_compat.h"

int main(void) {
    struct guest_identity_state identity;
    guest_identity_init(&identity);
    assert(identity.ruid == 0 && identity.euid == 0 && identity.rgid == 0 && identity.egid == 0);

    assert(guest_identity_fb0_access(&identity, 2) == 0);
    const uint32_t graphics_only[] = {GUEST_ID_AID_GRAPHICS};
    assert(guest_identity_setgroups(&identity, identity.euid, graphics_only, 1) == 0);
    assert(identity.group_count == 1 && guest_identity_has_group(&identity, GUEST_ID_AID_GRAPHICS));
    assert(guest_identity_getgroups_count(&identity, 0) == 1);
    assert(guest_identity_getgroups_count(&identity, 1) == 1);
    assert(guest_identity_getgroups_count(&identity, 0) == 1); /* size=0 asks for count only */

    assert(guest_identity_setgid(&identity, 1000) == 0);
    assert(guest_identity_setuid(&identity, 1000) == 0);
    assert(identity.ruid == 1000 && identity.euid == 1000 && identity.rgid == 1000 && identity.egid == 1000);
    assert(guest_identity_fb0_access(&identity, 2) == 0); /* supplementary graphics group */
    assert(guest_identity_setgroups(&identity, identity.euid, NULL, 0) == -EPERM);
    assert(guest_identity_setuid(&identity, 0) == -EPERM);
    assert(guest_identity_setgid(&identity, 0) == -EPERM);
    assert(guest_identity_setresuid(&identity, 0, GUEST_ID_INVALID, GUEST_ID_INVALID) == -EPERM);

    /* A process without the graphics supplementary group cannot open fb0. */
    identity.group_count = 0;
    assert(guest_identity_fb0_access(&identity, 2) == -EACCES);
    assert(guest_identity_fb0_access(&identity, 3) == -EINVAL);

    /* Root may assign the group and drop to the graphics service identity. */
    guest_identity_init(&identity);
    const uint32_t surfaceflinger_groups[] = {GUEST_ID_AID_GRAPHICS};
    assert(guest_identity_setgroups(&identity, 0, surfaceflinger_groups, 1) == 0);
    assert(guest_identity_setresgid(&identity, 1000, 1000, 1000) == 0);
    assert(guest_identity_setresuid(&identity, 1000, 1000, 1000) == 0);
    assert(guest_identity_fb0_access(&identity, 2) == 0);
    assert(guest_identity_has_group(&identity, GUEST_ID_AID_GRAPHICS));

    /* Invalid identities and over-capacity supplementary groups fail closed. */
    assert(guest_identity_setgroups(&identity, 0, surfaceflinger_groups,
        GUEST_ID_MAX_SUPPLEMENTARY_GROUPS + 1u) == -EINVAL);
    assert(guest_identity_setgroups(&identity, 1000, surfaceflinger_groups, 1) == -EPERM);
    assert(guest_identity_getgroups_count(&identity, 0) == 1);

    puts("guest identity regression: PASS (UID/GID and supplementary groups remain per-tracee; unprivileged setgroups/UID regain denied; graphics group gates fb0)");
    return 0;
}
