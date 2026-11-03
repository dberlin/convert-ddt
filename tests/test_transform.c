/* SPDX-License-Identifier: CDDL-1.0 */
#include <sys/zfs_context.h>
#include <sys/ddt.h>
#include <assert.h>
#include "../ddt_transform.h"

/* Check slot selection and preservation of encrypted DVAs, births, and refs. */
int
main(void)
{
    ddt_univ_phys_t old = {0}, flat;
    for (int slot = 1; slot <= 3; slot++) {
        memset(&old, 0, sizeof (old));
        old.ddp_trad[slot].ddp_dva[0].dva_word[0] = 0x1234;
        old.ddp_trad[slot].ddp_dva[0].dva_word[1] = 0x5678;
        old.ddp_trad[slot].ddp_dva[1].dva_word[0] = 0x9abc;
        old.ddp_trad[slot].ddp_dva[2].dva_word[0] = 0xdeadbeef;
        old.ddp_trad[slot].ddp_dva[2].dva_word[1] = 0xfeedface;
        old.ddp_trad[slot].ddp_refcnt = 19;
        old.ddp_trad[slot].ddp_phys_birth = 456;
        assert(ddt_convert_phys(&old, &flat, 1700000000) == 0);
        assert(flat.ddp_flat.ddp_dva[0].dva_word[0] == 0x1234);
        assert(flat.ddp_flat.ddp_dva[0].dva_word[1] == 0x5678);
        assert(flat.ddp_flat.ddp_dva[1].dva_word[0] == 0x9abc);
        assert(flat.ddp_flat.ddp_dva[2].dva_word[0] == 0xdeadbeef);
        assert(flat.ddp_flat.ddp_dva[2].dva_word[1] == 0xfeedface);
        assert(flat.ddp_flat.ddp_refcnt == 19);
        assert(flat.ddp_flat.ddp_phys_birth == 456);
        assert(flat.ddp_flat.ddp_class_start == 1700000000);
    }
    /* Independent allocation groups require separate physical identities. */
    old.ddp_trad[1].ddp_refcnt = 2;
    old.ddp_trad[1].ddp_phys_birth = 789;
    old.ddp_trad[1].ddp_dva[0].dva_word[0] = 123;
    assert(ddt_convert_phys(&old, &flat, 1) == ENOTSUP);
    memset(&old, 0, sizeof (old));
    old.ddp_trad[0].ddp_phys_birth = 88;
    assert(ddt_convert_phys(&old, &flat, 1) == ENOTSUP);
    memset(&old, 0, sizeof (old));
    assert(ddt_convert_phys(&old, &flat, 1) == EINVAL);
    old.ddp_trad[1].ddp_refcnt = 1;
    assert(ddt_convert_phys(&old, &flat, 1) == EINVAL);
    old.ddp_trad[1].ddp_phys_birth = 3;
    assert(ddt_convert_phys(&old, &flat, 1) == EINVAL);
    old.ddp_trad[1].ddp_dva[0].dva_word[0] = 1;
    old.ddp_trad[2].ddp_phys_birth = 4; /* zero refs still owns an allocation */
    assert(ddt_convert_phys(&old, &flat, 1) == ENOTSUP);
    puts("physical identity transformation: PASS");
    return (0);
}
