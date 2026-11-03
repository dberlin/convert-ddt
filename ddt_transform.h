/* SPDX-License-Identifier: CDDL-1.0 */
#ifndef CONVERT_DDT_TRANSFORM_H
#define CONVERT_DDT_TRANSFORM_H

/* A flat entry preserves one allocation group's block-pointer identity. */
static inline int
ddt_convert_phys(const ddt_univ_phys_t *old, ddt_univ_phys_t *flat,
    uint64_t timestamp)
{
    const ddt_univ_phys_t zero = {0};
    int selected = -1;
    for (int p = 0; p < DDT_PHYS_MAX; p++) {
        if (memcmp(&old->ddp_trad[p], &zero.ddp_trad[p],
            sizeof (old->ddp_trad[p])) == 0)
            continue;
        if (p == DDT_PHYS_DITTO || selected != -1)
            return (ENOTSUP);
        selected = p;
    }
    if (selected < 0 || old->ddp_trad[selected].ddp_refcnt == 0 ||
        old->ddp_trad[selected].ddp_phys_birth == 0 ||
        old->ddp_trad[selected].ddp_dva[0].dva_word[0] == 0)
        return (EINVAL);
    memset(flat, 0, sizeof (*flat));
    memcpy(flat->ddp_flat.ddp_dva, old->ddp_trad[selected].ddp_dva,
        sizeof (flat->ddp_flat.ddp_dva));
    flat->ddp_flat.ddp_refcnt = old->ddp_trad[selected].ddp_refcnt;
    flat->ddp_flat.ddp_phys_birth = old->ddp_trad[selected].ddp_phys_birth;
    flat->ddp_flat.ddp_class_start = timestamp;
    return (0);
}
#endif
