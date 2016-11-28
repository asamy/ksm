#ifndef __EXPORTS_H
#define __EXPORTS_H

extern int run_allgood(void);
extern int run_fail_entry(void);
extern int run_go_vmx(void);
extern int run_ept(void);

extern int initialize_features(void);
extern int give_me_root(void *vmxon);
extern int init_vmcs(void *vmcs);
extern void adjust_ctl_val(u32 msr, u32 *val);
extern bool setup_basic_vmcs(u32 other_primary, u32 other_secondary, uintptr_t sp, uintptr_t ip, uintptr_t stack);
extern int launch_vcpu(void);

#endif
