#ifndef PLUGIN_H
#define PLUGIN_H

#include <inttypes.h>

#ifndef CONFIG_PLUGIN
#define CONFIG_PLUGIN 0
#endif
static const int plugin_level = CONFIG_PLUGIN; // CONFIG_PLUGIN should be int

#if CONFIG_PLUGIN >= 2
#include "capstone/capstone.h"

typedef struct CPUPluginActionBranch {
    bool valid;
    bool taken; // TODO
    uint64_t target; // TODO
} CPUPluginActionBranch;

// TODO:mat?
typedef struct CPUPluginActionFetch {
    uint64_t pc;
    uint64_t pa;
    uint32_t insn;
} CPUPluginActionFetch;

typedef struct CPUPluginActionMemory {
    int op_id;
    int size;
    int num_pa;
    uint64_t base;
    uint64_t index;
    int64_t  disp;
    uint64_t va;
    uint64_t pa[2];
} CPUPluginActionMemory;

typedef enum CPUPluginRegType {
    PLUGIN_REG_INV  = 0,
    PLUGIN_REG_FR   = 1,
    PLUGIN_REG_FCC  = 2,
    PLUGIN_REG_FCSR = 3,
    PLUGIN_REG_GR   = 4,
    PLUGIN_REG_SCR  = 5
} CPUPluginRegType;

typedef struct CPUPluginRegMeta {
    CPUPluginRegType  type;
    unsigned int index;
} CPUPluginRegMeta;

typedef struct CPUPluginActionOperand{
    cs_loongarch_op op;
    CPUPluginRegMeta meta;
    uint8_t  res[256];
} CPUPluginActionOperand;

#define LA_EMU_PLUGIN_MAX_OPERAND 5
#define LA_EMU_PLUGIN_MAX_MEMORY  1
typedef struct CPUPluginAction {
    CPUPluginActionFetch  fetch;
    CPUPluginActionBranch branch;
    int op_count;
    CPUPluginActionOperand operands[LA_EMU_PLUGIN_MAX_OPERAND];
    uint8_t mem_count;
    CPUPluginActionMemory memory[LA_EMU_PLUGIN_MAX_MEMORY];
} CPUPluginAction;

typedef struct CPUPluginDisasm {
	csh handle;
	cs_insn* insn;
    uint64_t addr;
    uint8_t  code[4];
    const uint8_t* buffer[1];
} CPUPluginDisasm;


void la_emu_plugin_disasm_start(CPUPluginDisasm* disasm);
void la_emu_plugin_disasm_stop(CPUPluginDisasm* disasm);
void la_emu_plugin_disasm_work(CPUPluginDisasm* disasm, uint64_t pc, uint32_t code);

void la_emu_plugin_action_start();
void la_emu_plugin_action_stop();
void la_emu_plugin_action_before(void* env);
void la_emu_plugin_action_after(void* env);

void la_emu_plugin_record_memory(CPUPluginActionMemory* memory, uint64_t va, int num_pa, uint64_t* pa, int size);

extern CPUPluginRegMeta la_emu_reg_meta_table[LOONGARCH_REG_ENDING];


#endif

typedef struct la_emu_plugin_ops {
    void (*emu_start)(void);
    void (*emu_stop)(void);
    void (*emu_insn_before)(void* env, uint64_t pc, uint32_t insn);
    void (*emu_insn_after)(void* env);
    void (*emu_execption)(void* env, int ecode);
} la_emu_plugin_ops;



typedef la_emu_plugin_ops* (*la_emu_plugin_install_func_t)(const char *);

void la_emu_save_checkpoint(void *env, char* name);

#endif /* PLUGIN_H */
