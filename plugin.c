#include "cpu.h"
#include <stdio.h>

#if CONFIG_PLUGIN >= 2

#include "capstone/capstone.h"

bool initialized = false;
CPUPluginDisasm disasm_env;

void la_emu_plugin_disasm_start(CPUPluginDisasm* disasm) {
    cs_err res = CS_ERR_OK;
	res = cs_open(CS_ARCH_LOONGARCH, CS_MODE_LOONGARCH64, &disasm->handle);
    assert(res == CS_ERR_OK);
	res = cs_option(disasm->handle, CS_OPT_DETAIL, CS_OPT_ON);
    assert(res == CS_ERR_OK);
    disasm->insn = cs_malloc(disasm->handle);
}

void la_emu_plugin_disasm_work(CPUPluginDisasm* disasm, uint64_t pc, uint32_t code) {
    disasm->addr = pc;
    size_t size = 4;
    *(uint32_t*)disasm->code = code;
    disasm->buffer[0] = disasm->code;
    assert(disasm->buffer[0] == disasm->code);
    bool res = cs_disasm_iter(disasm->handle, disasm->buffer, &size, &disasm->addr, disasm->insn);
    if(!res){
        fprintf(stderr, "Failed to disasm:%016lx:%08x\n", pc, code);
    }
}

void la_emu_plugin_disasm_stop(CPUPluginDisasm* disasm) {
    cs_free(disasm->insn, 1);
	cs_close(&disasm->handle);
}

void la_emu_plugin_extract_value(void* _env, uint8_t* data, const CPUPluginRegMeta reg) {
    CPULoongArchState* env = (CPULoongArchState*)_env;
    if(reg.type == PLUGIN_REG_FR) {
        *(fpr_t*)data = env->fpr[reg.index];
    } else if(reg.type == PLUGIN_REG_GR) {
        *(uint64_t*)data = env->gpr[reg.index];
    } else if(reg.type == PLUGIN_REG_FCC) {
        *(bool*)data = env->cf[reg.index];
    } else if(reg.type == PLUGIN_REG_FCSR) {
        if(reg.index == 0) {
            *(uint32_t*)data = env->fcsr0;
        }
        // TODO
    } else if(reg.type == PLUGIN_REG_SCR){
        // TODO
    }
}

void la_emu_plugin_action_start(){
    assert(!initialized);
    initialized = true;
    la_emu_plugin_disasm_start(&disasm_env);
}

void la_emu_plugin_action_stop(){
    if(initialized) {
        la_emu_plugin_disasm_stop(&disasm_env);
        initialized = false;
    }
}

void la_emu_plugin_action_before(void* _env){
    CPULoongArchState* env = (CPULoongArchState*)_env;
    la_emu_plugin_disasm_work(&disasm_env, env->action.fetch.pc, env->action.fetch.insn);
    cs_detail* detail = disasm_env.insn->detail;
    env->action.op_count = detail->loongarch.op_count;
    for(int i = 0;i < detail->loongarch.op_count;i += 1) {
        const cs_loongarch_op* op = &detail->loongarch.operands[i];
        env->action.operands[i].op = *op;
        uint8_t* data = env->action.operands[i].res;
        int mem_id;
		switch(op->type){
			case LOONGARCH_OP_REG:
                env->action.operands[i].meta = la_emu_reg_meta_table[op->reg];
                la_emu_plugin_extract_value(_env, data, env->action.operands[i].meta);
				//printf("%d", op->reg);
				break;
			case LOONGARCH_OP_IMM:
                *(int64_t*)data = op->imm;
				break;
			case LOONGARCH_OP_MEM:
                mem_id = env->action.mem_count++;
                env->action.memory[mem_id].op_id = i;
                env->action.memory[mem_id].base  = env->gpr[op->mem.base];
                env->action.memory[mem_id].index = env->gpr[op->mem.index];
                env->action.memory[mem_id].disp  = op->mem.disp;
				//printf("[Reg %d + Reg %d + Imm %ld]", op->mem.base, op->mem.index, op->mem.disp);
				break;
			case LOONGARCH_OP_INVALID:
                assert(false);
				break;
		}
    }
    // fix access
    if(LOONGARCH_INS_LDGT_B <= disasm_env.insn->id && disasm_env.insn->id <= LOONGARCH_INS_LL_W){
        env->action.operands[0].op.access = CS_AC_WRITE;
    }
}

void la_emu_plugin_action_after(void* _env){
    CPULoongArchState* env = (CPULoongArchState*)_env;
    for(int i = 0;i < env->action.op_count;i += 1) {
        const cs_loongarch_op* op = &env->action.operands[i].op;
        if(op->type == LOONGARCH_OP_REG){
            bool is_write = op->access & CS_AC_WRITE;
            if(is_write) {
                uint8_t* data = env->action.operands[i].res;
                la_emu_plugin_extract_value(_env, data, env->action.operands[i].meta);
            }
            //#define PLUGIN_CHECK_RO TODO
            #ifdef PLUGIN_CHECK_RO
            else {
                bool has_write = false;
                for(int j = 0;j < i;j += 1) {
                    if(env->action.operands[j].op.type == LOONGARCH_OP_REG && op->reg == env->action.operands[j].op.reg){
                        has_write = true;
                    }
                }
                if(has_write){
                    continue;
                }
                uint8_t data[32] = {};
                la_emu_plugin_extract_value(_env, data, env->action.operands[i].meta);
                if(memcmp(data, env->action.operands[i].res, 32) != 0){
                    fprintf(stderr, "register %d is not read only:\n", i);
                    fprintf(stderr, "    %s %s\n",disasm_env.insn->mnemonic, disasm_env.insn->op_str);
                    for(int j = 0;j < env->action.op_count;j += 1) {
                        if(env->action.operands[j].op.type == LOONGARCH_OP_REG){
                            fprintf(stderr, "operand%d:%d %d %d\n", j, env->action.operands[j].op.type, env->action.operands[j].op.reg, env->action.operands[j].op.access);
                        }
                    }
                }
            }
            #endif
        }
    }
#define DUMP_LOAD
//#define DUMP_INSN
#if defined(DUMP_INSN) || defined(DUMP_LOAD)
    CPUPluginActionOperand* dst_op = &env->action.operands[0];
#endif
#if defined(DUMP_INSN)
    fprintf(stderr, "%s %s (RES=%lx)\n", disasm_env.insn->mnemonic, disasm_env.insn->op_str, *(uint64_t*)dst_op->res);
#endif
#if defined(DUMP_LOAD)
    CPUPluginActionOperand* mem_op = &env->action.operands[env->action.memory[0].op_id];
    if(env->action.mem_count > 0 && mem_op->op.access == CS_AC_READ){
        fprintf(stdout, "PC=%016lx,size=%d,VA=%016lx,PA=%016lx,RES=%016lx\n", 
                env->action.fetch.pc,
                env->action.memory[0].size,
                env->action.memory[0].va,
                env->action.memory[0].pa[0],
                *(uint64_t*)dst_op->res);
    }
#endif
}

void la_emu_plugin_record_memory(CPUPluginActionMemory* memory, uint64_t va, int num_pa, uint64_t* pa, int size) {
    memory->va = va;
    memory->num_pa = num_pa;
    for(int i = 0;i < num_pa;i += 1){
        memory->pa[i] = pa[i];
    }
    memory->size = size;
}

CPUPluginRegMeta la_emu_reg_meta_table[LOONGARCH_REG_ENDING] = {
	[LOONGARCH_REG_INVALID] = {PLUGIN_REG_INV, 0},
	[LOONGARCH_REG_F0    ]  = {PLUGIN_REG_FR, 0},
	[LOONGARCH_REG_F1    ]  = {PLUGIN_REG_FR, 1},
	[LOONGARCH_REG_F2    ]  = {PLUGIN_REG_FR, 2},
	[LOONGARCH_REG_F3    ]  = {PLUGIN_REG_FR, 3},
	[LOONGARCH_REG_F4    ]  = {PLUGIN_REG_FR, 4},
	[LOONGARCH_REG_F5    ]  = {PLUGIN_REG_FR, 5},
	[LOONGARCH_REG_F6    ]  = {PLUGIN_REG_FR, 6},
	[LOONGARCH_REG_F7    ]  = {PLUGIN_REG_FR, 7},
	[LOONGARCH_REG_F8    ]  = {PLUGIN_REG_FR, 8},
	[LOONGARCH_REG_F9    ]  = {PLUGIN_REG_FR, 9},
	[LOONGARCH_REG_F10   ]  = {PLUGIN_REG_FR,10},
	[LOONGARCH_REG_F11   ]  = {PLUGIN_REG_FR,11},
	[LOONGARCH_REG_F12   ]  = {PLUGIN_REG_FR,12},
	[LOONGARCH_REG_F13   ]  = {PLUGIN_REG_FR,13},
	[LOONGARCH_REG_F14   ]  = {PLUGIN_REG_FR,14},
	[LOONGARCH_REG_F15   ]  = {PLUGIN_REG_FR,15},
	[LOONGARCH_REG_F16   ]  = {PLUGIN_REG_FR,16},
	[LOONGARCH_REG_F17   ]  = {PLUGIN_REG_FR,17},
	[LOONGARCH_REG_F18   ]  = {PLUGIN_REG_FR,18},
	[LOONGARCH_REG_F19   ]  = {PLUGIN_REG_FR,19},
	[LOONGARCH_REG_F20   ]  = {PLUGIN_REG_FR,20},
	[LOONGARCH_REG_F21   ]  = {PLUGIN_REG_FR,21},
	[LOONGARCH_REG_F22   ]  = {PLUGIN_REG_FR,22},
	[LOONGARCH_REG_F23   ]  = {PLUGIN_REG_FR,23},
	[LOONGARCH_REG_F24   ]  = {PLUGIN_REG_FR,24},
	[LOONGARCH_REG_F25   ]  = {PLUGIN_REG_FR,25},
	[LOONGARCH_REG_F26   ]  = {PLUGIN_REG_FR,26},
	[LOONGARCH_REG_F27   ]  = {PLUGIN_REG_FR,27},
	[LOONGARCH_REG_F28   ]  = {PLUGIN_REG_FR,28},
	[LOONGARCH_REG_F29   ]  = {PLUGIN_REG_FR,29},
	[LOONGARCH_REG_F30   ]  = {PLUGIN_REG_FR,30},
	[LOONGARCH_REG_F31   ]  = {PLUGIN_REG_FR,31},
	[LOONGARCH_REG_FCC0  ]  = {PLUGIN_REG_FCC, 0},
	[LOONGARCH_REG_FCC1  ]  = {PLUGIN_REG_FCC, 1},
	[LOONGARCH_REG_FCC2  ]  = {PLUGIN_REG_FCC, 2},
	[LOONGARCH_REG_FCC3  ]  = {PLUGIN_REG_FCC, 3},
	[LOONGARCH_REG_FCC4  ]  = {PLUGIN_REG_FCC, 4},
	[LOONGARCH_REG_FCC5  ]  = {PLUGIN_REG_FCC, 5},
	[LOONGARCH_REG_FCC6  ]  = {PLUGIN_REG_FCC, 6},
	[LOONGARCH_REG_FCC7  ]  = {PLUGIN_REG_FCC, 7},
	[LOONGARCH_REG_FCSR0 ]  = {PLUGIN_REG_FCSR, 0},
	[LOONGARCH_REG_FCSR1 ]  = {PLUGIN_REG_FCSR, 1},
	[LOONGARCH_REG_FCSR2 ]  = {PLUGIN_REG_FCSR, 2},
	[LOONGARCH_REG_FCSR3 ]  = {PLUGIN_REG_FCSR, 3},
	[LOONGARCH_REG_R0    ]  = {PLUGIN_REG_GR, 0},
	[LOONGARCH_REG_R1    ]  = {PLUGIN_REG_GR, 1},
	[LOONGARCH_REG_R2    ]  = {PLUGIN_REG_GR, 2},
	[LOONGARCH_REG_R3    ]  = {PLUGIN_REG_GR, 3},
	[LOONGARCH_REG_R4    ]  = {PLUGIN_REG_GR, 4},
	[LOONGARCH_REG_R5    ]  = {PLUGIN_REG_GR, 5},
	[LOONGARCH_REG_R6    ]  = {PLUGIN_REG_GR, 6},
	[LOONGARCH_REG_R7    ]  = {PLUGIN_REG_GR, 7},
	[LOONGARCH_REG_R8    ]  = {PLUGIN_REG_GR, 8},
	[LOONGARCH_REG_R9    ]  = {PLUGIN_REG_GR, 9},
	[LOONGARCH_REG_R10   ]  = {PLUGIN_REG_GR,10},
	[LOONGARCH_REG_R11   ]  = {PLUGIN_REG_GR,11},
	[LOONGARCH_REG_R12   ]  = {PLUGIN_REG_GR,12},
	[LOONGARCH_REG_R13   ]  = {PLUGIN_REG_GR,13},
	[LOONGARCH_REG_R14   ]  = {PLUGIN_REG_GR,14},
	[LOONGARCH_REG_R15   ]  = {PLUGIN_REG_GR,15},
	[LOONGARCH_REG_R16   ]  = {PLUGIN_REG_GR,16},
	[LOONGARCH_REG_R17   ]  = {PLUGIN_REG_GR,17},
	[LOONGARCH_REG_R18   ]  = {PLUGIN_REG_GR,18},
	[LOONGARCH_REG_R19   ]  = {PLUGIN_REG_GR,19},
	[LOONGARCH_REG_R20   ]  = {PLUGIN_REG_GR,20},
	[LOONGARCH_REG_R21   ]  = {PLUGIN_REG_GR,21},
	[LOONGARCH_REG_R22   ]  = {PLUGIN_REG_GR,22},
	[LOONGARCH_REG_R23   ]  = {PLUGIN_REG_GR,23},
	[LOONGARCH_REG_R24   ]  = {PLUGIN_REG_GR,24},
	[LOONGARCH_REG_R25   ]  = {PLUGIN_REG_GR,25},
	[LOONGARCH_REG_R26   ]  = {PLUGIN_REG_GR,26},
	[LOONGARCH_REG_R27   ]  = {PLUGIN_REG_GR,27},
	[LOONGARCH_REG_R28   ]  = {PLUGIN_REG_GR,28},
	[LOONGARCH_REG_R29   ]  = {PLUGIN_REG_GR,29},
	[LOONGARCH_REG_R30   ]  = {PLUGIN_REG_GR,30},
	[LOONGARCH_REG_R31   ]  = {PLUGIN_REG_GR,31},
	[LOONGARCH_REG_SCR0  ]  = {PLUGIN_REG_SCR, 0},
	[LOONGARCH_REG_SCR1  ]  = {PLUGIN_REG_SCR, 1},
	[LOONGARCH_REG_SCR2  ]  = {PLUGIN_REG_SCR, 2},
	[LOONGARCH_REG_SCR3  ]  = {PLUGIN_REG_SCR, 3},
	[LOONGARCH_REG_VR0   ]  = {PLUGIN_REG_FR, 0},
	[LOONGARCH_REG_VR1   ]  = {PLUGIN_REG_FR, 1},
	[LOONGARCH_REG_VR2   ]  = {PLUGIN_REG_FR, 2},
	[LOONGARCH_REG_VR3   ]  = {PLUGIN_REG_FR, 3},
	[LOONGARCH_REG_VR4   ]  = {PLUGIN_REG_FR, 4},
	[LOONGARCH_REG_VR5   ]  = {PLUGIN_REG_FR, 5},
	[LOONGARCH_REG_VR6   ]  = {PLUGIN_REG_FR, 6},
	[LOONGARCH_REG_VR7   ]  = {PLUGIN_REG_FR, 7},
	[LOONGARCH_REG_VR8   ]  = {PLUGIN_REG_FR, 8},
	[LOONGARCH_REG_VR9   ]  = {PLUGIN_REG_FR, 9},
	[LOONGARCH_REG_VR10  ]  = {PLUGIN_REG_FR,10},
	[LOONGARCH_REG_VR11  ]  = {PLUGIN_REG_FR,11},
	[LOONGARCH_REG_VR12  ]  = {PLUGIN_REG_FR,12},
	[LOONGARCH_REG_VR13  ]  = {PLUGIN_REG_FR,13},
	[LOONGARCH_REG_VR14  ]  = {PLUGIN_REG_FR,14},
	[LOONGARCH_REG_VR15  ]  = {PLUGIN_REG_FR,15},
	[LOONGARCH_REG_VR16  ]  = {PLUGIN_REG_FR,16},
	[LOONGARCH_REG_VR17  ]  = {PLUGIN_REG_FR,17},
	[LOONGARCH_REG_VR18  ]  = {PLUGIN_REG_FR,18},
	[LOONGARCH_REG_VR19  ]  = {PLUGIN_REG_FR,19},
	[LOONGARCH_REG_VR20  ]  = {PLUGIN_REG_FR,20},
	[LOONGARCH_REG_VR21  ]  = {PLUGIN_REG_FR,21},
	[LOONGARCH_REG_VR22  ]  = {PLUGIN_REG_FR,22},
	[LOONGARCH_REG_VR23  ]  = {PLUGIN_REG_FR,23},
	[LOONGARCH_REG_VR24  ]  = {PLUGIN_REG_FR,24},
	[LOONGARCH_REG_VR25  ]  = {PLUGIN_REG_FR,25},
	[LOONGARCH_REG_VR26  ]  = {PLUGIN_REG_FR,26},
	[LOONGARCH_REG_VR27  ]  = {PLUGIN_REG_FR,27},
	[LOONGARCH_REG_VR28  ]  = {PLUGIN_REG_FR,28},
	[LOONGARCH_REG_VR29  ]  = {PLUGIN_REG_FR,29},
	[LOONGARCH_REG_VR30  ]  = {PLUGIN_REG_FR,30},
	[LOONGARCH_REG_VR31  ]  = {PLUGIN_REG_FR,31},
	[LOONGARCH_REG_XR0   ]  = {PLUGIN_REG_FR, 0},
	[LOONGARCH_REG_XR1   ]  = {PLUGIN_REG_FR, 1},
	[LOONGARCH_REG_XR2   ]  = {PLUGIN_REG_FR, 2},
	[LOONGARCH_REG_XR3   ]  = {PLUGIN_REG_FR, 3},
	[LOONGARCH_REG_XR4   ]  = {PLUGIN_REG_FR, 4},
	[LOONGARCH_REG_XR5   ]  = {PLUGIN_REG_FR, 5},
	[LOONGARCH_REG_XR6   ]  = {PLUGIN_REG_FR, 6},
	[LOONGARCH_REG_XR7   ]  = {PLUGIN_REG_FR, 7},
	[LOONGARCH_REG_XR8   ]  = {PLUGIN_REG_FR, 8},
	[LOONGARCH_REG_XR9   ]  = {PLUGIN_REG_FR, 9},
	[LOONGARCH_REG_XR10  ]  = {PLUGIN_REG_FR,10},
	[LOONGARCH_REG_XR11  ]  = {PLUGIN_REG_FR,11},
	[LOONGARCH_REG_XR12  ]  = {PLUGIN_REG_FR,12},
	[LOONGARCH_REG_XR13  ]  = {PLUGIN_REG_FR,13},
	[LOONGARCH_REG_XR14  ]  = {PLUGIN_REG_FR,14},
	[LOONGARCH_REG_XR15  ]  = {PLUGIN_REG_FR,15},
	[LOONGARCH_REG_XR16  ]  = {PLUGIN_REG_FR,16},
	[LOONGARCH_REG_XR17  ]  = {PLUGIN_REG_FR,17},
	[LOONGARCH_REG_XR18  ]  = {PLUGIN_REG_FR,18},
	[LOONGARCH_REG_XR19  ]  = {PLUGIN_REG_FR,19},
	[LOONGARCH_REG_XR20  ]  = {PLUGIN_REG_FR,20},
	[LOONGARCH_REG_XR21  ]  = {PLUGIN_REG_FR,21},
	[LOONGARCH_REG_XR22  ]  = {PLUGIN_REG_FR,22},
	[LOONGARCH_REG_XR23  ]  = {PLUGIN_REG_FR,23},
	[LOONGARCH_REG_XR24  ]  = {PLUGIN_REG_FR,24},
	[LOONGARCH_REG_XR25  ]  = {PLUGIN_REG_FR,25},
	[LOONGARCH_REG_XR26  ]  = {PLUGIN_REG_FR,26},
	[LOONGARCH_REG_XR27  ]  = {PLUGIN_REG_FR,27},
	[LOONGARCH_REG_XR28  ]  = {PLUGIN_REG_FR,28},
	[LOONGARCH_REG_XR29  ]  = {PLUGIN_REG_FR,29},
	[LOONGARCH_REG_XR30  ]  = {PLUGIN_REG_FR,30},
	[LOONGARCH_REG_XR31  ]  = {PLUGIN_REG_FR,31},
	[LOONGARCH_REG_F0_64 ]  = {PLUGIN_REG_FR, 0},
	[LOONGARCH_REG_F1_64 ]  = {PLUGIN_REG_FR, 1},
	[LOONGARCH_REG_F2_64 ]  = {PLUGIN_REG_FR, 2},
	[LOONGARCH_REG_F3_64 ]  = {PLUGIN_REG_FR, 3},
	[LOONGARCH_REG_F4_64 ]  = {PLUGIN_REG_FR, 4},
	[LOONGARCH_REG_F5_64 ]  = {PLUGIN_REG_FR, 5},
	[LOONGARCH_REG_F6_64 ]  = {PLUGIN_REG_FR, 6},
	[LOONGARCH_REG_F7_64 ]  = {PLUGIN_REG_FR, 7},
	[LOONGARCH_REG_F8_64 ]  = {PLUGIN_REG_FR, 8},
	[LOONGARCH_REG_F9_64 ]  = {PLUGIN_REG_FR, 9},
	[LOONGARCH_REG_F10_64]  = {PLUGIN_REG_FR,10},
	[LOONGARCH_REG_F11_64]  = {PLUGIN_REG_FR,11},
	[LOONGARCH_REG_F12_64]  = {PLUGIN_REG_FR,12},
	[LOONGARCH_REG_F13_64]  = {PLUGIN_REG_FR,13},
	[LOONGARCH_REG_F14_64]  = {PLUGIN_REG_FR,14},
	[LOONGARCH_REG_F15_64]  = {PLUGIN_REG_FR,15},
	[LOONGARCH_REG_F16_64]  = {PLUGIN_REG_FR,16},
	[LOONGARCH_REG_F17_64]  = {PLUGIN_REG_FR,17},
	[LOONGARCH_REG_F18_64]  = {PLUGIN_REG_FR,18},
	[LOONGARCH_REG_F19_64]  = {PLUGIN_REG_FR,19},
	[LOONGARCH_REG_F20_64]  = {PLUGIN_REG_FR,20},
	[LOONGARCH_REG_F21_64]  = {PLUGIN_REG_FR,21},
	[LOONGARCH_REG_F22_64]  = {PLUGIN_REG_FR,22},
	[LOONGARCH_REG_F23_64]  = {PLUGIN_REG_FR,23},
	[LOONGARCH_REG_F24_64]  = {PLUGIN_REG_FR,24},
	[LOONGARCH_REG_F25_64]  = {PLUGIN_REG_FR,25},
	[LOONGARCH_REG_F26_64]  = {PLUGIN_REG_FR,26},
	[LOONGARCH_REG_F27_64]  = {PLUGIN_REG_FR,27},
	[LOONGARCH_REG_F28_64]  = {PLUGIN_REG_FR,28},
	[LOONGARCH_REG_F29_64]  = {PLUGIN_REG_FR,29},
	[LOONGARCH_REG_F30_64]  = {PLUGIN_REG_FR,30},
	[LOONGARCH_REG_F31_64]  = {PLUGIN_REG_FR,31},
};

#endif
