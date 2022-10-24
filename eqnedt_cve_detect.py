

import ida_dbg
import ida_ida
import idaapi
import idc
import os


def set_breakpoint(addr, conditon):
    if addr == idaapi.BADADDR:
        return False

    idaapi.add_bpt(addr, 0, idaapi.BPT_SOFT)
    idaapi.enable_bpt(addr, True)
    bpt = idaapi.bpt_t()
    idaapi.get_bpt(addr, bpt)
    bpt.elang = 'Python'
    bpt.condition = conditon
    idaapi.update_bpt(bpt)
    return True

def find_ret(start):
    fnct = idaapi.get_func(start)
    if fnct:
        ea = fnct.start_ea
        while ea < fnct.end_ea:
            insn = idaapi.insn_t()
            if not idaapi.decode_insn(insn, ea):
                print('failed to decode instruction at %x', ea)
                continue
            if insn.itype == idaapi.NN_retn:
                break
            else:
                ea = idc.next_head(ea)
        return ea

    else:
        print('No function at cursor')
        return idaapi.BADADDR


class ApiDbgHook(ida_dbg.DBG_Hooks):
    def dbg_run_to(self, pid, tid=0, ea=0):
        print("got run_to: pid: %d tid: %d ea: 0x%x" % (pid, tid, ea))
        ida_dbg.continue_process()
        return 0

    def dbg_process_exit(self, pid, tid, ea, code):
        print("Process exited pid=%d tid=%d ea=0x%x code=%d" % (pid, tid, ea, code))
        os.system('taskkill /F /IM WINWORD.exe')
        return 0


class FunctionBlock(object):
    __start_cond = """esp = idc.get_reg_value('ESP')
eip = idc.get_reg_value('EIP')
ret_addr = ida_bytes.get_wide_dword(esp)
origin_return[eip]=ret_addr
print('EIP:0x%x return address: 0x%x' % (eip, ret_addr))
return False"""
    __end_cond = """esp = idc.get_reg_value('ESP')
eip = idc.get_reg_value('EIP')
start_ea = idaapi.get_func(eip).start_ea
ret_addr = ida_bytes.get_wide_dword(esp)
if origin_return[start_ea] != ret_addr:
    idaapi.msg_clear()
    print('EIP:0x%x overwritten address: 0x%x original: 0x%x' % (eip, ret_addr, origin_return[start_ea]))
    print(f'%s found!!' % EA_CVE_dict[start_ea])
    return True
else:    
    return False"""

    def __init__(self, start, cve):
        self.start = start
        self.end = find_ret(start)
        self.cve = cve
        self.ori_retn = idaapi.BADADDR
        self.start_condtion = None
        self.end_condition = None
        self.added_bpts = False
        print(f"ctor start {self.start:x}, end: {self.end:x}, cve: {self.cve}")

    def enable_bps(self):
        set_breakpoint(self.start, self.__start_cond)
        set_breakpoint(self.end, self.__end_cond)
        self.added_bpts = True
        return 0




EA_CVE_dict = {
    0x443E34: 'CVE-2018-0798',
    0x41160f: 'CVE-2017-11882',
    0x421774: 'CVE-2018-0802'}

origin_return = {}

for ea, cve in EA_CVE_dict.items():
    fblock = FunctionBlock(ea, cve)
    fblock.enable_bps()



try:
    if debughook:
        print("Removing previous hook ...")
        debughook.unhook()
        debughook = None
except:
    pass

debughook = ApiDbgHook()
debughook.hook()
print("Installed debugger hook!")

ida_dbg.load_debugger('win32', True)
ida_dbg.run_to(ida_ida.cvar.inf.start_ea)
