# -*- coding: utf-8 -*-
"""Isolated execution tests for the 蛮荒 auto-collect/dispatch settings.

The game is ASLR enabled. These tests deliberately load the injected code at
0xC20000 (the base observed in a real crash dump), not at the PE image base,
so any accidentally absolute address is caught here.
"""
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
import patch_wild_autocollect as pw
from petool import PE, IMAGE_BASE
from unicorn import Uc, UC_ARCH_X86, UC_MODE_32, UC_HOOK_CODE, UC_PROT_ALL
from unicorn.x86_const import (
    UC_X86_REG_EAX, UC_X86_REG_EBP, UC_X86_REG_EBX, UC_X86_REG_ECX,
    UC_X86_REG_ESP, UC_X86_REG_EDX, UC_X86_REG_EIP,
)

PATCHED = pw.OUT
RUNTIME_BASE = 0xC20000

SENTINEL = 0x30000000
STACK = 0x200000
FRAME = 0x201000
OBJECT = 0x210000
GAME = 0x220000
SLOTS = 0x230000
ITEMS = 0x240000
INVENTORY = 0x250000
FARM = 0x260000
FARM_DEFS = 0x270000
STUB_BASE = 0x1000000

STUB_GPI = STUB_BASE + 0x00
STUB_WPS = STUB_BASE + 0x10
STUB_ISWINDOW = STUB_BASE + 0x20
STUB_SENDMSG = STUB_BASE + 0x30
STUB_MAPRECT = STUB_BASE + 0x40
STUB_HMODULE = STUB_BASE + 0x50
STUB_CREATE = STUB_BASE + 0x60
STUB_SETWNDLONG = STUB_BASE + 0x70
STUB_CALLWNDPROC = STUB_BASE + 0x80


def rt(va):
    return RUNTIME_BASE + (va - IMAGE_BASE)


def p32(value):
    return struct.pack("<I", value)


class Harness:
    def __init__(self):
        pe = PE(PATCHED)
        self.pe = pe
        self.uc = Uc(UC_ARCH_X86, UC_MODE_32)
        self.uc.mem_map(RUNTIME_BASE, 0x310000, UC_PROT_ALL)
        for base, size in [
            (STACK, 0x3000), (OBJECT, 0x1000), (GAME, 0x2000),
            (SLOTS, 0x1000), (ITEMS, 0x1000), (STUB_BASE, 0x1000),
            (FARM, 0x3000), (FARM_DEFS, 0x2000),
        ]:
            self.uc.mem_map(base, size, UC_PROT_ALL)
        self.uc.mem_write(GAME + 0x11B8, p32(INVENTORY))

        self._copy(pw.AUTO_VA, 0x60)
        self._copy(pw.SYNC_VA, 0x200)
        self._copy(pw.AFTER_VA, 0x40)
        self._copy(pw.ADISPATCH_VA, 0x100)
        self._copy(pw.SYNC2_VA, 0x160)
        self._copy(pw.EXT_UI_VA, 0x90)
        self._copy(pw.CHECKBOX_VA, 0xC0)
        self._copy(pw.MANUAL_HARVEST_VA, 0xA0)
        self._copy(pw.FARM_EPI_VA, pw.FARM_VA - pw.FARM_EPI_VA)
        self._copy(pw.FARM_VA, 0xA0)
        self._copy(pw.FARM_TICK_VA, 7)
        self._copy(pw.UI_VA, 0x120)
        self._copy(pw.DISPATCH_UI_VA, 0x100)
        self._copy(pw.WNDPROC_VA, 0x80)
        self._copy(pw.DUNGEON_RETRY_VA, 0x80)
        self._copy(pw.HOOK_SETTINGS_INIT_VA, 9)

        self._write_va(pw.WASHD_CLASS_VA, "BUTTON\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_TEXT_VA,
                       "\u81ea\u52a8\u6536\u53d6\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_DISPATCH_TEXT_VA,
                       "\u81ea\u52a8\u6d3e\u9063\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_APP_VA, "Wild\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_KEY_VA, "AutoCollect\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_DISPATCH_KEY_VA,
                       "AutoDispatch\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_HARVEST_TEXT_VA,
                       "\u81ea\u52a8\u6536\u83b7\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_PLANT_TEXT_VA,
                       "\u81ea\u52a8\u79cd\u690d\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_HARVEST_KEY_VA,
                       "AutoHarvest\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_PLANT_KEY_VA,
                       "AutoPlant\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_ON_VA, "1\x00".encode("utf-16-le"))
        self._write_va(pw.WASHD_OFF_VA, "0\x00".encode("utf-16-le"))
        self._write_va(pw.WILD_INI_VA, "wild.ini\x00".encode("utf-16-le"))

        for slot, stub in [
            (pw.GET_PRIVATE_PROFILE_INT_W, STUB_GPI),
            (pw.WRITE_PRIVATE_PROFILE_STRING_W, STUB_WPS),
            (pw.IS_WINDOW, STUB_ISWINDOW),
            (pw.SEND_MESSAGE_W, STUB_SENDMSG),
            (pw.MAP_DIALOG_RECT, STUB_MAPRECT),
            (pw.GET_MODULE_HANDLE_W, STUB_HMODULE),
            (pw.CREATE_WINDOW_EX_W, STUB_CREATE),
            (pw.SET_WINDOW_LONG_W, STUB_SETWNDLONG),
            (pw.CALL_WINDOW_PROC_W, STUB_CALLWNDPROC),
        ]:
            self._write_va(slot, p32(stub))
        for stub in (STUB_GPI, STUB_WPS, STUB_ISWINDOW, STUB_SENDMSG,
                     STUB_MAPRECT, STUB_HMODULE, STUB_CREATE, STUB_SETWNDLONG,
                     STUB_CALLWNDPROC):
            self.uc.mem_write(stub, b"\xC3")

        self.uc.hook_add(UC_HOOK_CODE, self._hook)

        self.profile_collect = 1
        self.profile_dispatch = 0
        self.profile_harvest = 0
        self.profile_plant = 0
        self.profile_calls = []
        self.is_window = 1
        self.check_value = 1
        self.dispatch_check_value = 0
        self.harvest_check_value = 0
        self.plant_check_value = 0
        self.collect_check_hwnd = 0
        self.dispatch_check_hwnd = 0
        self.harvest_check_hwnd = 0
        self.plant_check_hwnd = 0
        self.sync_setting = 1
        self.intercept_sync = False
        self.created_hwnd = 0x11223344
        self.dispatch_hwnd = 0x11223345
        self.harvest_hwnd = 0x11223346
        self.plant_hwnd = 0x11223347
        self.parent_hwnd = 0x55667788
        self.old_wndproc = 0x33445566
        self.callwndproc_result = 0x5555AAAA
        self.write_calls = []
        self.create_calls = []
        self.send_calls = []
        self.setwndlong_calls = []
        self.callwndproc_calls = []
        self.sync_calls = 0

        self.can_collect = True
        self.game_ptr = GAME
        self.collect_result = 0
        self.collect_count = 0
        self.can_collect_count = 0
        self.size_count = 0
        self.size_ecx = None
        self.collect_ecx = None
        self.collect_eax = None

        self.dispatch_calls = []
        self.reset_calls = 0
        self.pet_valid_calls = []
        self.selected_queries = []
        self.item_type_calls = []
        self.item_available_calls = []
        self.pet_invalid = 0
        self.item_types = {}
        self.items_available = 1
        self.selected_items = []
        self.events = []

        self.farm_ptr = FARM
        self.harvest_calls = []
        self.harvest_ids = []
        self.plant_calls = []
        self.harvest_success = True
        self.plant_success = True

    def _copy(self, va, size):
        self.uc.mem_write(rt(va), self.pe.bytes_at(va, size))

    def _write_va(self, va, data):
        self.uc.mem_write(rt(va), data)

    def _read_va(self, va, size):
        return bytes(self.uc.mem_read(rt(va), size))

    def _wstr(self, va):
        out = bytearray()
        for i in range(0, 0x400, 2):
            pair = bytes(self.uc.mem_read(va + i, 2))
            if pair == b"\x00\x00":
                break
            out += pair
        return out.decode("utf-16-le")

    def _args(self, count):
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        raw = bytes(self.uc.mem_read(esp + 4, count * 4))
        return list(struct.unpack("<" + "I" * count, raw))

    def _return_from_hook(self, eax=None, callee_pop=0):
        esp = self.uc.reg_read(UC_X86_REG_ESP)
        ret = struct.unpack("<I", self.uc.mem_read(esp, 4))[0]
        self.uc.reg_write(UC_X86_REG_ESP, esp + 4 + callee_pop)
        self.uc.reg_write(UC_X86_REG_EIP, ret)
        if eax is not None:
            self.uc.reg_write(UC_X86_REG_EAX, eax)

    def _hook(self, uc, address, size, user_data):
        if self.intercept_sync and address == rt(pw.SYNC_VA):
            self.sync_calls += 1
            self._return_from_hook(self.sync_setting)
        elif address == rt(pw.GAME_VA):
            self._return_from_hook(self.game_ptr)
        elif address == rt(pw.CAN_COLLECT_VA):
            self.can_collect_count += 1
            self._return_from_hook(1 if self.can_collect else 0)
        elif address == rt(pw.CONTAINER_SIZE_VA):
            self.size_count += 1
            self.size_ecx = uc.reg_read(UC_X86_REG_ECX)
            self._return_from_hook(self.container_size)
        elif address == rt(pw.COLLECT_VA):
            self.collect_count += 1
            self.collect_ecx = uc.reg_read(UC_X86_REG_ECX)
            self.collect_eax = uc.reg_read(UC_X86_REG_EAX)
            self._return_from_hook(self.collect_result)
        elif address == rt(pw.RESET_WILD_VA):
            self.reset_calls += 1
            self.events.append("reset")
            wild = uc.reg_read(UC_X86_REG_ECX)
            uc.mem_write(wild + 0x54, b"\x00")
            uc.mem_write(wild + 0x58, p32(0))
            self._return_from_hook(0)
        elif address == rt(pw.SUBMIT_DISPATCH_VA):
            pet, items = self._args(2)
            self.dispatch_calls.append(
                (uc.reg_read(UC_X86_REG_ECX), pet, items))
            self.events.append("dispatch")
            self._return_from_hook(0, 8)
        elif address == rt(pw.PET_VALID_VA):
            self.pet_valid_calls.append(uc.reg_read(UC_X86_REG_ECX))
            self._return_from_hook(self.pet_invalid)
        elif address == rt(pw.SELECTED_ITEM_VA):
            index = self._args(1)[0]
            self.selected_queries.append(index)
            slot = SLOTS + index * 8 if index < len(self.selected_items) else 0
            self._return_from_hook(slot, 4)
        elif address == rt(pw.ITEM_TYPE_VA):
            item = uc.reg_read(UC_X86_REG_ECX)
            self.item_type_calls.append(item)
            self._return_from_hook(self.item_types.get(item, 1))
        elif address == rt(pw.ITEM_AVAILABLE_VA):
            item, count = self._args(2)
            self.item_available_calls.append(
                (uc.reg_read(UC_X86_REG_ECX), item, count))
            self.events.append("items")
            self._return_from_hook(self.items_available, 8)
        elif address == rt(pw.HARVEST_PLOT_VA):
            pit = uc.reg_read(UC_X86_REG_ECX)
            self.harvest_calls.append(pit)
            definition = struct.unpack(
                "<I", bytes(uc.mem_read(pit, 4)))[0]
            if definition:
                self.harvest_ids.append(struct.unpack(
                    "<I", bytes(uc.mem_read(definition, 4)))[0])
            if self.harvest_success:
                uc.mem_write(pit, b"\x00" * 0x10)
            self._return_from_hook(None, 8)
        elif address == rt(pw.PLANT_PLOT_VA):
            plant_id = self._args(1)[0]
            pit = uc.reg_read(UC_X86_REG_ECX)
            self.plant_calls.append((pit, plant_id))
            if self.plant_success:
                definition = FARM_DEFS + 0x1800
                uc.mem_write(definition, p32(plant_id))
                uc.mem_write(pit, p32(definition))
                uc.mem_write(pit + 4, p32(1))
            self._return_from_hook(None, 4)
        elif address == STUB_GPI:
            app, key, default, path = self._args(4)
            key_name = self._wstr(key)
            self.profile_calls.append((self._wstr(app), key_name,
                                       default, self._wstr(path)))
            if key_name == "AutoDispatch":
                result = self.profile_dispatch
            elif key_name == "AutoHarvest":
                result = self.profile_harvest
            elif key_name == "AutoPlant":
                result = self.profile_plant
            else:
                result = self.profile_collect
            self._return_from_hook(result, 16)
        elif address == STUB_WPS:
            app, key, value, path = self._args(4)
            self.write_calls.append((self._wstr(app), self._wstr(key),
                                     self._wstr(value), self._wstr(path)))
            self._return_from_hook(1, 16)
        elif address == STUB_ISWINDOW:
            self._return_from_hook(self.is_window, 4)
        elif address == STUB_SENDMSG:
            hwnd, msg, wparam, lparam = self._args(4)
            self.send_calls.append((hwnd, msg, wparam, lparam))
            result = 0
            if msg == 0xF0:
                if hwnd == self.dispatch_check_hwnd:
                    result = self.dispatch_check_value
                elif hwnd == self.harvest_check_hwnd:
                    result = self.harvest_check_value
                elif hwnd == self.plant_check_hwnd:
                    result = self.plant_check_value
                elif hwnd == self.collect_check_hwnd:
                    result = self.check_value
            elif msg == 0x31:
                result = 0x55667788
            self._return_from_hook(result, 16)
        elif address == STUB_MAPRECT:
            hwnd, rect = self._args(2)
            left, top, right, bottom = struct.unpack(
                "<iiii", bytes(uc.mem_read(rect, 16)))
            mapped = (left * 8 // 5, top * 2, right * 8 // 5, bottom * 2)
            uc.mem_write(rect, struct.pack("<iiii", *mapped))
            self._return_from_hook(1, 8)
        elif address == STUB_HMODULE:
            self._return_from_hook(0x700000, 4)
        elif address == STUB_CREATE:
            args = self._args(12)
            index = len(self.create_calls)
            self.create_calls.append(args)
            self._return_from_hook(self.created_hwnd + index, 48)
        elif address == STUB_SETWNDLONG:
            args = self._args(3)
            self.setwndlong_calls.append(tuple(args))
            self._return_from_hook(self.old_wndproc, 12)
        elif address == STUB_CALLWNDPROC:
            args = self._args(5)
            self.callwndproc_calls.append(tuple(args))
            self._return_from_hook(self.callwndproc_result, 20)

    def set_object(self, active, state, timer, state_padding=0):
        uc = self.uc
        uc.mem_write(OBJECT, p32(active))
        uc.mem_write(OBJECT + 4, struct.pack("<f", timer))
        uc.mem_write(OBJECT + 0x10, p32((state_padding << 8) | state))

    def run_sync(self, setting=1, dispatch_setting=0, init=1, hwnd=0,
                 dispatch_hwnd=0, is_window=1, check=1, dispatch_check=0,
                 profile=1, dispatch_profile=0, ext_init=1):
        self._write_va(pw.SETTING_VA, p32(setting))
        self._write_va(pw.DISPATCH_SETTING_VA, p32(dispatch_setting))
        self._write_va(pw.SETTING_INIT_VA, p32(init))
        self._write_va(pw.EXT_INIT_VA, p32(ext_init))
        self._write_va(pw.SETTING_HWND_VA, p32(hwnd))
        self._write_va(pw.DISPATCH_HWND_VA, p32(dispatch_hwnd))
        self.is_window = is_window
        self.collect_check_hwnd = hwnd
        self.dispatch_check_hwnd = dispatch_hwnd
        self.check_value = check
        self.dispatch_check_value = dispatch_check
        self.profile_collect = profile
        self.profile_dispatch = dispatch_profile
        self.profile_calls = []
        self.write_calls = []

        esp = STACK + 0x800
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.SYNC_VA))
        self.uc.emu_start(rt(pw.SYNC_VA), SENTINEL, count=1000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "eax": self.uc.reg_read(UC_X86_REG_EAX),
            "setting": struct.unpack("<I", self._read_va(pw.SETTING_VA, 4))[0],
            "dispatch_setting": struct.unpack(
                "<I", self._read_va(pw.DISPATCH_SETTING_VA, 4))[0],
            "init": struct.unpack("<I", self._read_va(pw.SETTING_INIT_VA, 4))[0],
            "profile_calls": self.profile_calls,
            "writes": self.write_calls,
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_sync2(self, harvest_setting=0, plant_setting=0, init=1,
                  harvest_hwnd=0, plant_hwnd=0, is_window=1,
                  harvest_check=0, plant_check=0, harvest_profile=0,
                  plant_profile=0):
        self._write_va(pw.HARVEST_SETTING_VA, p32(harvest_setting))
        self._write_va(pw.PLANT_SETTING_VA, p32(plant_setting))
        self._write_va(pw.EXT_INIT_VA, p32(init))
        self._write_va(pw.HARVEST_HWND_VA, p32(harvest_hwnd))
        self._write_va(pw.PLANT_HWND_VA, p32(plant_hwnd))
        self.is_window = is_window
        self.harvest_check_hwnd = harvest_hwnd
        self.plant_check_hwnd = plant_hwnd
        self.harvest_check_value = harvest_check
        self.plant_check_value = plant_check
        self.profile_harvest = harvest_profile
        self.profile_plant = plant_profile
        self.profile_calls = []
        self.write_calls = []

        esp = STACK + 0x800
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.SYNC2_VA))
        self.uc.emu_start(rt(pw.SYNC2_VA), SENTINEL, count=1000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "harvest_setting": struct.unpack(
                "<I", self._read_va(pw.HARVEST_SETTING_VA, 4))[0],
            "plant_setting": struct.unpack(
                "<I", self._read_va(pw.PLANT_SETTING_VA, 4))[0],
            "init": struct.unpack("<I", self._read_va(pw.EXT_INIT_VA, 4))[0],
            "profile_calls": self.profile_calls,
            "writes": self.write_calls,
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def set_farm(self, pits=(), harvest_setting=0, plant_setting=0,
                 farm_ptr=FARM, delay=0, harvest_success=True,
                 plant_success=True):
        self._write_va(pw.HARVEST_SETTING_VA, p32(harvest_setting))
        self._write_va(pw.PLANT_SETTING_VA, p32(plant_setting))
        self._write_va(pw.FARM_DELAY_VA, p32(delay))
        self.farm_ptr = farm_ptr
        self.harvest_success = harvest_success
        self.plant_success = plant_success
        self.harvest_calls = []
        self.harvest_ids = []
        self.plant_calls = []
        self.uc.mem_write(FARM + 0x1894, b"\x00" * (9 * 0x28))
        for index, (plant_id, state) in enumerate(pits):
            pit = FARM + 0x1894 + index * 0x28
            if plant_id:
                definition = FARM_DEFS + index * 0x100
                self.uc.mem_write(definition, p32(plant_id))
                self.uc.mem_write(pit, p32(definition))
            self.uc.mem_write(pit + 4, p32(state))
        self.uc.mem_write(GAME + 0x9C0, p32(farm_ptr))

    def run_farm(self, pits=(), harvest_setting=1, plant_setting=1,
                 farm_ptr=FARM, delay=0, harvest_success=True,
                 plant_success=True):
        self.set_farm(pits, harvest_setting, plant_setting, farm_ptr, delay,
                      harvest_success, plant_success)
        esp = STACK + 0xA00
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, 0x13572468)
        self.uc.reg_write(UC_X86_REG_EBX, 0x24681357)
        self.uc.reg_write(UC_X86_REG_ECX, farm_ptr)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.FARM_VA))
        self.uc.emu_start(rt(pw.FARM_VA), SENTINEL, count=5000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "harvests": self.harvest_calls,
            "harvest_ids": self.harvest_ids,
            "plants": self.plant_calls,
            "delay": struct.unpack(
                "<I", self._read_va(pw.FARM_DELAY_VA, 4))[0],
            "ebp": self.uc.reg_read(UC_X86_REG_EBP),
            "ebx": self.uc.reg_read(UC_X86_REG_EBX),
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_farm_tick(self, pits=(), harvest_setting=1, plant_setting=1,
                      delay=0, harvest_success=True, plant_success=True):
        self.set_farm(pits, harvest_setting, plant_setting, FARM, delay,
                      harvest_success, plant_success)
        esp = STACK + 0xA00
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.mem_write(rt(pw.FARM_TICK_VA + 7), b"\xC3")
        self.uc.mem_write(FRAME - 4, p32(FARM))
        self.uc.mem_write(FRAME - 0x1C, p32(0xFFFFFFFF))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EBP, FRAME)
        self.uc.reg_write(UC_X86_REG_ECX, 0)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.FARM_TICK_VA))
        self.uc.emu_start(rt(pw.FARM_TICK_VA), SENTINEL, count=5000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "harvests": self.harvest_calls,
            "plants": self.plant_calls,
            "local": struct.unpack("<I", self.uc.mem_read(FRAME - 0x1C, 4))[0],
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_manual_harvest(self, pits=(), plant_setting=1,
                           harvest_success=True, plant_success=True):
        self.set_farm(pits, 1, plant_setting, FARM, 0, harvest_success,
                      plant_success)
        if not pits:
            raise ValueError("manual harvest needs a plot")
        pit = FARM + 0x1894
        esp = STACK + 0xB00
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.mem_write(esp + 4, p32(0x11111111))
        self.uc.mem_write(esp + 8, p32(0x22222222))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_ECX, pit)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.MANUAL_HARVEST_VA))
        self.uc.emu_start(rt(pw.MANUAL_HARVEST_VA), SENTINEL, count=2000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "harvests": self.harvest_calls,
            "harvest_ids": self.harvest_ids,
            "plants": self.plant_calls,
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_auto(self, setting=1, obj_ptr=OBJECT, active=1, state=1,
                 timer=0.0, state_padding=0, room_full=False,
                 game_ptr=GAME, capacity=0x20, room_size=0,
                 harvest_setting=0, plant_setting=0, farm_pits=(),
                 harvest_success=True):
        self._write_va(pw.SETTING_VA, p32(setting))
        self.sync_setting = setting
        self.intercept_sync = True
        self.set_object(active, state, timer, state_padding)
        self.can_collect = bool(active and state == 1 and timer <= 0.0)
        self.game_ptr = game_ptr
        self.container_size = capacity if room_full else room_size
        self.set_farm(farm_pits, harvest_setting, plant_setting,
                      FARM if game_ptr else 0, 0, harvest_success)
        if game_ptr:
            self.uc.mem_write(game_ptr + 0x75C, p32(capacity))
        self.collect_count = 0
        self.can_collect_count = 0
        self.size_count = 0
        self.size_ecx = None
        self.collect_ecx = None
        self.collect_eax = None

        ebp = FRAME
        esp = FRAME - 0x80
        self.uc.mem_write(ebp, p32(0x11111111))
        self.uc.mem_write(ebp + 4, p32(SENTINEL))
        self.uc.mem_write(ebp - 4, p32(obj_ptr))
        self.uc.reg_write(UC_X86_REG_EBP, ebp)
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.AUTO_VA))
        self.uc.emu_start(rt(pw.AUTO_VA), SENTINEL, count=1000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "collects": self.collect_count,
            "can_collect_checks": self.can_collect_count,
            "size_checks": self.size_count,
            "size_ecx": self.size_ecx,
            "collect_ecx": self.collect_ecx,
            "ebp": self.uc.reg_read(UC_X86_REG_EBP),
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_dungeon_retry(self, mode=1, target=0x12345678,
                          target_def=OBJECT + 0x200, auto=1,
                          battle_slot=0xDEADBEEF, state=2, timer=0):
        uc = self.uc
        uc.mem_write(OBJECT, b"\x00" * 0x600)
        uc.mem_write(OBJECT + 0x48, p32(battle_slot))
        uc.mem_write(OBJECT + 0x4C, p32(mode))
        uc.mem_write(OBJECT + 0x56C, p32(target))
        uc.mem_write(OBJECT + 0x570, p32(target_def))
        uc.mem_write(OBJECT + 0x596, bytes([auto]))
        uc.mem_write(OBJECT + 0x5A0, p32(state))
        uc.mem_write(OBJECT + 0x5B8, p32(timer))

        ebp = FRAME
        esp = FRAME - 0x80
        uc.mem_write(esp, p32(SENTINEL))
        uc.mem_write(ebp - 4, p32(OBJECT))
        uc.reg_write(UC_X86_REG_EBP, ebp)
        uc.reg_write(UC_X86_REG_ESP, esp)
        uc.reg_write(UC_X86_REG_EIP, rt(pw.DUNGEON_RETRY_VA))
        uc.emu_start(rt(pw.DUNGEON_RETRY_VA),
                     rt(pw.DUNGEON_RETRY_RETURN_VA), count=1000)
        return {
            "slot": struct.unpack("<I", bytes(uc.mem_read(OBJECT + 0x48, 4)))[0],
            "state": struct.unpack("<I", bytes(uc.mem_read(OBJECT + 0x5A0, 4)))[0],
            "timer": struct.unpack("<I", bytes(uc.mem_read(OBJECT + 0x5B8, 4)))[0],
            "returned_to": uc.reg_read(UC_X86_REG_EIP),
            "ebp": uc.reg_read(UC_X86_REG_EBP),
            "esp": uc.reg_read(UC_X86_REG_ESP),
        }

    def set_items(self, items):
        self.selected_items = list(items)
        self.item_types = {}
        for index, (item, count, item_type) in enumerate(self.selected_items):
            slot = SLOTS + index * 8
            self.uc.mem_write(slot, p32(item))
            self.uc.mem_write(slot + 4, p32(count))
            self.item_types[item] = item_type

    def run_dispatch(self, setting=1, last_pet=0, active=0, pet_invalid=0,
                     items=(), available=1, game_ptr=GAME):
        self._write_va(pw.DISPATCH_SETTING_VA, p32(setting))
        self.game_ptr = game_ptr
        self.uc.mem_write(OBJECT, p32(active))
        self.uc.mem_write(OBJECT + 0x58, p32(0))
        self.pet_invalid = pet_invalid
        self.items_available = available
        self.set_items(items)
        self.dispatch_calls = []
        self.pet_valid_calls = []
        self.selected_queries = []
        self.item_type_calls = []
        self.item_available_calls = []

        esp = STACK + 0x800
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_ECX, OBJECT)
        self.uc.reg_write(UC_X86_REG_EDX, last_pet)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.ADISPATCH_VA))
        self.uc.emu_start(rt(pw.ADISPATCH_VA), SENTINEL, count=2000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "dispatch": self.dispatch_calls,
            "pet_valid": self.pet_valid_calls,
            "queries": self.selected_queries,
            "type_calls": self.item_type_calls,
            "available": self.item_available_calls,
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_after_collect(self, dispatch_setting=1, last_pet=0x220100,
                          active=0, pet_invalid=0, items=(), available=1):
        self._write_va(pw.DISPATCH_SETTING_VA, p32(dispatch_setting))
        self.game_ptr = GAME
        self.uc.mem_write(OBJECT, p32(active))
        self.uc.mem_write(OBJECT + 0x58, p32(last_pet))
        self.pet_invalid = pet_invalid
        self.items_available = available
        self.set_items(items)
        self.dispatch_calls = []
        self.pet_valid_calls = []
        self.selected_queries = []
        self.item_type_calls = []
        self.item_available_calls = []
        self.reset_calls = 0
        self.events = []

        esp = STACK + 0x800
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_ECX, OBJECT)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.AFTER_VA))
        self.uc.emu_start(rt(pw.AFTER_VA), SENTINEL, count=2000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "dispatch": self.dispatch_calls,
            "reset": self.reset_calls,
            "events": self.events,
            "pet_valid": self.pet_valid_calls,
            "queries": self.selected_queries,
            "available": self.item_available_calls,
            "last_pet_after": struct.unpack(
                "<I", self.uc.mem_read(OBJECT + 0x58, 4))[0],
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_ui(self, setting=1, dispatch_setting=0, harvest_setting=0,
               plant_setting=0):
        self._write_va(pw.SETTING_VA, p32(setting))
        self._write_va(pw.DISPATCH_SETTING_VA, p32(dispatch_setting))
        self._write_va(pw.HARVEST_SETTING_VA, p32(harvest_setting))
        self._write_va(pw.PLANT_SETTING_VA, p32(plant_setting))
        self._write_va(pw.SETTING_INIT_VA, p32(1))
        self._write_va(pw.EXT_INIT_VA, p32(1))
        self._write_va(pw.SETTING_HWND_VA, p32(0))
        self._write_va(pw.DISPATCH_HWND_VA, p32(0))
        self._write_va(pw.HARVEST_HWND_VA, p32(0))
        self._write_va(pw.PLANT_HWND_VA, p32(0))
        self.uc.mem_write(OBJECT + 0x20, p32(self.parent_hwnd))
        self.sync_setting = setting
        self.intercept_sync = True
        self.create_calls = []
        self.send_calls = []
        self.setwndlong_calls = []

        ebp = FRAME
        self.uc.mem_write(FRAME - 4, p32(OBJECT))
        self.uc.mem_write(FRAME, p32(0x11111111))
        self.uc.mem_write(FRAME + 4, p32(SENTINEL))
        self.uc.reg_write(UC_X86_REG_EBP, ebp)
        self.uc.reg_write(UC_X86_REG_ESP, FRAME - 0x80)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.HOOK_SETTINGS_INIT_VA))
        self.uc.emu_start(rt(pw.HOOK_SETTINGS_INIT_VA), SENTINEL, count=2000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "eax": self.uc.reg_read(UC_X86_REG_EAX),
            "hwnd": struct.unpack("<I", self._read_va(pw.SETTING_HWND_VA, 4))[0],
            "dispatch_hwnd": struct.unpack(
                "<I", self._read_va(pw.DISPATCH_HWND_VA, 4))[0],
            "harvest_hwnd": struct.unpack(
                "<I", self._read_va(pw.HARVEST_HWND_VA, 4))[0],
            "plant_hwnd": struct.unpack(
                "<I", self._read_va(pw.PLANT_HWND_VA, 4))[0],
            "dispatch_setting": struct.unpack(
                "<I", self._read_va(pw.DISPATCH_SETTING_VA, 4))[0],
            "harvest_setting": struct.unpack(
                "<I", self._read_va(pw.HARVEST_SETTING_VA, 4))[0],
            "plant_setting": struct.unpack(
                "<I", self._read_va(pw.PLANT_SETTING_VA, 4))[0],
            "creates": self.create_calls,
            "sends": self.send_calls,
            "setwndlong": self.setwndlong_calls,
            "oldproc": struct.unpack("<I", self._read_va(pw.SETTING_OLDPROC_VA, 4))[0],
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }

    def run_wndproc(self, msg, wparam, lparam=0, oldproc=0x33445566):
        self._write_va(pw.SETTING_OLDPROC_VA, p32(oldproc))
        self.intercept_sync = True
        self.sync_setting = 1
        self.sync_calls = 0
        self.callwndproc_calls = []

        esp = STACK + 0x900
        self.uc.mem_write(esp, p32(SENTINEL))
        self.uc.mem_write(esp + 4, p32(self.parent_hwnd))
        self.uc.mem_write(esp + 8, p32(msg))
        self.uc.mem_write(esp + 12, p32(wparam))
        self.uc.mem_write(esp + 16, p32(lparam))
        self.uc.reg_write(UC_X86_REG_ESP, esp)
        self.uc.reg_write(UC_X86_REG_EIP, rt(pw.WNDPROC_VA))
        self.uc.emu_start(rt(pw.WNDPROC_VA), SENTINEL, count=1000)
        assert self.uc.reg_read(UC_X86_REG_EIP) == SENTINEL
        return {
            "eax": self.uc.reg_read(UC_X86_REG_EAX),
            "sync_calls": self.sync_calls,
            "callwndproc": self.callwndproc_calls,
            "esp": self.uc.reg_read(UC_X86_REG_ESP),
        }


def test_sync_does_not_load_profile_state():
    h = Harness()
    r = h.run_sync(setting=0, dispatch_setting=0, init=0, hwnd=0,
                   profile=1, dispatch_profile=1)
    assert r["eax"] == 0 and r["setting"] == 0, r
    assert r["dispatch_setting"] == 0, r
    assert r["profile_calls"] == [], r
    assert r["writes"] == [], r


def test_sync_dispatch_checkbox_is_session_only():
    h = Harness()
    r = h.run_sync(setting=0, dispatch_setting=0, dispatch_hwnd=0x5678,
                   dispatch_check=1, profile=1, dispatch_profile=0)
    assert r["setting"] == 0 and r["dispatch_setting"] == 1, r
    assert r["profile_calls"] == [], r
    assert r["writes"] == [], r


def test_sync_updates_checkbox_off_without_config_write():
    h = Harness()
    r = h.run_sync(setting=1, init=1, hwnd=0x1234, is_window=1, check=0)
    assert r["eax"] == 0 and r["setting"] == 0, r
    assert r["profile_calls"] == [] and r["writes"] == [], r


def test_sync_updates_checkbox_on_without_config_write():
    h = Harness()
    r = h.run_sync(setting=0, init=1, hwnd=0x1234, is_window=1, check=1)
    assert r["eax"] == 1 and r["setting"] == 1, r
    assert r["profile_calls"] == [] and r["writes"] == [], r


def test_sync_updates_dispatch_checkbox_off_without_config_write():
    h = Harness()
    r = h.run_sync(dispatch_setting=1, init=1, dispatch_hwnd=0x5678,
                   is_window=1, dispatch_check=0)
    assert r["dispatch_setting"] == 0, r
    assert r["profile_calls"] == [] and r["writes"] == [], r


def test_sync_updates_dispatch_checkbox_on_without_config_write():
    h = Harness()
    r = h.run_sync(dispatch_setting=0, init=1, dispatch_hwnd=0x5678,
                   is_window=1, dispatch_check=1)
    assert r["dispatch_setting"] == 1, r
    assert r["profile_calls"] == [] and r["writes"] == [], r


def test_sync_ignores_destroyed_checkbox():
    h = Harness()
    r = h.run_sync(setting=1, init=1, hwnd=0x1234, is_window=0, check=0)
    assert r["eax"] == 1 and r["setting"] == 1, r
    assert r["writes"] == [], r


def test_sync2_does_not_load_profile_state():
    h = Harness()
    r = h.run_sync2(harvest_setting=0, plant_setting=0, init=0,
                    harvest_profile=1, plant_profile=0)
    assert r["harvest_setting"] == 0 and r["plant_setting"] == 0, r
    assert r["profile_calls"] == [], r
    assert r["writes"] == [], r


def test_sync2_updates_harvest_checkbox_without_config_write():
    h = Harness()
    r = h.run_sync2(harvest_setting=0, init=1, harvest_hwnd=0x6789,
                    harvest_check=1)
    assert r["harvest_setting"] == 1, r
    assert r["profile_calls"] == [] and r["writes"] == [], r


def test_sync2_updates_plant_checkbox_without_config_write():
    h = Harness()
    r = h.run_sync2(plant_setting=1, init=1, plant_hwnd=0x789A,
                    plant_check=0)
    assert r["plant_setting"] == 0, r
    assert r["profile_calls"] == [] and r["writes"] == [], r


def test_sync2_ignores_destroyed_checkboxes():
    h = Harness()
    r = h.run_sync2(harvest_setting=1, plant_setting=1, init=1,
                    harvest_hwnd=0x6789, plant_hwnd=0x789A,
                    is_window=0, harvest_check=0, plant_check=0)
    assert r["harvest_setting"] == 1 and r["plant_setting"] == 1, r
    assert r["writes"] == [], r


def test_auto_collects_without_prior_manual_collect():
    h = Harness()
    r = h.run_auto(setting=1)
    assert r["collects"] == 1 and h.collect_ecx == OBJECT, r
    assert r["can_collect_checks"] == 1, r


def test_auto_respects_disabled_setting():
    h = Harness()
    r = h.run_auto(setting=0)
    assert r["collects"] == 0 and r["size_checks"] == 0, r
    assert r["can_collect_checks"] == 0, r


def test_auto_skips_inactive_object():
    h = Harness()
    r = h.run_auto(setting=1, active=0, state=1, timer=0,
                   state_padding=0xFF)
    assert r["collects"] == 0 and r["size_checks"] == 0, r


def test_auto_skips_in_progress():
    h = Harness()
    r = h.run_auto(setting=1, active=1, state=0, timer=0)
    assert r["collects"] == 0 and r["size_checks"] == 0, r


def test_auto_skips_not_finished():
    h = Harness()
    r = h.run_auto(setting=1, active=1, state=1, timer=12.5)
    assert r["collects"] == 0 and r["size_checks"] == 0, r


def test_auto_skips_without_game_object():
    h = Harness()
    r = h.run_auto(setting=1, active=5, state=1, timer=0, game_ptr=0)
    assert r["collects"] == 0 and r["size_checks"] == 0, r


def test_auto_skips_full_pet_room():
    h = Harness()
    r = h.run_auto(setting=1, active=7, state=1, timer=0,
                   room_full=True)
    assert r["collects"] == 0, r
    assert r["size_checks"] == 1 and r["size_ecx"] == GAME + 0x7CC, r


def test_auto_collects_finished_pet():
    h = Harness()
    r = h.run_auto(setting=1, active=9, state=1, timer=0)
    assert r["collects"] == 1, r
    assert r["size_checks"] == 1 and r["size_ecx"] == GAME + 0x7CC, r
    assert r["collect_ecx"] == OBJECT, r
    assert r["ebp"] == 0x11111111 and r["esp"] == FRAME + 8, r


def test_farm_tick_hook_uses_current_farm_object():
    h = Harness()
    r = h.run_farm_tick(pits=[(0x16379, 3)])
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["plants"] == [(FARM + 0x1894, 0x16379)], r
    assert r["local"] == 0, r
    assert r["esp"] == STACK + 0xA04, r


def test_farm_off_does_nothing():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3)], harvest_setting=0,
                   plant_setting=1)
    assert r["harvests"] == [] and r["plants"] == [], r


def test_farm_harvests_mature_plot_without_planting():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3)], harvest_setting=1,
                   plant_setting=0)
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["harvest_ids"] == [0x16379], r
    assert r["plants"] == [], r
    assert r["esp"] == STACK + 0xA04, r
    assert r["ebp"] == 0x13572468 and r["ebx"] == 0x24681357, r


def test_farm_replants_same_recipe():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3)], harvest_setting=1,
                   plant_setting=1)
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["plants"] == [(FARM + 0x1894, 0x16379)], r


def test_farm_ignores_empty_and_growing_plots():
    h = Harness()
    r = h.run_farm(pits=[(0, 0), (0x16379, 1), (0x1637A, 2), (0, 3)],
                   harvest_setting=1, plant_setting=1)
    assert r["harvests"] == [] and r["plants"] == [], r


def test_farm_harvests_each_mature_plot():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3), (0x1637A, 3)],
                   harvest_setting=1, plant_setting=1)
    assert r["harvests"] == [FARM + 0x1894, FARM + 0x18BC], r
    assert r["harvest_ids"] == [0x16379, 0x1637A], r
    assert r["plants"] == [(FARM + 0x1894, 0x16379),
                           (FARM + 0x18BC, 0x1637A)], r


def test_farm_full_bag_skips_plant_and_sets_cooldown():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3)], harvest_setting=1,
                   plant_setting=1, harvest_success=False)
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["plants"] == [], r
    assert r["delay"] == 90, r


def test_farm_cooldown_skips_harvest_attempts():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3)], harvest_setting=1,
                   plant_setting=1, delay=2)
    assert r["harvests"] == [] and r["plants"] == [], r
    assert r["delay"] == 1, r


def test_farm_ignores_missing_farm_object():
    h = Harness()
    r = h.run_farm(pits=[(0x16379, 3)], harvest_setting=1,
                   plant_setting=1, farm_ptr=0)
    assert r["harvests"] == [] and r["plants"] == [], r


def test_manual_harvest_replants_same_recipe():
    h = Harness()
    r = h.run_manual_harvest(pits=[(0x16379, 3)], plant_setting=1)
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["harvest_ids"] == [0x16379], r
    assert r["plants"] == [(FARM + 0x1894, 0x16379)], r
    assert r["esp"] == STACK + 0xB0C, r


def test_manual_harvest_respects_auto_plant_off():
    h = Harness()
    r = h.run_manual_harvest(pits=[(0x16379, 3)], plant_setting=0)
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["plants"] == [], r


def test_manual_harvest_skips_plant_when_harvest_failed():
    h = Harness()
    r = h.run_manual_harvest(pits=[(0x16379, 3)], plant_setting=1,
                             harvest_success=False)
    assert r["harvests"] == [FARM + 0x1894], r
    assert r["plants"] == [], r


def test_after_collect_dispatches_saved_pet():
    h = Harness()
    assert h.pe.bytes_at(pw.HOOK_COLLECT_DONE_VA, 1) == b"\xE8"
    r = h.run_after_collect(dispatch_setting=1, last_pet=0x220100, active=0)
    assert r["reset"] == 1, r
    assert r["dispatch"] == [(OBJECT, 0x220100, OBJECT + 0x5C)], r
    assert r["events"] == ["reset", "dispatch"], r
    assert r["last_pet_after"] == 0, r
    assert r["esp"] == STACK + 0x804, r


def test_after_collect_respects_dispatch_off():
    h = Harness()
    r = h.run_after_collect(dispatch_setting=0, last_pet=0x220100)
    assert r["reset"] == 1, r
    assert r["dispatch"] == [] and r["pet_valid"] == [], r
    assert r["queries"] == [], r


def test_after_collect_skips_without_last_pet():
    h = Harness()
    r = h.run_after_collect(dispatch_setting=1, last_pet=0)
    assert r["reset"] == 1, r
    assert r["dispatch"] == [] and r["pet_valid"] == [], r


def test_after_collect_short_items_dispatch_without_items():
    h = Harness()
    items = [(ITEMS, 3, 1), (ITEMS + 0x10, 1, 1)]
    r = h.run_after_collect(dispatch_setting=1, last_pet=0x220100,
                            items=items, available=0)
    assert r["events"] == ["reset", "items", "dispatch"], r
    assert r["dispatch"] == [(OBJECT, 0x220100, 0)], r
    assert r["available"] == [(INVENTORY, ITEMS, 3)], r


def test_after_collect_carries_items_when_available():
    h = Harness()
    items = [(ITEMS, 3, 1), (ITEMS + 0x10, 1, 1)]
    r = h.run_after_collect(dispatch_setting=1, last_pet=0x220100,
                            items=items, available=1)
    assert r["events"] == ["reset", "items", "items", "dispatch"], r
    assert r["dispatch"] == [(OBJECT, 0x220100, OBJECT + 0x5C)], r
    assert r["available"] == [
        (INVENTORY, ITEMS, 3),
        (INVENTORY, ITEMS + 0x10, 1)], r
    assert r["queries"] == [0, 1, 2, 3, 4], r


def test_dispatch_off_skips_pet_and_items():
    h = Harness()
    r = h.run_dispatch(setting=0, last_pet=0x220100,
                       items=[(ITEMS, 1, 1)])
    assert r["dispatch"] == [] and r["pet_valid"] == [], r
    assert r["queries"] == [], r


def test_dispatch_skips_while_pet_is_active():
    h = Harness()
    r = h.run_dispatch(setting=1, last_pet=0x220100, active=1)
    assert r["dispatch"] == [] and r["pet_valid"] == [], r


def test_dispatch_skips_invalid_last_pet():
    h = Harness()
    r = h.run_dispatch(setting=1, last_pet=0x220100, pet_invalid=1)
    assert r["dispatch"] == [], r
    assert r["pet_valid"] == [0x220100 + 0x694], r


def test_dispatch_skips_without_game_object():
    h = Harness()
    r = h.run_dispatch(setting=1, last_pet=0x220100, game_ptr=0)
    assert r["dispatch"] == [], r
    assert r["pet_valid"] == [0x220100 + 0x694], r


def test_dispatch_ignores_non_stackable_item_quantity():
    h = Harness()
    r = h.run_dispatch(setting=1, last_pet=0x220100,
                       items=[(ITEMS, 1, 2)], available=0)
    assert r["available"] == [], r
    assert r["dispatch"] == [(OBJECT, 0x220100, OBJECT + 0x5C)], r


def test_dispatch_items_survive_switching_wild_slots():
    pe = PE(PATCHED)
    assert pe.bytes_at(pw.HOOK_SWITCH_CLEAR_ITEMS_VA, 5) == b"\x90" * 5


def test_auto_treats_negative_timer_as_finished():
    h = Harness()
    r = h.run_auto(setting=1, active=11, state=1, timer=-3.0)
    assert r["collects"] == 1, r


def test_auto_ignores_state_padding_bytes():
    h = Harness()
    r = h.run_auto(setting=1, active=3, state=1, timer=0,
                   state_padding=0x7E)
    assert r["collects"] == 1, r


def test_dungeon_failure_retries_when_auto_challenge_enabled():
    h = Harness()
    r = h.run_dungeon_retry(auto=1)
    assert r["slot"] == 0xDEADBEEF, r
    assert r["state"] == 4 and r["timer"] == 5, r
    assert r["returned_to"] == rt(pw.DUNGEON_RETRY_RETURN_VA), r
    assert r["ebp"] == FRAME and r["esp"] == FRAME - 0x80, r


def test_dungeon_failure_retry_ignores_battle_mode():
    h = Harness()
    for mode in (0, 1, 2, 10):
        r = h.run_dungeon_retry(mode=mode, auto=1)
        assert r["slot"] == 0xDEADBEEF, (mode, r)
        assert r["state"] == 4 and r["timer"] == 5, (mode, r)
        assert r["returned_to"] == rt(pw.DUNGEON_RETRY_RETURN_VA), (mode, r)


def test_dungeon_failure_without_auto_challenge_preserves_state():
    h = Harness()
    r = h.run_dungeon_retry(auto=0, state=4, timer=7)
    assert r["slot"] == 0xDEADBEEF, r
    assert r["state"] == 4 and r["timer"] == 7, r
    assert r["returned_to"] == rt(pw.DUNGEON_RETRY_RETURN_VA), r


def test_dungeon_failure_retry_requires_target_id():
    h = Harness()
    r = h.run_dungeon_retry(target=0, state=3, timer=9)
    assert r["slot"] == 0xDEADBEEF, r
    assert r["state"] == 3 and r["timer"] == 9, r
    assert r["returned_to"] == rt(pw.DUNGEON_RETRY_RETURN_VA), r


def test_dungeon_failure_retry_uses_target_id_after_scene_cleanup():
    h = Harness()
    r = h.run_dungeon_retry(target_def=0)
    assert r["slot"] == 0xDEADBEEF, r
    assert r["state"] == 4 and r["timer"] == 5, r
    assert r["returned_to"] == rt(pw.DUNGEON_RETRY_RETURN_VA), r


def test_settings_dialog_layout_is_compacted():
    pe = PE(PATCHED)
    data = pe.raw[pw.SETTINGS_DIALOG_OFF:
                  pw.SETTINGS_DIALOG_OFF + pw.SETTINGS_DIALOG_SIZE]
    parsed = pw.parse_dialog(data)
    assert parsed["end"] == len(data), parsed
    assert parsed["client"] == (125, 309), parsed
    assert len(parsed["controls"]) == 41, parsed
    for index, (y, height) in pw.SETTINGS_DIALOG_LAYOUT.items():
        control = parsed["controls"][index]
        assert (control["y"], control["height"]) == (y, height), (index, control)
    bottom = max(c["y"] + c["height"] for c in parsed["controls"])
    assert bottom == 255, bottom
    assert pw.AUTO_COLLECT_RECT[1] - bottom == 4, pw.AUTO_COLLECT_RECT
    assert pw.AUTO_DISPATCH_RECT[1] == pw.AUTO_COLLECT_RECT[1], \
        pw.AUTO_DISPATCH_RECT
    assert pw.AUTO_HARVEST_RECT[1] == pw.AUTO_PLANT_RECT[1], \
        pw.AUTO_HARVEST_RECT
    assert pw.AUTO_HARVEST_RECT[1] == pw.AUTO_COLLECT_RECT[1] + 11, \
        pw.AUTO_HARVEST_RECT
    assert (pw.AUTO_COLLECT_RECT[0] == pw.AUTO_HARVEST_RECT[0] and
            pw.AUTO_DISPATCH_RECT[0] == pw.AUTO_PLANT_RECT[0]), \
        (pw.AUTO_COLLECT_RECT, pw.AUTO_HARVEST_RECT)
    lowest = max(rect[1] + rect[3] for rect in (
        pw.AUTO_COLLECT_RECT, pw.AUTO_DISPATCH_RECT,
        pw.AUTO_HARVEST_RECT, pw.AUTO_PLANT_RECT))
    assert 309 - lowest == 30, lowest


def test_ui_creates_checkbox_and_restores_stack():
    h = Harness()
    r = h.run_ui(setting=1, dispatch_setting=0, harvest_setting=0,
                 plant_setting=1)
    assert r["eax"] == 1 and r["esp"] == FRAME + 8, r
    assert r["hwnd"] == h.created_hwnd, r
    assert r["dispatch_hwnd"] == h.dispatch_hwnd, r
    assert r["dispatch_setting"] == 0, r
    assert r["harvest_hwnd"] == h.harvest_hwnd, r
    assert r["plant_hwnd"] == h.plant_hwnd, r
    assert r["harvest_setting"] == 0 and r["plant_setting"] == 1, r
    assert len(r["creates"]) == 4, r

    (exstyle, cls, title, style, x, y, width, height, parent, cid,
     instance, param) = r["creates"][0]
    assert exstyle == 0 and style == 0x50010003, r
    assert h._wstr(cls) == "BUTTON", r
    assert h._wstr(title) == "\u81ea\u52a8\u6536\u53d6", r
    assert (x, y, width, height) == (16, 518, 88, 18), r
    assert parent == h.parent_hwnd and cid == 1100, r
    assert instance == 0x700000 and param == 0, r
    assert (h.created_hwnd, 0xF1, 1, 0) in r["sends"], r
    assert (h.parent_hwnd, 0x31, 0, 0) in r["sends"], r
    assert (h.created_hwnd, 0x30, 0x55667788, 1) in r["sends"], r

    (exstyle, cls, title, style, x, y, width, height, parent, cid,
     instance, param) = r["creates"][1]
    assert exstyle == 0 and style == 0x50010003, r
    assert h._wstr(cls) == "BUTTON", r
    assert h._wstr(title) == "\u81ea\u52a8\u6d3e\u9063", r
    assert (x, y, width, height) == (107, 518, 88, 18), r
    assert parent == h.parent_hwnd and cid == 1101, r
    assert instance == 0x700000 and param == 0, r
    assert (h.dispatch_hwnd, 0xF1, 0, 0) in r["sends"], r
    assert (h.parent_hwnd, 0x31, 0, 0) in r["sends"], r
    assert (h.dispatch_hwnd, 0x30, 0x55667788, 1) in r["sends"], r

    (exstyle, cls, title, style, x, y, width, height, parent, cid,
     instance, param) = r["creates"][2]
    assert exstyle == 0 and style == 0x50010003, r
    assert h._wstr(cls) == "BUTTON", r
    assert h._wstr(title) == "\u81ea\u52a8\u6536\u83b7", r
    assert (x, y, width, height) == (16, 540, 88, 18), r
    assert parent == h.parent_hwnd and cid == 1102, r
    assert instance == 0x700000 and param == 0, r
    assert (h.harvest_hwnd, 0xF1, 0, 0) in r["sends"], r
    assert (h.harvest_hwnd, 0x30, 0x55667788, 1) in r["sends"], r

    (exstyle, cls, title, style, x, y, width, height, parent, cid,
     instance, param) = r["creates"][3]
    assert exstyle == 0 and style == 0x50010003, r
    assert h._wstr(cls) == "BUTTON", r
    assert h._wstr(title) == "\u81ea\u52a8\u79cd\u690d", r
    assert (x, y, width, height) == (107, 540, 88, 18), r
    assert parent == h.parent_hwnd and cid == 1103, r
    assert instance == 0x700000 and param == 0, r
    assert (h.plant_hwnd, 0xF1, 1, 0) in r["sends"], r
    assert (h.plant_hwnd, 0x30, 0x55667788, 1) in r["sends"], r

    assert r["setwndlong"] == [
        (h.parent_hwnd, 0xFFFFFFFC, rt(pw.WNDPROC_VA))], r
    assert r["oldproc"] == h.old_wndproc, r


def test_wndproc_syncs_on_checkbox_command():
    h = Harness()
    r = h.run_wndproc(0x111, 1100)
    assert r["eax"] == h.callwndproc_result, r
    assert r["sync_calls"] == 1, r
    assert r["esp"] == STACK + 0x900 + 0x14, r
    assert r["callwndproc"] == [
        (0x33445566, h.parent_hwnd, 0x111, 1100, 0)], r


def test_wndproc_syncs_on_dispatch_checkbox_command():
    h = Harness()
    r = h.run_wndproc(0x111, 1101)
    assert r["eax"] == h.callwndproc_result, r
    assert r["sync_calls"] == 1, r
    assert r["esp"] == STACK + 0x900 + 0x14, r
    assert r["callwndproc"] == [
        (0x33445566, h.parent_hwnd, 0x111, 1101, 0)], r


def test_wndproc_syncs_on_harvest_checkbox_command():
    h = Harness()
    r = h.run_wndproc(0x111, 1102)
    assert r["eax"] == h.callwndproc_result, r
    assert r["sync_calls"] == 1, r
    assert r["esp"] == STACK + 0x900 + 0x14, r
    assert r["callwndproc"] == [
        (0x33445566, h.parent_hwnd, 0x111, 1102, 0)], r


def test_wndproc_syncs_on_plant_checkbox_command():
    h = Harness()
    r = h.run_wndproc(0x111, 1103)
    assert r["eax"] == h.callwndproc_result, r
    assert r["sync_calls"] == 1, r
    assert r["esp"] == STACK + 0x900 + 0x14, r
    assert r["callwndproc"] == [
        (0x33445566, h.parent_hwnd, 0x111, 1103, 0)], r


def test_wndproc_ignores_other_commands():
    h = Harness()
    r = h.run_wndproc(0x111, 1095)
    assert r["eax"] == h.callwndproc_result, r
    assert r["sync_calls"] == 0, r


def test_wndproc_ignores_non_command_messages():
    h = Harness()
    r = h.run_wndproc(0x0010, 0)  # WM_CLOSE
    assert r["eax"] == h.callwndproc_result, r
    assert r["sync_calls"] == 0, r


if __name__ == "__main__":
    tests = [v for k, v in sorted(globals().items()) if k.startswith("test_")]
    for test in tests:
        test()
        print("PASS", test.__name__)
    print("all %d tests passed" % len(tests))
