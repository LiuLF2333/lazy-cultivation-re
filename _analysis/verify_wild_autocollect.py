# -*- coding: utf-8 -*-
"""Static verification for the 蛮荒 auto-collect/settings patch."""
import struct
import sys

sys.path.insert(0, r"D:\XiuXian\_analysis")
import patch_wild_autocollect as pw
from petool import PE
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_OP_MEM

PATH = sys.argv[1] if len(sys.argv) > 1 else pw.EXE
pe = PE(PATH)


def section(name):
    return next(s for s in pe.sections if s["name"] == name)


def call_target(site, raw):
    assert raw[0] == 0xE8, (hex(site), raw.hex())
    return site + 5 + struct.unpack_from("<i", raw, 1)[0]


def jmp_target(site, raw):
    assert raw[0] == 0xE9, (hex(site), raw.hex())
    return site + 5 + struct.unpack_from("<i", raw, 1)[0]


def assert_pic(data, base, name):
    """Reject absolute data operands in the ASLR-enabled game."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    for ins in md.disasm(data, base):
        for op in ins.operands:
            if op.type == CS_OP_MEM and op.mem.base == 0 and op.mem.index == 0:
                raise AssertionError("%s has absolute operand at 0x%X: %s %s" % (
                    name, ins.address, ins.mnemonic, ins.op_str))


assert section(".text")["vsize"] == pw.TEXT_VSIZE, section(".text")
assert section(".nine")["vsize"] == pw.NINE_VSIZE, section(".nine")
assert section(".wash")["vsize"] == pw.WASH_VSIZE, section(".wash")
assert section(".wash")["rawsize"] == pw.WASH_RAW_SIZE, section(".wash")
assert section(".washd")["vsize"] == pw.WASHD_VSIZE, section(".washd")
wash = section(".wash")
washd = section(".washd")
assert washd["rawptr"] == wash["rawptr"] + pw.WASH_RAW_SIZE, (wash, washd)

tick = pe.bytes_at(pw.HOOK_TICK_VA, 5)
assert jmp_target(pw.HOOK_TICK_VA, tick) == pw.AUTO_VA, tick.hex()

collect_done = pe.bytes_at(pw.HOOK_COLLECT_DONE_VA, 5)
assert call_target(pw.HOOK_COLLECT_DONE_VA, collect_done) == pw.AFTER_VA, collect_done.hex()
assert pe.bytes_at(pw.HOOK_COLLECT_DONE_VA + 5, 4) == bytes.fromhex("8be55dc3")

settings = pe.bytes_at(pw.HOOK_SETTINGS_INIT_VA, 5)
assert call_target(pw.HOOK_SETTINGS_INIT_VA, settings) == pw.UI_VA, settings.hex()
assert pe.bytes_at(pw.HOOK_SETTINGS_INIT_VA + 5, 4) == bytes.fromhex("8be55dc3")

farm_tick = pe.bytes_at(pw.FARM_TICK_VA, 7)
assert jmp_target(pw.FARM_TICK_VA, farm_tick) == pw.FARM_TRAMP_VA, farm_tick.hex()
assert farm_tick[5:] == b"\x90\x90", farm_tick.hex()

for site in (pw.HOOK_HARVEST_QUICK_VA, pw.HOOK_HARVEST_ALL_VA):
    raw = pe.bytes_at(site, 5)
    assert call_target(site, raw) == pw.MANUAL_HARVEST_VA, (hex(site), raw.hex())

dungeon_fail = pe.bytes_at(pw.HOOK_DUNGEON_FAIL_VA, 5)
assert jmp_target(pw.HOOK_DUNGEON_FAIL_VA, dungeon_fail) == \
    pw.DUNGEON_RETRY_VA, dungeon_fail.hex()
assert pe.bytes_at(pw.HOOK_DUNGEON_FAIL_VA + 5, 3) == \
    bytes.fromhex("8b55fc"), dungeon_fail.hex()
assert pe.bytes_at(pw.HOOK_SWITCH_CLEAR_ITEMS_VA, 5) == b"\x90" * 5, \
    "switching wild slots must keep the previous item selection"

assert pe.u32(pw.SETTING_VA) == 0, "auto-collect setting defaults to disabled"
assert pe.u32(pw.DISPATCH_SETTING_VA) == 0, "auto-dispatch setting defaults to disabled"
assert pe.u32(pw.HARVEST_SETTING_VA) == 0, "auto-harvest setting defaults to disabled"
assert pe.u32(pw.PLANT_SETTING_VA) == 0, "auto-plant setting defaults to disabled"
assert pe.u32(pw.SETTING_HWND_VA) == 0, "checkbox HWND starts empty"
assert pe.u32(pw.DISPATCH_HWND_VA) == 0, "dispatch checkbox HWND starts empty"
assert pe.u32(pw.HARVEST_HWND_VA) == 0, "harvest checkbox HWND starts empty"
assert pe.u32(pw.PLANT_HWND_VA) == 0, "plant checkbox HWND starts empty"
assert pe.u32(pw.SETTING_INIT_VA) == 0, "configuration is loaded lazily"
assert pe.u32(pw.EXT_INIT_VA) == 0, "extended configuration is loaded lazily"
assert pe.u32(pw.SETTING_OLDPROC_VA) == 0, "settings WndProc starts unset"
assert pe.u32(pw.FARM_DELAY_VA) == 0, "farm retry cooldown starts clear"

auto = pw.build_auto()
sync = pw.build_sync()
after_collect = pw.build_after_collect()
auto_dispatch = pw.build_adispatch()
sync2 = pw.build_sync2()
ext_ui = pw.build_ext_ui()
checkbox = pw.build_checkbox()
manual_harvest = pw.build_manual_harvest()
farm_epi = pw.build_farm_epi()
farm_tramp = pw.build_farm_tramp()
farm = pw.build_farm()
ui = pw.build_ui()
dispatch_ui = pw.build_dispatch_ui()
wndproc = pw.build_wndproc()
dungeon_retry = pw.build_dungeon_retry()
assert pe.bytes_at(pw.AUTO_VA, len(auto)) == auto
assert pe.bytes_at(pw.SYNC_VA, len(sync)) == sync
assert pe.bytes_at(pw.AFTER_VA, len(after_collect)) == after_collect
assert pe.bytes_at(pw.ADISPATCH_VA, len(auto_dispatch)) == auto_dispatch
assert pe.bytes_at(pw.SYNC2_VA, len(sync2)) == sync2
assert pe.bytes_at(pw.EXT_UI_VA, len(ext_ui)) == ext_ui
assert pe.bytes_at(pw.CHECKBOX_VA, len(checkbox)) == checkbox
assert pe.bytes_at(pw.MANUAL_HARVEST_VA, len(manual_harvest)) == manual_harvest
assert pe.bytes_at(pw.FARM_EPI_VA, len(farm_epi)) == farm_epi
assert pe.bytes_at(pw.FARM_TRAMP_VA, len(farm_tramp)) == farm_tramp
assert pe.bytes_at(pw.FARM_VA, len(farm)) == farm
assert pe.bytes_at(pw.UI_VA, len(ui)) == ui
assert pe.bytes_at(pw.DISPATCH_UI_VA, len(dispatch_ui)) == dispatch_ui
assert pe.bytes_at(pw.WNDPROC_VA, len(wndproc)) == wndproc
assert pe.bytes_at(pw.DUNGEON_RETRY_VA, len(dungeon_retry)) == dungeon_retry
retry_tail = pe.bytes_at(pw.DUNGEON_RETRY_VA + len(dungeon_retry) - 5, 5)
assert jmp_target(pw.DUNGEON_RETRY_VA + len(dungeon_retry) - 5,
                  retry_tail) == pw.DUNGEON_RETRY_RETURN_VA, retry_tail.hex()
assert pe.bytes_at(pw.DUNGEON_RETRY_RETURN_VA, 6) == \
    bytes.fromhex("6a006a006a32"), pe.bytes_at(pw.DUNGEON_RETRY_RETURN_VA, 6).hex()
assert pw.AUTO_VA + len(auto) <= pw.SYNC_VA
assert pw.SYNC_VA + len(sync) <= pw.AFTER_VA
assert pw.AFTER_VA + len(after_collect) <= pw.ADISPATCH_VA
assert pw.ADISPATCH_VA + len(auto_dispatch) <= pw.SYNC2_VA
assert pw.SYNC2_VA + len(sync2) <= pw.EXT_UI_VA
assert pw.EXT_UI_VA + len(ext_ui) <= pw.CHECKBOX_VA
assert pw.CHECKBOX_VA + len(checkbox) <= pw.FARM_EPI_VA
assert pw.CHECKBOX_VA + len(checkbox) <= pw.MANUAL_HARVEST_VA
assert pw.MANUAL_HARVEST_VA + len(manual_harvest) <= pw.FARM_EPI_VA
assert pw.FARM_EPI_VA + len(farm_epi) <= pw.FARM_TRAMP_VA
assert pw.FARM_TRAMP_VA + len(farm_tramp) <= pw.FARM_VA
assert pw.FARM_VA + len(farm) <= pw.WILD_INI_VA
assert pw.WILD_INI_VA + len("wild.ini\x00".encode("utf-16-le")) <= pw.WASH_CAVE_END_VA
assert pw.UI_VA + len(ui) <= pw.DISPATCH_UI_VA
assert pw.DISPATCH_UI_VA + len(dispatch_ui) <= pw.TEXT_CAVE_END_VA
assert pw.WNDPROC_VA + len(wndproc) <= pw.NINE_CAVE_END_VA
assert pw.DUNGEON_RETRY_VA >= pw.WNDPROC_VA + len(wndproc)
assert pw.DUNGEON_RETRY_VA + len(dungeon_retry) <= pw.NINE_CAVE_END_VA

assert_pic(auto, pw.AUTO_VA, "auto")
assert_pic(sync, pw.SYNC_VA, "sync")
assert_pic(after_collect, pw.AFTER_VA, "after-collect")
assert_pic(auto_dispatch, pw.ADISPATCH_VA, "auto-dispatch")
assert_pic(sync2, pw.SYNC2_VA, "extended-sync")
assert_pic(ext_ui, pw.EXT_UI_VA, "extended-ui")
assert_pic(checkbox, pw.CHECKBOX_VA, "checkbox")
assert_pic(manual_harvest, pw.MANUAL_HARVEST_VA, "manual-harvest")
assert_pic(farm_epi, pw.FARM_EPI_VA, "farm-epilogue")
assert_pic(farm_tramp, pw.FARM_TRAMP_VA, "farm-trampoline")
assert_pic(farm, pw.FARM_VA, "farm")
assert_pic(ui, pw.UI_VA, "ui")
assert_pic(dispatch_ui, pw.DISPATCH_UI_VA, "dispatch-ui")
assert_pic(wndproc, pw.WNDPROC_VA, "wndproc")
assert_pic(dungeon_retry, pw.DUNGEON_RETRY_VA, "dungeon-retry")

auto_jmp_site = pw.AUTO_VA + len(auto) - 5
assert jmp_target(auto_jmp_site, auto[-5:]) == pw.FARM_EPI_VA

assert pe.wide(pw.WASHD_CLASS_VA) == "BUTTON"
assert pe.wide(pw.WASHD_TEXT_VA) == "\u81ea\u52a8\u6536\u53d6"
assert pe.wide(pw.WASHD_DISPATCH_TEXT_VA) == "\u81ea\u52a8\u6d3e\u9063"
assert pe.wide(pw.WASHD_HARVEST_TEXT_VA) == "\u81ea\u52a8\u6536\u83b7"
assert pe.wide(pw.WASHD_PLANT_TEXT_VA) == "\u81ea\u52a8\u79cd\u690d"
assert pe.wide(pw.WASHD_APP_VA) == "Wild"
assert pe.wide(pw.WASHD_KEY_VA) == "AutoCollect"
assert pe.wide(pw.WASHD_DISPATCH_KEY_VA) == "AutoDispatch"
assert pe.wide(pw.WASHD_HARVEST_KEY_VA) == "AutoHarvest"
assert pe.wide(pw.WASHD_PLANT_KEY_VA) == "AutoPlant"
assert pe.wide(pw.WASHD_ON_VA) == "1"
assert pe.wide(pw.WASHD_OFF_VA) == "0"
assert pe.wide(pw.WILD_INI_VA) == "wild.ini"

settings_dialog = pe.raw[pw.SETTINGS_DIALOG_OFF:
                         pw.SETTINGS_DIALOG_OFF + pw.SETTINGS_DIALOG_SIZE]
parsed_dialog = pw.parse_dialog(settings_dialog)
assert parsed_dialog["end"] == len(settings_dialog), parsed_dialog
assert parsed_dialog["client"] == (125, 309), parsed_dialog
assert len(parsed_dialog["controls"]) == 41, parsed_dialog
for index, (y, height) in pw.SETTINGS_DIALOG_LAYOUT.items():
    control = parsed_dialog["controls"][index]
    assert (control["y"], control["height"]) == (y, height), (index, control)
existing_bottom = max(
    c["y"] + c["height"] for c in parsed_dialog["controls"])
assert existing_bottom == 255, existing_bottom
assert min(pw.AUTO_COLLECT_RECT[1], pw.AUTO_DISPATCH_RECT[1]) - \
    existing_bottom == 4
assert pw.AUTO_HARVEST_RECT[1] == pw.AUTO_COLLECT_RECT[1] + 11
assert 309 - (pw.AUTO_HARVEST_RECT[1] + pw.AUTO_HARVEST_RECT[3]) == 30

print("verify ok: %s" % PATH)
print("auto   %d bytes @ 0x%08X" % (len(auto), pw.AUTO_VA))
print("sync   %d bytes @ 0x%08X" % (len(sync), pw.SYNC_VA))
print("after  %d bytes @ 0x%08X" % (len(after_collect), pw.AFTER_VA))
print("dispatch %d bytes @ 0x%08X" % (len(auto_dispatch), pw.ADISPATCH_VA))
print("sync2  %d bytes @ 0x%08X" % (len(sync2), pw.SYNC2_VA))
print("ext-ui %d bytes @ 0x%08X" % (len(ext_ui), pw.EXT_UI_VA))
print("checkbox %d bytes @ 0x%08X" % (len(checkbox), pw.CHECKBOX_VA))
print("manual-harvest %d bytes @ 0x%08X" % (len(manual_harvest), pw.MANUAL_HARVEST_VA))
print("farm-epi %d bytes @ 0x%08X" % (len(farm_epi), pw.FARM_EPI_VA))
print("farm-tramp %d bytes @ 0x%08X" % (len(farm_tramp), pw.FARM_TRAMP_VA))
print("farm   %d bytes @ 0x%08X" % (len(farm), pw.FARM_VA))
print("ui     %d bytes @ 0x%08X" % (len(ui), pw.UI_VA))
print("dispatch-ui %d bytes @ 0x%08X" % (len(dispatch_ui), pw.DISPATCH_UI_VA))
print("wndproc %d bytes @ 0x%08X" % (len(wndproc), pw.WNDPROC_VA))
print("dungeon-retry %d bytes @ 0x%08X" % (
    len(dungeon_retry), pw.DUNGEON_RETRY_VA))
print("hooks  tick=%s collect=%s settings=%s farm=%s" % (
    tick.hex(), collect_done.hex(), settings.hex(),
    farm_tick.hex()))
print("state  setting=%d hwnd=0x%08X dispatch=%d dispatch_hwnd=0x%08X init=%d oldproc=0x%08X" % (
    pe.u32(pw.SETTING_VA),
    pe.u32(pw.SETTING_HWND_VA), pe.u32(pw.DISPATCH_SETTING_VA),
    pe.u32(pw.DISPATCH_HWND_VA), pe.u32(pw.SETTING_INIT_VA),
    pe.u32(pw.SETTING_OLDPROC_VA)))
print("new    harvest=%d hwnd=0x%08X plant=%d hwnd=0x%08X init=%d" % (
    pe.u32(pw.HARVEST_SETTING_VA), pe.u32(pw.HARVEST_HWND_VA),
    pe.u32(pw.PLANT_SETTING_VA), pe.u32(pw.PLANT_HWND_VA),
    pe.u32(pw.EXT_INIT_VA)))
print("farm   delay=%d" % pe.u32(pw.FARM_DELAY_VA))
