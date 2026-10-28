# -*- coding: utf-8 -*-
"""Add session-only automation settings for 蛮荒 pets and farming.

Behaviour:
  * The four settings-page checkboxes (AutoCollect, AutoDispatch, AutoHarvest,
    and AutoPlant) start disabled on every launch. Their state is kept only in
    memory and no configuration file is read or written for these options.
  * The AutoCollect checkbox controls pet collection exactly like AutoHarvest
    controls the farm: when enabled, every finished pet is collected by the
    normal updater without any prior manual click.
  * A second checkbox controls auto-dispatch. After a successful collect, the
    pet and items from the most recent dispatch are submitted again. If any
    carried item is no longer available, dispatch proceeds without items.
    Each of the three wild-dispatch slots keeps its own item selection while
    another slot is active, so all three can replay their own previous items.
  * AutoHarvest scans the nine farm plots on every farm update and sends mature
    crops through the game's normal harvest routine. When AutoPlant is on,
    the same planting recipe is submitted again in the cleared plot. If the
    harvest cannot be completed (for example because the inventory is full),
    replanting is skipped and the next attempt waits for a short cooldown.
    The farm hook uses the update function's own farm object rather than the
    global singleton lookup, so it runs independently of pet state.
  * A dungeon battle failure normally leaves the automatic-challenge
    controller in a terminal wait state. When AutoDungeon is enabled, the
    failure branch now enters the same short result phase used by a victory,
    allowing the existing automatic-challenge loop to start the next attempt.

The new UI/sync helpers live in the zero-filled tail of .text, the farm helper
occupies the end of the expanded .wash section, and the settings window
subclass lives in the tail of .nine. Their labels and UTF-16 setting strings
live in the unused tail of .washd.

The four automation options are session-only. They default to off at startup
and deliberately ignore any existing wild.ini values.
"""
import os
import glob
import hashlib
import shutil
import struct
import sys
from datetime import datetime

sys.path.insert(0, r"D:\XiuXian\_analysis")
from petool import PE, IMAGE_BASE
from keystone import Ks, KS_ARCH_X86, KS_MODE_32
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

EXE = r"D:\XiuXian\懒人修仙传.exe"
OUT = r"D:\XiuXian\懒人修仙传.wild.exe"
ORIGINAL_SHA256 = "A84DE8DC435C7765E38A62C89C6ABFEEFF4A1E80D8D04C707407AC52C20556D5"

HOOK_TICK_VA = 0x4A0E70       # mov esp,ebp ; pop ebp ; ret ; int3
HOOK_COLLECT_DONE_VA = 0x49FC5C  # call 0x4A1AC0 on the collect success path
HOOK_SETTINGS_INIT_VA = 0x45E9C7  # mov eax,1 in settings OnInitDialog
FARM_TICK_VA = 0x4C5E63          # mov dword ptr [ebp-0x1c],0 after farm loop
HOOK_HARVEST_QUICK_VA = 0x4C8684  # call harvest on the selected-plot path
HOOK_HARVEST_ALL_VA = 0x4C994C    # call harvest in the harvest-all command
HOOK_DUNGEON_FAIL_VA = 0x48FE4C  # common exit for dungeon result 2 (defeat)
HOOK_SWITCH_CLEAR_ITEMS_VA = 0x49FB67  # clear old slot's items when switching

COLLECT_VA = 0x49FB80
GAME_VA = 0x48E800
CAN_COLLECT_VA = 0x4A1860
CONTAINER_SIZE_VA = 0x40DD50
PET_VALID_VA = 0x432080
SUBMIT_DISPATCH_VA = 0x49F9C0
RESET_WILD_VA = 0x4A1AC0
SELECTED_ITEM_VA = 0x492FE0
ITEM_TYPE_VA = 0x432260
ITEM_AVAILABLE_VA = 0x43AAD0
HARVEST_PLOT_VA = 0x4A4EC0
PLANT_PLOT_VA = 0x4A4260

AUTO_VA = 0x703820
SYNC_VA = 0x7038B0
AFTER_VA = 0x703A00
ADISPATCH_VA = 0x703A20
SYNC2_VA = 0x703AC0
EXT_UI_VA = 0x703C00
CHECKBOX_VA = 0x703D00
MANUAL_HARVEST_VA = 0x703DC0
FARM_EPI_VA = 0x703F00
FARM_TRAMP_VA = 0x703F08
FARM_VA = 0x703F20
DISPATCH_UI_VA = 0x644750

SETTING_VA = 0x70400C
SETTING_HWND_VA = 0x704010
SETTING_INIT_VA = 0x704014
SETTING_OLDPROC_VA = 0x704018
DISPATCH_SETTING_VA = 0x704072
DISPATCH_HWND_VA = 0x704076
HARVEST_SETTING_VA = 0x7040A0
HARVEST_HWND_VA = 0x7040A4
PLANT_SETTING_VA = 0x7040A8
PLANT_HWND_VA = 0x7040AC
EXT_INIT_VA = 0x7040B0
FARM_DELAY_VA = 0x7040F4

WASHD_APP_VA = 0x704044
WASHD_KEY_VA = 0x704050
WASHD_ON_VA = 0x70406A
WASHD_OFF_VA = 0x70406E
WASHD_CLASS_VA = 0x704020
WASHD_TEXT_VA = 0x704030
WASHD_DISPATCH_TEXT_VA = 0x70407A
WASHD_DISPATCH_KEY_VA = 0x704084
WASHD_HARVEST_TEXT_VA = 0x7040B4
WASHD_PLANT_TEXT_VA = 0x7040BE
WASHD_HARVEST_KEY_VA = 0x7040C8
WASHD_PLANT_KEY_VA = 0x7040E0

CONFIG_INI_VA = 0x687188
WILD_INI_VA = 0x703FB0

AUTO_COLLECT_RECT = (10, 259, 55, 9)
AUTO_DISPATCH_RECT = (67, 259, 55, 9)
AUTO_HARVEST_RECT = (10, 270, 55, 9)
AUTO_PLANT_RECT = (67, 270, 55, 9)

SETTINGS_DIALOG_OFF = 0x2C51B0
SETTINGS_DIALOG_SIZE = 1648
SETTINGS_DIALOG_LAYOUT = {
    0: (6, 155),
    1: (34, 9), 2: (34, 9), 3: (34, 9),
    4: (46, 9), 5: (46, 9), 6: (46, 9),
    7: (24, 7),
    8: (65, 9), 9: (65, 9), 10: (65, 9),
    11: (75, 9), 12: (75, 9),
    13: (56, 7),
    14: (85, 9), 15: (85, 9), 16: (85, 9),
    17: (95, 9), 18: (95, 9),
    19: (105, 9), 20: (105, 9),
    21: (115, 9), 22: (115, 9), 23: (115, 9),
    24: (127, 7),
    25: (137, 9), 26: (137, 9), 27: (137, 9),
    28: (172, 9),
    29: (151, 9), 30: (151, 9),
    31: (186, 9), 32: (197, 9), 33: (208, 9), 34: (219, 9),
    35: (238, 9), 36: (238, 9), 37: (238, 9),
    38: (230, 25),
    39: (171, 13), 40: (184, 13),
}


TEXT_CAVE_VA = 0x64462A
TEXT_CAVE_END_VA = 0x644800
UI_VA = 0x64462A
WASH_CAVE_END_VA = 0x704000

NINE_CAVE_VA = 0x701B28
NINE_CAVE_END_VA = 0x701C00
WNDPROC_VA = NINE_CAVE_VA
DUNGEON_RETRY_VA = 0x701B80
DUNGEON_RETRY_RETURN_VA = 0x48FF0B

GET_MODULE_HANDLE_W = 0x6453A4
GET_PRIVATE_PROFILE_INT_W = 0x6453B4
WRITE_PRIVATE_PROFILE_STRING_W = 0x645414
MAP_DIALOG_RECT = 0x645540
CREATE_WINDOW_EX_W = 0x645638
SEND_MESSAGE_W = 0x6456F4
IS_WINDOW = 0x645710
SET_WINDOW_LONG_W = 0x6456F8
CALL_WINDOW_PROC_W = 0x645648

WASH_VSIZE = 0x1000
WASH_RAW_SIZE = 0x1000
WASHD_VSIZE = 0x100
TEXT_VSIZE = 0x243800
NINE_VSIZE = 0x1C00


def asm(src, base):
    ks = Ks(KS_ARCH_X86, KS_MODE_32)
    enc, count = ks.asm(src, base)
    if enc is None:
        raise RuntimeError("assembly failed")
    return bytes(enc)


def build_auto():
    src = """
        pushad
        mov ecx, dword ptr [ebp - 4]
        test ecx, ecx
        jz done

        call 0x%08X
        test eax, eax
        jz done

        mov ecx, dword ptr [ebp - 4]
        call 0x4A1860
        test al, al
        jz done

        call 0x48E800
        test eax, eax
        jz done
        mov ecx, eax
        add ecx, 0x7CC
        push eax
        call 0x40DD50
        pop ecx
        cmp eax, dword ptr [ecx + 0x75C]
        jge done

        mov ecx, dword ptr [ebp - 4]
        call 0x49FB80
    done:
        popad
        jmp 0x%08X
    """ % (SYNC_VA, FARM_EPI_VA)
    return asm(src, AUTO_VA)


def build_farm_epi():
    src = """
        mov esp, ebp
        pop ebp
        ret
    """
    return asm(src, FARM_EPI_VA)


def build_farm():
    src = """
        pushad
        call farm_get_eip
    farm_get_eip:
        pop ebx
        sub ebx, farm_get_eip - 0x%08X

        cmp dword ptr [ebx + 0x%08X], 0
        jz farm_done

        mov eax, dword ptr [ebx + 0x%08X]
        test eax, eax
        jz farm_ready
        sub eax, 1
        mov dword ptr [ebx + 0x%08X], eax
        jnz farm_done

    farm_ready:
        mov esi, ecx
        test esi, esi
        jz farm_done
        xor edi, edi

    farm_loop:
        cmp edi, 9
        jae farm_done
        imul ecx, edi, 0x28
        lea ebp, [esi + ecx + 0x1894]
        cmp dword ptr [ebp], 0
        je farm_next
        cmp dword ptr [ebp + 4], 3
        jne farm_next

        mov eax, dword ptr [ebp]
        mov eax, dword ptr [eax]
        push eax
        push 0
        push 0
        mov ecx, ebp
        call 0x%08X
        pop eax

        cmp dword ptr [ebp + 4], 0
        jne farm_retry
        cmp dword ptr [ebx + 0x%08X], 0
        je farm_next
        push eax
        mov ecx, ebp
        call 0x%08X

    farm_next:
        inc edi
        jmp farm_loop
    farm_retry:
        mov dword ptr [ebx + 0x%08X], 90
    farm_done:
        popad
        ret
    """ % (IMAGE_BASE, HARVEST_SETTING_VA - IMAGE_BASE,
           FARM_DELAY_VA - IMAGE_BASE, FARM_DELAY_VA - IMAGE_BASE,
           HARVEST_PLOT_VA, PLANT_SETTING_VA - IMAGE_BASE,
           PLANT_PLOT_VA, FARM_DELAY_VA - IMAGE_BASE)
    return asm(src, FARM_VA)


def build_farm_tramp():
    src = """
        mov dword ptr [ebp - 0x1C], 0
        mov ecx, dword ptr [ebp - 4]
        call 0x%08X
        jmp 0x%08X
    """ % (FARM_VA, FARM_TICK_VA + 7)
    return asm(src, FARM_TRAMP_VA)


def build_manual_harvest():
    src = """
        enter 8, 0
        pushad
        call mh_get_eip
    mh_get_eip:
        pop ebx
        sub ebx, mh_get_eip - 0x%08X

        mov dword ptr [ebp - 4], ecx
        mov dword ptr [ebp - 8], 0
        mov eax, dword ptr [ecx]
        test eax, eax
        jz mh_call_original
        mov eax, dword ptr [eax]
        mov dword ptr [ebp - 8], eax

    mh_call_original:
        push dword ptr [ebp + 0x0C]
        push dword ptr [ebp + 0x08]
        mov ecx, dword ptr [ebp - 4]
        call 0x%08X

        mov eax, dword ptr [ebp - 8]
        test eax, eax
        jz mh_done
        cmp dword ptr [ebx + 0x%08X], 0
        je mh_done
        mov ecx, dword ptr [ebp - 4]
        cmp dword ptr [ecx + 4], 0
        jne mh_done
        push eax
        call 0x%08X

    mh_done:
        popad
        leave
        ret 8
    """ % (IMAGE_BASE, HARVEST_PLOT_VA, PLANT_SETTING_VA - IMAGE_BASE,
           PLANT_PLOT_VA)
    return asm(src, MANUAL_HARVEST_VA)


def build_after_collect():
    src = """
        push ebx
        push esi
        mov esi, ecx
        mov ebx, dword ptr [esi + 0x58]
        mov ecx, esi
        call 0x4A1AC0
        test ebx, ebx
        jz after_done
        mov ecx, esi
        mov edx, ebx
        call 0x%08X
    after_done:
        pop esi
        pop ebx
        ret
    """ % ADISPATCH_VA
    return asm(src, AFTER_VA)


def build_adispatch():
    src = """
        pushad
        push 0
        mov esi, ecx
        mov edi, edx
        call ad_get_eip
    ad_get_eip:
        pop ebx
        sub ebx, ad_get_eip - 0x400000
        cmp dword ptr [ebx + 0x304072], 0
        jz ad_done

        cmp dword ptr [esi], 0
        jne ad_done
        test edi, edi
        jz ad_done

        mov ecx, edi
        add ecx, 0x694
        call 0x432080
        test al, al
        jnz ad_done

        call 0x48E800
        test eax, eax
        jz ad_done
        mov ebp, eax

    ad_item_loop:
        cmp dword ptr [esp], 5
        jae ad_items_ready
        push dword ptr [esp]
        mov ecx, esi
        add ecx, 0x5c
        call 0x492FE0
        test eax, eax
        jz ad_item_next
        push eax
        mov ecx, dword ptr [eax]
        call 0x432260
        pop edx
        cmp eax, 1
        jne ad_item_next
        push dword ptr [edx + 4]
        push dword ptr [edx]
        mov ecx, dword ptr [ebp + 0x11B8]
        call 0x43AAD0
        test al, al
        jz ad_no_items
    ad_item_next:
        inc dword ptr [esp]
        jmp ad_item_loop

    ad_items_ready:
        lea eax, dword ptr [esi + 0x5C]
        jmp ad_submit
    ad_no_items:
        xor eax, eax
    ad_submit:
        push eax
        push edi
        mov ecx, esi
        call 0x49F9C0
    ad_done:
        add esp, 4
        popad
        ret
    """
    return asm(src, ADISPATCH_VA)


def build_sync():
    src = """
        pushad
        call sync_get_eip
    sync_get_eip:
        pop ebx
        sub ebx, sync_get_eip - 0x%(base)08X

    sync_check_collect:
        mov eax, dword ptr [ebx + 0x%(collect_hwnd)08X]
        test eax, eax
        jz sync_check_dispatch
        push eax
        call dword ptr [ebx + 0x%(is_window)08X]
        test eax, eax
        jz sync_check_dispatch
        push 0
        push 0
        push 0xF0
        push dword ptr [ebx + 0x%(collect_hwnd)08X]
        call dword ptr [ebx + 0x%(send_message)08X]
        and eax, 1
        cmp eax, dword ptr [ebx + 0x%(collect_setting)08X]
        je sync_check_dispatch
        mov dword ptr [ebx + 0x%(collect_setting)08X], eax

    sync_check_dispatch:
        mov eax, dword ptr [ebx + 0x%(dispatch_hwnd)08X]
        test eax, eax
        jz sync_done
        push eax
        call dword ptr [ebx + 0x%(is_window)08X]
        test eax, eax
        jz sync_done
        push 0
        push 0
        push 0xF0
        push dword ptr [ebx + 0x%(dispatch_hwnd)08X]
        call dword ptr [ebx + 0x%(send_message)08X]
        and eax, 1
        cmp eax, dword ptr [ebx + 0x%(dispatch_setting)08X]
        je sync_done
        mov dword ptr [ebx + 0x%(dispatch_setting)08X], eax

    sync_done:
        call 0x%(sync2)08X
        mov eax, dword ptr [ebx + 0x%(collect_setting)08X]
        mov dword ptr [esp + 28], eax
        popad
        ret
    """ % {
        "base": IMAGE_BASE,
        "collect_setting": SETTING_VA - IMAGE_BASE,
        "dispatch_setting": DISPATCH_SETTING_VA - IMAGE_BASE,
        "collect_hwnd": SETTING_HWND_VA - IMAGE_BASE,
        "dispatch_hwnd": DISPATCH_HWND_VA - IMAGE_BASE,
        "is_window": IS_WINDOW - IMAGE_BASE,
        "send_message": SEND_MESSAGE_W - IMAGE_BASE,
        "sync2": SYNC2_VA,
    }
    return asm(src, SYNC_VA)


def build_sync2():
    src = """
        pushad
        call sync2_get_eip
    sync2_get_eip:
        pop ebx
        sub ebx, sync2_get_eip - 0x%(base)08X

    sync2_check_harvest:
        mov eax, dword ptr [ebx + 0x%(harvest_hwnd)08X]
        test eax, eax
        jz sync2_check_plant
        push eax
        call dword ptr [ebx + 0x%(is_window)08X]
        test eax, eax
        jz sync2_check_plant
        push 0
        push 0
        push 0xF0
        push dword ptr [ebx + 0x%(harvest_hwnd)08X]
        call dword ptr [ebx + 0x%(send_message)08X]
        and eax, 1
        cmp eax, dword ptr [ebx + 0x%(harvest_setting)08X]
        je sync2_check_plant
        mov dword ptr [ebx + 0x%(harvest_setting)08X], eax

    sync2_check_plant:
        mov eax, dword ptr [ebx + 0x%(plant_hwnd)08X]
        test eax, eax
        jz sync2_done
        push eax
        call dword ptr [ebx + 0x%(is_window)08X]
        test eax, eax
        jz sync2_done
        push 0
        push 0
        push 0xF0
        push dword ptr [ebx + 0x%(plant_hwnd)08X]
        call dword ptr [ebx + 0x%(send_message)08X]
        and eax, 1
        cmp eax, dword ptr [ebx + 0x%(plant_setting)08X]
        je sync2_done
        mov dword ptr [ebx + 0x%(plant_setting)08X], eax

    sync2_done:
        popad
        ret
    """ % {
        "base": IMAGE_BASE,
        "harvest_setting": HARVEST_SETTING_VA - IMAGE_BASE,
        "plant_setting": PLANT_SETTING_VA - IMAGE_BASE,
        "harvest_hwnd": HARVEST_HWND_VA - IMAGE_BASE,
        "plant_hwnd": PLANT_HWND_VA - IMAGE_BASE,
        "is_window": IS_WINDOW - IMAGE_BASE,
        "send_message": SEND_MESSAGE_W - IMAGE_BASE,
    }
    return asm(src, SYNC2_VA)


def build_ui():
    x, y, width, height = AUTO_COLLECT_RECT
    src = """
        enter 0x1C, 0
        push ebx
        push esi
        push edi
        call ui_get_eip
    ui_get_eip:
        pop ebx
        sub ebx, ui_get_eip - 0x%08X
        mov eax, dword ptr [ebp]
        test eax, eax
        jz ui_fail
        mov ecx, dword ptr [eax - 4]
        test ecx, ecx
        jz ui_fail
        mov eax, dword ptr [ecx + 0x20]
        test eax, eax
        jz ui_fail
        mov dword ptr [ebp - 0x14], eax
        call 0x%08X
        mov esi, eax

        mov dword ptr [ebp - 0x10], %d
        mov dword ptr [ebp - 0x0C], %d
        mov dword ptr [ebp - 0x08], %d
        mov dword ptr [ebp - 0x04], %d
        lea eax, dword ptr [ebp - 0x10]
        push eax
        push dword ptr [ebp - 0x14]
        call dword ptr [ebx + 0x%08X]

        push 0
        call dword ptr [ebx + 0x%08X]
        mov dword ptr [ebp - 0x1C], eax
        push 0
        push eax
        push 1100
        push dword ptr [ebp - 0x14]
        mov ecx, dword ptr [ebp - 0x04]
        sub ecx, dword ptr [ebp - 0x0C]
        push ecx
        mov ecx, dword ptr [ebp - 0x08]
        sub ecx, dword ptr [ebp - 0x10]
        push ecx
        push dword ptr [ebp - 0x0C]
        push dword ptr [ebp - 0x10]
        push 0x50010003
        lea eax, [ebx + 0x%08X]
        push eax
        lea eax, [ebx + 0x%08X]
        push eax
        push 0
        call dword ptr [ebx + 0x%08X]
        mov dword ptr [ebx + 0x%08X], eax
        test eax, eax
        jz ui_fail
        mov edi, eax

        push 0
        push esi
        push 0xF1
        push edi
        call dword ptr [ebx + 0x%08X]

        push 0
        push 0x31
        push dword ptr [ebp - 0x14]
        call dword ptr [ebx + 0x%08X]
        mov dword ptr [ebp - 0x18], eax
        push 1
        push eax
        push 0x30
        push dword ptr [ebx + 0x%08X]
        call dword ptr [ebx + 0x%08X]
        push dword ptr [ebp - 0x18]
        push dword ptr [ebp - 0x1C]
        push dword ptr [ebp - 0x14]
        call 0x%08X

        lea edx, [ebx + 0x%08X]
        push edx
        push -4
        push dword ptr [ebp - 0x14]
        call dword ptr [ebx + 0x%08X]
        mov dword ptr [ebx + 0x%08X], eax
    ui_fail:
        pop edi
        pop esi
        pop ebx
        xor eax, eax
        inc eax
        leave
        ret
    """ % (IMAGE_BASE, SYNC_VA, x, y, x + width, y + height,
            MAP_DIALOG_RECT - IMAGE_BASE,
            GET_MODULE_HANDLE_W - IMAGE_BASE, WASHD_TEXT_VA - IMAGE_BASE,
            WASHD_CLASS_VA - IMAGE_BASE, CREATE_WINDOW_EX_W - IMAGE_BASE,
            SETTING_HWND_VA - IMAGE_BASE,
            SEND_MESSAGE_W - IMAGE_BASE, SEND_MESSAGE_W - IMAGE_BASE,
            SETTING_HWND_VA - IMAGE_BASE, SEND_MESSAGE_W - IMAGE_BASE,
            EXT_UI_VA, WNDPROC_VA - IMAGE_BASE,
            SET_WINDOW_LONG_W - IMAGE_BASE, SETTING_OLDPROC_VA - IMAGE_BASE)
    return asm(src, UI_VA)


def build_dispatch_ui():
    x, y, width, height = AUTO_DISPATCH_RECT
    src = """
        enter 0x18, 0
        push ebx
        push edi
        call dispatch_get_eip
    dispatch_get_eip:
        pop ebx
        sub ebx, dispatch_get_eip - 0x%08X

        mov dword ptr [ebp - 0x10], %d
        mov dword ptr [ebp - 0x0C], %d
        mov dword ptr [ebp - 0x08], %d
        mov dword ptr [ebp - 0x04], %d
        lea eax, dword ptr [ebp - 0x10]
        push eax
        push dword ptr [ebp + 8]
        call dword ptr [ebx + 0x%08X]

        push 0
        push dword ptr [ebp + 0x0C]
        push 1101
        push dword ptr [ebp + 8]
        mov ecx, dword ptr [ebp - 0x04]
        sub ecx, dword ptr [ebp - 0x0C]
        push ecx
        mov ecx, dword ptr [ebp - 0x08]
        sub ecx, dword ptr [ebp - 0x10]
        push ecx
        push dword ptr [ebp - 0x0C]
        push dword ptr [ebp - 0x10]
        push 0x50010003
        lea eax, [ebx + 0x%08X]
        push eax
        lea eax, [ebx + 0x%08X]
        push eax
        push 0
        call dword ptr [ebx + 0x%08X]
        mov dword ptr [ebx + 0x%08X], eax
        test eax, eax
        jz dispatch_fail
        mov edi, eax

        push 0
        push dword ptr [ebx + 0x%08X]
        push 0xF1
        push edi
        call dword ptr [ebx + 0x%08X]

        push 1
        push dword ptr [ebp + 0x10]
        push 0x30
        push edi
        call dword ptr [ebx + 0x%08X]
    dispatch_fail:
        pop edi
        pop ebx
        leave
        ret 12
    """ % (IMAGE_BASE, x, y, x + width, y + height,
            MAP_DIALOG_RECT - IMAGE_BASE,
            WASHD_DISPATCH_TEXT_VA - IMAGE_BASE, WASHD_CLASS_VA - IMAGE_BASE,
            CREATE_WINDOW_EX_W - IMAGE_BASE, DISPATCH_HWND_VA - IMAGE_BASE,
            DISPATCH_SETTING_VA - IMAGE_BASE, SEND_MESSAGE_W - IMAGE_BASE,
            SEND_MESSAGE_W - IMAGE_BASE)
    return asm(src, DISPATCH_UI_VA)


def build_checkbox():
    src = """
        enter 0x10, 0
        push ebx
        push edi
        call cb_get_eip
    cb_get_eip:
        pop ebx
        sub ebx, cb_get_eip - 0x%08X

        mov eax, dword ptr [ebp + 0x1C]
        mov dword ptr [ebp - 0x10], eax
        mov eax, dword ptr [ebp + 0x20]
        mov dword ptr [ebp - 0x0C], eax
        mov eax, dword ptr [ebp + 0x1C]
        add eax, dword ptr [ebp + 0x24]
        mov dword ptr [ebp - 0x08], eax
        mov eax, dword ptr [ebp + 0x20]
        add eax, dword ptr [ebp + 0x28]
        mov dword ptr [ebp - 0x04], eax

        lea eax, [ebp - 0x10]
        push eax
        push dword ptr [ebp + 0x08]
        call dword ptr [ebx + 0x%08X]

        push 0
        push dword ptr [ebp + 0x0C]
        push dword ptr [ebp + 0x18]
        push dword ptr [ebp + 0x08]
        mov ecx, dword ptr [ebp - 0x04]
        sub ecx, dword ptr [ebp - 0x0C]
        push ecx
        mov ecx, dword ptr [ebp - 0x08]
        sub ecx, dword ptr [ebp - 0x10]
        push ecx
        push dword ptr [ebp - 0x0C]
        push dword ptr [ebp - 0x10]
        push 0x50010003
        push dword ptr [ebp + 0x14]
        lea eax, [ebx + 0x%08X]
        push eax
        push 0
        call dword ptr [ebx + 0x%08X]
        test eax, eax
        jz cb_fail
        mov edi, eax
        mov ecx, dword ptr [ebp + 0x30]
        mov dword ptr [ecx], eax

        push 0
        push dword ptr [ebp + 0x2C]
        push 0xF1
        push edi
        call dword ptr [ebx + 0x%08X]

        push 1
        push dword ptr [ebp + 0x10]
        push 0x30
        push edi
        call dword ptr [ebx + 0x%08X]
    cb_fail:
        pop edi
        pop ebx
        leave
        ret 44
    """ % (IMAGE_BASE, MAP_DIALOG_RECT - IMAGE_BASE,
            WASHD_CLASS_VA - IMAGE_BASE, CREATE_WINDOW_EX_W - IMAGE_BASE,
            SEND_MESSAGE_W - IMAGE_BASE, SEND_MESSAGE_W - IMAGE_BASE)
    return asm(src, CHECKBOX_VA)


def build_ext_ui():
    harvest_x, harvest_y, harvest_width, harvest_height = AUTO_HARVEST_RECT
    plant_x, plant_y, plant_width, plant_height = AUTO_PLANT_RECT
    src = """
        enter 0, 0
        push ebx
        call ext_get_eip
    ext_get_eip:
        pop ebx
        sub ebx, ext_get_eip - 0x%08X

        push dword ptr [ebp + 0x10]
        push dword ptr [ebp + 0x0C]
        push dword ptr [ebp + 0x08]
        call 0x%08X

        lea eax, [ebx + 0x%08X]
        push eax
        push dword ptr [ebx + 0x%08X]
        push %d
        push %d
        push %d
        push %d
        push 1102
        lea eax, [ebx + 0x%08X]
        push eax
        push dword ptr [ebp + 0x10]
        push dword ptr [ebp + 0x0C]
        push dword ptr [ebp + 0x08]
        call 0x%08X

        lea eax, [ebx + 0x%08X]
        push eax
        push dword ptr [ebx + 0x%08X]
        push %d
        push %d
        push %d
        push %d
        push 1103
        lea eax, [ebx + 0x%08X]
        push eax
        push dword ptr [ebp + 0x10]
        push dword ptr [ebp + 0x0C]
        push dword ptr [ebp + 0x08]
        call 0x%08X

        pop ebx
        leave
        ret 12
    """ % (IMAGE_BASE, DISPATCH_UI_VA,
            HARVEST_HWND_VA - IMAGE_BASE, HARVEST_SETTING_VA - IMAGE_BASE,
            harvest_height, harvest_width, harvest_y, harvest_x,
            WASHD_HARVEST_TEXT_VA - IMAGE_BASE, CHECKBOX_VA,
            PLANT_HWND_VA - IMAGE_BASE, PLANT_SETTING_VA - IMAGE_BASE,
            plant_height, plant_width, plant_y, plant_x,
            WASHD_PLANT_TEXT_VA - IMAGE_BASE, CHECKBOX_VA)
    return asm(src, EXT_UI_VA)


def build_wndproc():
    src = """
        push ebp
        mov ebp, esp
        push ebx
        call wp_get_eip
    wp_get_eip:
        pop ebx
        sub ebx, wp_get_eip - 0x%08X

        push dword ptr [ebp + 0x14]
        push dword ptr [ebp + 0x10]
        push dword ptr [ebp + 0x0C]
        push dword ptr [ebp + 0x08]
        push dword ptr [ebx + 0x%08X]
        call dword ptr [ebx + 0x%08X]
        push eax

        cmp dword ptr [ebp + 0x0C], 0x111
        jne wp_done
        mov eax, dword ptr [ebp + 0x10]
        and eax, 0xFFFF
        sub eax, 1100
        cmp eax, 3
        ja wp_done
        call 0x%08X
    wp_done:
        pop eax
        pop ebx
        pop ebp
        ret 16
    """ % (IMAGE_BASE, SETTING_OLDPROC_VA - IMAGE_BASE,
            CALL_WINDOW_PROC_W - IMAGE_BASE, SYNC_VA)
    return asm(src, WNDPROC_VA)


def build_dungeon_retry():
    src = """
        pushad
        mov eax, dword ptr [ebp - 4]
        cmp byte ptr [eax + 0x596], 0
        je retry_done
        cmp dword ptr [eax + 0x56C], 0
        je retry_done

        mov dword ptr [eax + 0x5A0], 4
        mov dword ptr [eax + 0x5B8], 5
    retry_done:
        popad
        jmp 0x%08X
    """ % DUNGEON_RETRY_RETURN_VA
    return asm(src, DUNGEON_RETRY_VA)


def section_header_offset(pe, name):
    sec = pe.opt + pe.sizeopt
    for i in range(pe.nsec):
        off = sec + i * 40
        if pe.raw[off:off + 8].rstrip(b"\x00").decode("latin1") == name:
            return off
    raise KeyError(name)


def parse_dialog(data):
    def u16(off):
        return struct.unpack_from("<H", data, off)[0]

    def read_sz(off):
        value = u16(off)
        if value == 0:
            return off + 2, None
        if value == 0xFFFF:
            return off + 4, ("ORD", u16(off + 2))
        chars = []
        while u16(off):
            chars.append(chr(u16(off)))
            off += 2
        return off + 2, "".join(chars)

    version, signature = struct.unpack_from("<HH", data, 0)
    extended = version == 1 and signature == 0xFFFF
    off = 4
    if extended:
        _, _, style, count, _, _, cx, cy = struct.unpack_from(
            "<IIIHhhhh", data, off)
        off += 22
    else:
        style, _, count, _, _, cx, cy = struct.unpack_from(
            "<IIHhhhh", data, off)
        off += 18
    off, _ = read_sz(off)
    off, _ = read_sz(off)
    off, _ = read_sz(off)
    if style & 0x40:
        off += 6 if extended else 2
        off, _ = read_sz(off)

    controls = []
    for index in range(count):
        off = (off + 3) & ~3
        start = off
        if extended:
            _, _, _, x, y, width, height, cid = struct.unpack_from(
                "<IIIhhhhI", data, off)
            off += 24
            y_off = start + 14
            height_off = start + 18
        else:
            _, _, x, y, width, height, cid = struct.unpack_from(
                "<IIhhhhH", data, off)
            off += 18
            y_off = start + 10
            height_off = start + 14
        off, _ = read_sz(off)
        off, _ = read_sz(off)
        extra = u16(off)
        off += 2 + extra
        controls.append({
            "id": cid, "x": x, "y": y, "width": width, "height": height,
            "y_off": y_off, "height_off": height_off,
        })
    return {"client": (cx, cy), "controls": controls, "end": off}


def compact_settings_dialog(data):
    parsed = parse_dialog(data)
    if parsed["end"] != len(data) or len(parsed["controls"]) != 41:
        raise SystemExit("unexpected settings dialog layout")
    if parsed["client"] != (125, 309):
        raise SystemExit("unexpected settings dialog size")
    raw = bytearray(data)
    for index, (y, height) in SETTINGS_DIALOG_LAYOUT.items():
        control = parsed["controls"][index]
        struct.pack_into("<h", raw, control["y_off"], y)
        struct.pack_into("<h", raw, control["height_off"], height)
    return bytes(raw)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def pristine_source():
    candidates = [EXE] + sorted(glob.glob(EXE + ".bak.*"), reverse=True)
    for path in candidates:
        if os.path.isfile(path) and sha256(path) == ORIGINAL_SHA256:
            return path
    raise SystemExit("no pristine original executable found")


def main():
    source = pristine_source()
    pe = PE(source)
    if os.path.exists(OUT):
        os.remove(OUT)

    auto = build_auto()
    sync = build_sync()
    after_collect = build_after_collect()
    auto_dispatch = build_adispatch()
    sync2 = build_sync2()
    ext_ui = build_ext_ui()
    checkbox = build_checkbox()
    manual_harvest = build_manual_harvest()
    farm_epi = build_farm_epi()
    farm_tramp = build_farm_tramp()
    farm = build_farm()
    ui = build_ui()
    dispatch_ui = build_dispatch_ui()
    wndproc = build_wndproc()
    dungeon_retry = build_dungeon_retry()
    tick_orig = pe.bytes_at(HOOK_TICK_VA, 5)
    collect_done_orig = pe.bytes_at(HOOK_COLLECT_DONE_VA, 5)
    settings_orig = pe.bytes_at(HOOK_SETTINGS_INIT_VA, 5)
    farm_tick_orig = pe.bytes_at(FARM_TICK_VA, 7)
    harvest_quick_orig = pe.bytes_at(HOOK_HARVEST_QUICK_VA, 5)
    harvest_all_orig = pe.bytes_at(HOOK_HARVEST_ALL_VA, 5)
    dungeon_fail_orig = pe.bytes_at(HOOK_DUNGEON_FAIL_VA, 5)
    switch_clear_items_orig = pe.bytes_at(HOOK_SWITCH_CLEAR_ITEMS_VA, 5)
    if tick_orig != bytes.fromhex("8be55dc3cc"):
        raise SystemExit("unexpected tick hook bytes: " + tick_orig.hex())
    if collect_done_orig != bytes.fromhex("e85f1e0000"):
        raise SystemExit("unexpected collect hook bytes: " + collect_done_orig.hex())
    if settings_orig != bytes.fromhex("b801000000"):
        raise SystemExit("unexpected settings hook bytes: " + settings_orig.hex())
    if dungeon_fail_orig != bytes.fromhex("e9ba000000"):
        raise SystemExit("unexpected dungeon failure hook bytes: " +
                         dungeon_fail_orig.hex())
    if switch_clear_items_orig != bytes.fromhex("e82436ffff"):
        raise SystemExit("unexpected wild switch item-clear bytes: " +
                         switch_clear_items_orig.hex())
    if farm_tick_orig != bytes.fromhex("c745e400000000"):
        raise SystemExit("unexpected farm tick hook bytes: " + farm_tick_orig.hex())
    for site, raw in ((HOOK_HARVEST_QUICK_VA, harvest_quick_orig),
                      (HOOK_HARVEST_ALL_VA, harvest_all_orig)):
        target = site + 5 + struct.unpack_from("<i", raw, 1)[0]
        if raw[0] != 0xE8 or target != HARVEST_PLOT_VA:
            raise SystemExit("unexpected manual harvest hook at 0x%08X: %s" %
                             (site, raw.hex()))
    if any(pe.bytes_at(AUTO_VA, SYNC_VA - AUTO_VA)):
        raise SystemExit("auto code cave is not empty")
    if any(pe.bytes_at(SYNC_VA, AFTER_VA - SYNC_VA)):
        raise SystemExit("sync code cave is not empty")
    if AUTO_VA + len(auto) > SYNC_VA:
        raise SystemExit("auto routine overlaps sync routine")
    if SYNC_VA + len(sync) > AFTER_VA:
        raise SystemExit("sync routine overlaps the collect trampoline")
    if AFTER_VA + len(after_collect) > ADISPATCH_VA:
        raise SystemExit("collect trampoline overlaps the auto-dispatch routine")
    if ADISPATCH_VA + len(auto_dispatch) > SYNC2_VA:
        raise SystemExit("auto-dispatch routine overlaps the extended sync routine")
    if SYNC2_VA + len(sync2) > EXT_UI_VA:
        raise SystemExit("extended sync routine overlaps the extended UI routine")
    if EXT_UI_VA + len(ext_ui) > CHECKBOX_VA:
        raise SystemExit("extended UI routine overlaps the checkbox helper")
    if CHECKBOX_VA + len(checkbox) > FARM_EPI_VA:
        raise SystemExit("checkbox helper overlaps the farm epilogue")
    if CHECKBOX_VA + len(checkbox) > MANUAL_HARVEST_VA:
        raise SystemExit("checkbox helper overlaps manual harvest")
    if MANUAL_HARVEST_VA + len(manual_harvest) > FARM_EPI_VA:
        raise SystemExit("manual harvest overlaps the farm epilogue")
    if FARM_EPI_VA + len(farm_epi) > FARM_VA:
        raise SystemExit("farm epilogue overlaps the farm routine")
    if FARM_EPI_VA + len(farm_epi) > FARM_TRAMP_VA:
        raise SystemExit("farm epilogue overlaps the farm trampoline")
    if FARM_TRAMP_VA + len(farm_tramp) > FARM_VA:
        raise SystemExit("farm trampoline overlaps the farm routine")
    if FARM_VA + len(farm) > WASH_CAVE_END_VA:
        raise SystemExit("farm routine overlaps the wash cave end")
    if FARM_VA + len(farm) > WILD_INI_VA:
        raise SystemExit("farm routine overlaps the wild.ini string")
    if WILD_INI_VA + len("wild.ini\x00".encode("utf-16-le")) > WASH_CAVE_END_VA:
        raise SystemExit("wild.ini string exceeds the wash cave")
    if any(pe.bytes_at(TEXT_CAVE_VA, TEXT_CAVE_END_VA - TEXT_CAVE_VA)):
        raise SystemExit("text code cave is not empty")
    if UI_VA + len(ui) > DISPATCH_UI_VA:
        raise SystemExit("settings routine overlaps dispatch routine")
    if DISPATCH_UI_VA + len(dispatch_ui) > TEXT_CAVE_END_VA:
        raise SystemExit("dispatch routine overlaps the text cave end")
    if any(pe.bytes_at(NINE_CAVE_VA, NINE_CAVE_END_VA - NINE_CAVE_VA)):
        raise SystemExit("wndproc code cave is not empty")
    if WNDPROC_VA + len(wndproc) > NINE_CAVE_END_VA:
        raise SystemExit("wndproc routine overlaps the nine cave end")
    if DUNGEON_RETRY_VA < WNDPROC_VA + len(wndproc):
        raise SystemExit("dungeon retry routine overlaps wndproc")
    if DUNGEON_RETRY_VA + len(dungeon_retry) > NINE_CAVE_END_VA:
        raise SystemExit("dungeon retry routine overlaps the nine cave end")

    sections = {s["name"]: s for s in pe.sections}
    wash = sections[".wash"]
    washd = sections[".washd"]
    if wash["rawptr"] + wash["rawsize"] != washd["rawptr"]:
        raise SystemExit("unexpected .wash/.washd raw layout")
    settings_dialog = compact_settings_dialog(
        pe.raw[SETTINGS_DIALOG_OFF:SETTINGS_DIALOG_OFF + SETTINGS_DIALOG_SIZE])

    # The new helper needs file-backed bytes beyond the original .wash raw
    # size. Move the last section (.washd) 0x600 bytes forward and grow
    # .wash to one full page. Section VAs stay unchanged, so the relocated
    # .washd data and strings are still addressed identically.
    new_washd_rawptr = wash["rawptr"] + WASH_RAW_SIZE
    washd_end = washd["rawptr"] + washd["rawsize"]
    raw = bytearray(pe.raw[:washd["rawptr"]])
    raw += b"\x00" * (new_washd_rawptr - washd["rawptr"])
    raw += pe.raw[washd["rawptr"]:washd_end]
    raw += pe.raw[washd_end:]
    raw[SETTINGS_DIALOG_OFF:SETTINGS_DIALOG_OFF + SETTINGS_DIALOG_SIZE] = (
        settings_dialog)

    layout = []
    for sec in pe.sections:
        rawptr = new_washd_rawptr if sec["name"] == ".washd" else sec["rawptr"]
        rawsize = WASH_RAW_SIZE if sec["name"] == ".wash" else sec["rawsize"]
        layout.append((IMAGE_BASE + sec["va"], rawsize, rawptr))

    def put(va, data):
        for base, rawsize, rawptr in layout:
            if base <= va < base + rawsize:
                off = rawptr + (va - base)
                raw[off:off + len(data)] = data
                return
        raise SystemExit("unmapped patch address 0x%08X" % va)

    put(AUTO_VA, auto)
    put(SYNC_VA, sync)
    put(AFTER_VA, after_collect)
    put(ADISPATCH_VA, auto_dispatch)
    put(SYNC2_VA, sync2)
    put(EXT_UI_VA, ext_ui)
    put(CHECKBOX_VA, checkbox)
    put(MANUAL_HARVEST_VA, manual_harvest)
    put(FARM_EPI_VA, farm_epi)
    put(FARM_TRAMP_VA, farm_tramp)
    put(FARM_VA, farm)
    put(UI_VA, ui)
    put(DISPATCH_UI_VA, dispatch_ui)
    put(WNDPROC_VA, wndproc)
    put(DUNGEON_RETRY_VA, dungeon_retry)

    # UTF-16 setting strings and state used by the injected helpers.
    put(WASHD_CLASS_VA, "BUTTON\x00".encode("utf-16-le"))
    put(WASHD_TEXT_VA, "\u81ea\u52a8\u6536\u53d6\x00".encode("utf-16-le"))
    put(WASHD_DISPATCH_TEXT_VA, "\u81ea\u52a8\u6d3e\u9063\x00".encode("utf-16-le"))
    put(WASHD_HARVEST_TEXT_VA, "\u81ea\u52a8\u6536\u83b7\x00".encode("utf-16-le"))
    put(WASHD_PLANT_TEXT_VA, "\u81ea\u52a8\u79cd\u690d\x00".encode("utf-16-le"))
    put(WASHD_APP_VA, "Wild\x00".encode("utf-16-le"))
    put(WILD_INI_VA, "wild.ini\x00".encode("utf-16-le"))
    put(WASHD_KEY_VA, "AutoCollect\x00".encode("utf-16-le"))
    put(WASHD_DISPATCH_KEY_VA, "AutoDispatch\x00".encode("utf-16-le"))
    put(WASHD_HARVEST_KEY_VA, "AutoHarvest\x00".encode("utf-16-le"))
    put(WASHD_PLANT_KEY_VA, "AutoPlant\x00".encode("utf-16-le"))
    put(WASHD_ON_VA, "1\x00".encode("utf-16-le"))
    put(WASHD_OFF_VA, "0\x00".encode("utf-16-le"))
    put(SETTING_VA, struct.pack("<I", 0))
    put(DISPATCH_SETTING_VA, struct.pack("<I", 0))
    put(HARVEST_SETTING_VA, struct.pack("<I", 0))
    put(PLANT_SETTING_VA, struct.pack("<I", 0))
    put(SETTING_HWND_VA, struct.pack("<I", 0))
    put(DISPATCH_HWND_VA, struct.pack("<I", 0))
    put(HARVEST_HWND_VA, struct.pack("<I", 0))
    put(PLANT_HWND_VA, struct.pack("<I", 0))
    put(SETTING_INIT_VA, struct.pack("<I", 0))
    put(EXT_INIT_VA, struct.pack("<I", 0))
    put(FARM_DELAY_VA, struct.pack("<I", 0))
    put(SETTING_OLDPROC_VA, struct.pack("<I", 0))

    # jmp AUTO_VA from the normal tick epilogue
    put(HOOK_TICK_VA, b"\xE9" + struct.pack("<i", AUTO_VA - (HOOK_TICK_VA + 5)))
    # Successful collects reach this call to the UI refresh; failures jump
    # straight to the epilogue. Route the success path through auto-dispatch.
    put(HOOK_COLLECT_DONE_VA,
        b"\xE8" + struct.pack("<i", AFTER_VA - (HOOK_COLLECT_DONE_VA + 5)))
    # Replace the final "mov eax,1" in settings OnInitDialog. The helper
    # creates the checkbox and returns eax=1 for the original success path.
    put(HOOK_SETTINGS_INIT_VA,
        b"\xE8" + struct.pack("<i", UI_VA - (HOOK_SETTINGS_INIT_VA + 5)))
    # Manual harvest paths also honour AutoPlant. The wrapper saves the old
    # crop id before the original routine clears the plot.
    for site in (HOOK_HARVEST_QUICK_VA, HOOK_HARVEST_ALL_VA):
        put(site, b"\xE8" + struct.pack("<i", MANUAL_HARVEST_VA - (site + 5)))
    # Run the farm helper once, immediately after the nine-plot update loop.
    # The trampoline repeats the overwritten instruction before jumping back.
    put(FARM_TICK_VA,
        b"\xE9" + struct.pack("<i", FARM_TRAMP_VA - (FARM_TICK_VA + 5)) +
        b"\x90\x90")
    # Every failed-battle path reaches this jump to the result epilogue. Use
    # the victory result delay when automatic dungeon challenge is on, then
    # continue through the original prompt and function epilogue.
    put(HOOK_DUNGEON_FAIL_VA,
        b"\xE9" + struct.pack("<i", DUNGEON_RETRY_VA -
                              (HOOK_DUNGEON_FAIL_VA + 5)))
    # Switching wild slots clears the old slot's pet selection. Keep its item
    # list intact as well so auto-dispatch can replay all three slots' items.
    put(HOOK_SWITCH_CLEAR_ITEMS_VA, b"\x90" * 5)

    # Cover the injected tails and reserve all state dwords/strings.
    text_hdr = section_header_offset(pe, ".text")
    nine_hdr = section_header_offset(pe, ".nine")
    wash_hdr = section_header_offset(pe, ".wash")
    washd_hdr = section_header_offset(pe, ".washd")
    struct.pack_into("<I", raw, text_hdr + 8, TEXT_VSIZE)
    struct.pack_into("<I", raw, nine_hdr + 8, NINE_VSIZE)
    struct.pack_into("<I", raw, wash_hdr + 8, WASH_VSIZE)
    struct.pack_into("<I", raw, wash_hdr + 16, WASH_RAW_SIZE)
    struct.pack_into("<I", raw, washd_hdr + 8, WASHD_VSIZE)
    struct.pack_into("<I", raw, washd_hdr + 16, washd["rawsize"])
    struct.pack_into("<I", raw, washd_hdr + 20, new_washd_rawptr)

    open(OUT, "wb").write(raw)

    out = PE(OUT)
    changed = [i for i, (a, b) in enumerate(zip(pe.raw, out.raw)) if a != b]
    print("auto routine: %d bytes @ 0x%08X" % (len(auto), AUTO_VA))
    print("sync routine: %d bytes @ 0x%08X" % (len(sync), SYNC_VA))
    print("after collect: %d bytes @ 0x%08X" % (len(after_collect), AFTER_VA))
    print("auto dispatch: %d bytes @ 0x%08X" % (len(auto_dispatch), ADISPATCH_VA))
    print("ext sync    : %d bytes @ 0x%08X" % (len(sync2), SYNC2_VA))
    print("ext ui      : %d bytes @ 0x%08X" % (len(ext_ui), EXT_UI_VA))
    print("checkbox    : %d bytes @ 0x%08X" % (len(checkbox), CHECKBOX_VA))
    print("manual harv : %d bytes @ 0x%08X" % (len(manual_harvest), MANUAL_HARVEST_VA))
    print("farm epi    : %d bytes @ 0x%08X" % (len(farm_epi), FARM_EPI_VA))
    print("farm tramp  : %d bytes @ 0x%08X" % (len(farm_tramp), FARM_TRAMP_VA))
    print("farm        : %d bytes @ 0x%08X" % (len(farm), FARM_VA))
    print("ui routine  : %d bytes @ 0x%08X" % (len(ui), UI_VA))
    print("dispatch ui : %d bytes @ 0x%08X" % (len(dispatch_ui), DISPATCH_UI_VA))
    print("wndproc     : %d bytes @ 0x%08X" % (len(wndproc), WNDPROC_VA))
    print("dungeon retry: %d bytes @ 0x%08X" % (len(dungeon_retry), DUNGEON_RETRY_VA))
    print("setting     : 0x%08X (default 0)" % SETTING_VA)
    print("dispatch    : 0x%08X (default 0)" % DISPATCH_SETTING_VA)
    print("harvest     : 0x%08X (default 0)" % HARVEST_SETTING_VA)
    print("plant       : 0x%08X (default 0)" % PLANT_SETTING_VA)
    print("changed bytes: %d" % len(changed))
    print("source %s" % source)
    print("wrote %s" % OUT)

    md = Cs(CS_ARCH_X86, CS_MODE_32)
    print("\n--- auto ---")
    for ins in md.disasm(auto, AUTO_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    print("\n--- sync ---")
    for ins in md.disasm(sync, SYNC_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    print("\n--- after collect ---")
    for ins in md.disasm(after_collect, AFTER_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    print("\n--- auto dispatch ---")
    for ins in md.disasm(auto_dispatch, ADISPATCH_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    print("\n--- ui ---")
    for ins in md.disasm(ui, UI_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    print("\n--- dispatch ui ---")
    for ins in md.disasm(dispatch_ui, DISPATCH_UI_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))
    print("\n--- wndproc ---")
    for ins in md.disasm(wndproc, WNDPROC_VA):
        print("0x%08X  %-22s %s %s" % (ins.address, ins.bytes.hex(), ins.mnemonic, ins.op_str))

    backup = EXE + ".bak." + datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    shutil.copy2(source, backup)
    print("backup %s" % backup)


if __name__ == "__main__":
    main()

