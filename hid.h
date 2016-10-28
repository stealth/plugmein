/*
 * This file is part of the plugmein USB security toolset.
 *
 * (C) 2016 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
 *
 * plugmein is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * plugmein is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with plugmein.  If not, see <http://www.gnu.org/licenses/>.
 */

// keyboard HID usage table
#ifndef plugmein_hid_h
#define plugmein_hid_h

#include <stdint.h>

namespace plugmein {

struct hid_tab {
	uint8_t mod;
	uint8_t reserved;
	uint8_t key[6];
};



// As per HID Usage Tables version 1.12
struct {
	uint8_t value;
	const char *str;
} hid_tab_entry[256] = {
	{0, ""},
	{0x01, "<ErrorRollOver>"},
	{0x02, "<POSTFail>"},
	{0x03, "<ErrorUndefined>"},
	{0x04, "a"},
	{0x05, "b"},
	{0x06, "c"},
	{0x07, "d"},
	{0x08, "e"},
	{0x09, "f"},
	{0x0A, "g"},
	{0x0B, "h"},
	{0x0C, "i"},
	{0x0D, "j"},
	{0x0E, "k"},
	{0x0F, "l"},
	{0x10, "m"},
	{0x11, "n"},
	{0x12, "o"},
	{0x13, "p"},
	{0x14, "q"},
	{0x15, "r"},
	{0x16, "s"},
	{0x17, "t"},
	{0x18, "u"},
	{0x19, "v"},
	{0x1A, "w"},
	{0x1B, "x"},
	{0x1C, "y"},
	{0x1D, "z"},
	{0x1E, "1"},
	{0x1F, "2"},
	{0x20, "3"},
	{0x21, "4"},
	{0x22, "5"},
	{0x23, "6"},
	{0x24, "7"},
	{0x25, "8"},
	{0x26, "9"},
	{0x27, "0"},
	{0x28, "<Enter>"},
	{0x29, "<Escape>"},
	{0x2A, "<Backspace>"},
	{0x2B, "<Tab>"},
	{0x2C, "<Space>"},
	{0x2D, "<- or _>"},
	{0x2E, "<= or +>"},
	{0x2F, "<[ or {>"},
	{0x30, "<] or }>"},
	{0x31, "<\\ or |>"},
	{0x32, "<Non-US #>"},
	{0x33, "<; or  :>"},
	{0x34, "'"},
	{0x35, "~"},
	{0x36, "<, or <>"},
	{0x37, "<> or .>"},
	{0x38, "</ or  ?>"},
	{0x39, "<Caps Lock>"},
	{0x3A, "<F1>"},
	{0x3B, "<F2>"},
	{0x3C, "<F3>"},
	{0x3D, "<F4>"},
	{0x3E, "<F5>"},
	{0x3F, "<F6>"},
	{0x40, "<F7>"},
	{0x41, "<F8>"},
	{0x42, "<F9>"},
	{0x43, "<F10>"},
	{0x44, "<F11>"},
	{0x45, "<F12>"},
	{0x46, "<PrintScreen>"},
	{0x47, "<Scroll Lock>"},
	{0x48, "<Pause>"},
	{0x49, "<Insert>"},
	{0x4A, "<Home>"},
	{0x4B, "<PageUp>"},
	{0x4C, "<Delete Forward>"},
	{0x4D, "<End>"},
	{0x4E, "<PageDown>"},
	{0x4F, "<RightArrow>"},
	{0x50, "<LeftArrow>"},
	{0x51, "<DownArrow>"},
	{0x52, "<UpArrow>"},
	{0x53, "<Keypad Num Lock Clear>"},
	{0x54, "<Keypad />"},
	{0x55, "<Keypad *>"},
	{0x56, "<Keypad ->"},
	{0x57, "<Keypad +>"},
	{0x58, "<Keypad Return>"},
	{0x59, "<Keypad 1>"},
	{0x5A, "<Keypad 2>"},
	{0x5B, "<Keypad 3>"},
	{0x5C, "<Keypad 4>"},
	{0x5D, "<Keypad 5>"},
	{0x5E, "<Keypad 6>"},
	{0x5F, "<Keypad 7>"},
	{0x60, "<Keypad 8>"},
	{0x61, "<Keypad 9>"},
	{0x62, "<Keypad 0>"},
	{0x63, "<Keypad . or ,>"},
	{0x64, "<Non-US \\ or |>"},
	{0x65, "<Application>"},
	{0x66, "<Power>"},
	{0x67, "<Keypad =>"},
	{0x68, "<F13>"},
	{0x69, "<F14>"},
	{0x6A, "<F15>"},
	{0x6B, "<F16>"},
	{0x6C, "<F17>"},
	{0x6D, "<F18>"},
	{0x6E, "<F19>"},
	{0x6F, "<F20>"},
	{0x70, "<F21>"},
	{0x71, "<F22>"},
	{0x72, "<F23>"},
	{0x73, "<F24>"},
	{0x74, "<Execute>"},
	{0x75, "<Help>"},
	{0x76, "<Menu>"},
	{0x77, "<Select>"},
	{0x78, "<Stop>"},
	{0x79, "<Again>"},
	{0x7A, "<Undo>"},
	{0x7B, "<Cut>"},
	{0x7C, "<Copy>"},
	{0x7D, "<Paste>"},
	{0x7E, "<Find>"},
	{0x7F, "<Mute>"},
	{0x80, "<Volume Up>"},
	{0x81, "<Volume Down>"},
	{0x82, "<Locking Caps Lock>"},
	{0x83, "<Locking Num Lock>"},
	{0x84, "<Locking Scroll Lock>"},
	{0x85, "<Keypad Comma>"},
	{0x86, "<Keypad Equal Sign>"},
	{0x87, "<International1>"},
	{0x88, "<International2>"},
	{0x89, "<International3>"},
	{0x8A, "<International4>"},
	{0x8B, "<International5>"},
	{0x8C, "<International6>"},
	{0x8D, "<International7>"},
	{0x8E, "<International8>"},
	{0x8F, "<International9>"},
	{0x90, "<LANG1>"},
	{0x91, "<LANG2>"},
	{0x92, "<LANG3>"},
	{0x93, "<LANG4>"},
	{0x94, "<LANG5>"},
	{0x95, "<LANG6>"},
	{0x96, "<LANG7>"},
	{0x97, "<LANG8>"},
	{0x98, "<LANG9>"},
	{0x99, "<Alternate Erase>"},
	{0x9A, "<SysReq/Attention>"},
	{0x9B, "<Cancel>"},
	{0x9C, "<Clear>"},
	{0x9D, "<Prior>"},
	{0x9E, "<Return>"},
	{0x9F, "<Separator>"},
	{0xA0, "<Out>"},
	{0xA1, "<Oper>"},
	{0xA2, "<Clear/Again>"},
	{0xA3, "<CrSel/Props>"},
	{0xA4, "<ExSel>"},
	{0xE0, "<LeftControl>"},
	{0xE1, "<LeftShift>"},
	{0xE2, "<LeftAlt>"},
	{0xE3, "<Left GUI>"},
	{0xE4, "<RightControl>"},
	{0xE5, "<RightShift>"},
	{0xE6, "<RightAlt>"},
	{0xE7, "<Right GUI>"}
};


enum {
	HID_MOD_NONE	= 0,
	HID_MOD_LCTRL	= 1,
	HID_MOD_LSHIFT	= 2,
	HID_MOD_LALT	= 4,
	HID_MOD_LGUI	= 8,
	HID_MOD_RCTRL	= 16,
	HID_MOD_RSHIFT	= 32,
	HID_MOD_RALT	= 64,
	HID_MOD_RGUI	= 128
};

}



#endif
