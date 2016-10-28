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

#ifndef plugmein_usb_h
#define plugmein_usb_h

#include <stdint.h>
extern "C" {
#include <pcap.h>
#include <pcap/usb.h>
}


namespace plugmein {

struct usb_hdr {
	uint64_t id;
	uint8_t event_type, transfer_type, endpoint, device;
	uint16_t bus_id;
	char setup_flag, data_flag;
	int64_t ts_sec;
	int32_t ts_usec;
	int32_t status;
	uint32_t urb_len, data_len;
	pcap_usb_setup setup;
};


// event_type's
enum {
	EVENT_SUBMIT	= 'S',
	EVENT_COMPLETE	= 'C',
	EVENT_ERROR	= 'E'
};


}

#endif

