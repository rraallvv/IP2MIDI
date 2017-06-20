// Copyright 2011 Joe Ranieri.
//
// IP2MIDI is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 2 of the License, or (at your option) any later
// version.
//
// IP2MIDI is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// IP2MIDI. If not, see <http://www.gnu.org/licenses/>.

#include <CoreFoundation/CoreFoundation.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include "VMBuffer.h"
#include "queue.h"

#import <CoreMIDI/CoreMIDI.h>
#include <signal.h>

#define INVALID_PID -1

static CFMessagePortRef gMessagePort;
static pcap_t *handle;

MIDIClientRef   theMidiClient;
MIDIEndpointRef midiOut;
char pktBuffer[1024];
MIDIPacketList* pktList = (MIDIPacketList*) pktBuffer;
MIDIPacket     *pkt;

static volatile int keepRunning = 1;

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service
	u_short tlen;           // Total length
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
	u_char  data;
}udp_header;

/* UDP emplty package length */
u_int udp_empty_length = 8;

// Funtion prototypes
void CaptureHandler(u_char *one, const struct pcap_pkthdr *packHead, const u_char *packData);
bool SetupCapture(const char *interface);
void MessagePortClosed(CFMessagePortRef ms, void *info);
void InterruptionHandler(int dummy);
void *CaptureThread(void *arg);

/**
 * Sends information that has been gathered about a packet to the GUI tool on the
 * other end of our CFMesssagePort.
 *
 * The format is:
 * - pcap_pkthdr
 * - packet data
 * - application path
 */
static void SendPacketData(const char *appPath, const struct pcap_pkthdr *packHead, const u_char *packData)
{
	static SInt32 msgid;
	static VMBuffer<UInt8> messageBuffer;
	messageBuffer.Grow(sizeof(pcap_pkthdr) + packHead->caplen + strlen(appPath) + 1);

	UInt8 *pos = messageBuffer.Data();
	memcpy(pos, packHead, sizeof(pcap_pkthdr));
	pos += sizeof(pcap_pkthdr);

	memcpy(pos, packData, packHead->caplen);
	pos += packHead->caplen;

	memcpy(pos, appPath, strlen(appPath) + 1);
	pos += strlen(appPath) + 1;

	CFDataRef data = CFDataCreateWithBytesNoCopy(NULL, messageBuffer.Data(), pos - messageBuffer.Data(), kCFAllocatorNull);
	CFMessagePortSendRequest(gMessagePort, msgid++, data, -1, -1, NULL, NULL);
	CFRelease(data);
}

/**
 * The libpcap callback function. Invoked every time a packet is sent/received.
 */
void CaptureHandler(u_char *one, const struct pcap_pkthdr *packHead, const u_char *packData) {
	const struct ether_header *etherHeader = (const struct ether_header *)packData;
	const struct ip *ipHeader = (const struct ip *)(etherHeader + 1);

	// we can only find endpoints for UDP sockets for now
	if(IPPROTO_UDP == ipHeader->ip_p) {
		ip_header *ih;
		udp_header *uh;
		u_int ip_len;

		/* retireve the position of the ip header */
		ih = (ip_header *) (packData + 14); //length of ethernet header

		/* retireve the position of the udp header */
		ip_len = (ih->ver_ihl & 0xf) * 4;
		uh = (udp_header *) ((u_char*)ih + ip_len);

		int length = OSSwapInt16(uh->len) - udp_empty_length;

		u_char *pdata = &(uh->data);

		pkt = MIDIPacketListInit(pktList);
		pkt = MIDIPacketListAdd(pktList, 1024, pkt, 0, length, pdata);
		MIDIReceived(midiOut, pktList);

		if (gMessagePort != NULL) {
			char buff[32];

			for (int i = 0; i < length; i++) {
				sprintf(buff + i * 3, "%02x:", pdata[i]);
			}

			SendPacketData(buff, packHead, packData);
		}
	}
}

const int buffer_size = 10;

void *CaptureThread(void *arg) {
	if (gMessagePort == NULL) {
		printf("Listening to udp port 9000 (Ctr-C to exit).\n");
	} else {
		printf("Running in GUI mode.\n");
	}
	pcap_loop(handle, -1, CaptureHandler, NULL);
	pcap_close(handle);
	return NULL;
}

bool SetupCapture(const char *interface) {
	handle = pcap_open_live(interface, BUFSIZ, 1, 2, NULL);
	if (handle == NULL) return false;

	char filter_exp[] = "udp port 9000";
	struct bpf_program fp;

	if (pcap_compile(handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
		printf("Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return false;
	}

	if (pcap_setfilter(handle, &fp) == -1) {
		printf("Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
		return false;
	}

	void *buffer[buffer_size];
	queue_t queue = QUEUE_INITIALIZER(buffer);

	// We can't capture on the main thread because it'll block, so we need to
	// set it up on a background thread.
	pthread_t tproducer;
	pthread_create(&tproducer, NULL, CaptureThread, &queue);

	return true;
}

void MessagePortClosed(CFMessagePortRef ms, void *info) {
	// FIXME: we should think about how this process should gracefully shut down.
	// Currently this doesn't kill the capture thread we set up or allow pcap_close
	// to run.
	//
	// I doubt it matters though.
	CFRunLoopStop(CFRunLoopGetCurrent());
}

void InterruptionHandler(int dummy) {
	keepRunning = 0;
}

int main(int argc, char *argv[]) {
	// The name of the message port we're supposed to be connecting to will be the
	// first argument passed to the program. If it's invalid or not specified,
	// this is a critical error and we must abort the process.
	if (argc >= 2) {
		CFStringRef portName = CFStringCreateWithCString(NULL, argv[1], kCFStringEncodingUTF8);
		gMessagePort = CFMessagePortCreateRemote(NULL, portName);
		CFRelease(portName);

		if (!gMessagePort) return 1;
	}

	MIDIClientCreate(CFSTR("Magical MIDI"), NULL, NULL,
					 &theMidiClient);
	MIDISourceCreate(theMidiClient, CFSTR("Magical MIDI Source"),
					 &midiOut);

	// FIXME: don't hardcode "en1". Instead we should probably have it passed
	// to us in argv.
	if (SetupCapture("en0")) {
		if (gMessagePort != NULL) {
			// We need to get notified when this message port gets invalidated because
			// this is our signal by the parent process that capturing needs to stop.
			//
			// Since we're in CF-land and not using Mach ports directly, we need a
			// CFRunLoop.
			CFMessagePortSetInvalidationCallBack(gMessagePort, MessagePortClosed);
			CFRunLoopRun();
		} else {
			// We need to wait for the interuption signal (Ctrl+C), since we're running in CLI mode.
			signal(SIGINT, InterruptionHandler);
			while (keepRunning);
		}

		MIDIEndpointDispose(midiOut);
		MIDIClientDispose(theMidiClient);
		return 0;
	}

	return 1;
}
