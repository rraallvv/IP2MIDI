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
#include "Utils.h"

#import <CoreMIDI/CoreMIDI.h>
#include <signal.h>

#define INVALID_PID -1

static CFMessagePortRef gMessagePort;

MIDIClientRef   theMidiClient;
MIDIEndpointRef midiOut;
char pktBuffer[1024];
MIDIPacketList* pktList = (MIDIPacketList*) pktBuffer;
MIDIPacket     *pkt;
Byte            midiDataToSend[] = {0x91, 0x3c, 0x40};

static volatile int keepRunning = 1;

// Funtion prototypes
void Handler(u_char *one, const struct pcap_pkthdr *packHead, const u_char *packData);
bool SetupCapture(const char *interface);
void MessagePortClosed(CFMessagePortRef ms, void *info);
void InterruptionHandler(int dummy);

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
	if (gMessagePort == NULL) {
		return;
	}

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
void Handler(u_char *one, const struct pcap_pkthdr *packHead, const u_char *packData) {
	const struct ether_header *etherHeader = (const struct ether_header *)packData;
	const struct ip *ipHeader = (const struct ip *)(etherHeader + 1);

	// we can only find endpoints for TCP sockets for now
	if(IPPROTO_UDP == ipHeader->ip_p) {
		char buff[64];
		unsigned char bytes[4];
		bytes[0] = ipHeader->ip_src.s_addr & 0xFF;
		bytes[1] = (ipHeader->ip_src.s_addr >> 8) & 0xFF;
		bytes[2] = (ipHeader->ip_src.s_addr >> 16) & 0xFF;
		bytes[3] = (ipHeader->ip_src.s_addr >> 24) & 0xFF;
		sprintf(buff,"%d.%d.%d.%d", bytes[0], bytes[1], bytes[2], bytes[3]);

		if(strcmp("192.168.0.101", buff) != 0) {
			return;
		}

		sprintf(buff, "%x %x %x", *(packData + 42), *(packData + 43), *(packData + 44));

		midiDataToSend[0] = *(packData + 42);
		midiDataToSend[1] = *(packData + 43);
		midiDataToSend[2] = *(packData + 44);

		pkt = MIDIPacketListInit(pktList);
		pkt = MIDIPacketListAdd(pktList, 1024, pkt, 0, 3, midiDataToSend);
		MIDIReceived(midiOut, pktList);

		printf("%s\n", buff);

		SendPacketData(buff, packHead, packData);
	}
}

bool SetupCapture(const char *interface) {
	pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 2, NULL);
	if (handle == NULL) return false;

	// We can't run this on the main thread because it'll block, so we need to
	// set it up on a background thread. I tried quite a bit to get this running
	// under a CFRunloop using CFFileDescriptorRef, but it just wouldn't work.
	//
	// If I ran it under libdispach directly, it worked fine (I think), but then
	// I couldn't get notifications about the message port being invalidated.
	RunBlockThreaded(^(void) {
		pcap_loop(handle, -1, Handler, NULL);
		pcap_close(handle);
	});

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
		// We need to get notified when this message port gets invalidated because
		// this is our signal by the parent process that capturing needs to stop.
		//
		// Since we're in CF-land and not using Mach ports directly, we need a
		// CFRunLoop and not dispatch_main.
		if (gMessagePort != NULL) {
			CFMessagePortSetInvalidationCallBack(gMessagePort, MessagePortClosed);
			CFRunLoopRun();
		} else {
			signal(SIGINT, InterruptionHandler);
			while (keepRunning);
		}

		MIDIEndpointDispose(midiOut);
		MIDIClientDispose(theMidiClient);
		return 0;
	}

	return 1;
}
