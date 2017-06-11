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

#import "IP2MIDICapture.h"
#import <pcap.h>
#import "IP2MIDIDocument.h"

@implementation IP2MIDICapture

void DissectPacket(IP2MIDICapture *delegate, SInt32 msgid, NSData *rawData) {
	const char *bytes = (const char *)[rawData bytes];
	pcap_pkthdr *header = (pcap_pkthdr *)bytes;
	const char *dataStart = (const char *)(header + 1);
	const char *nameStart = dataStart + header->caplen;
	
	NSData *packetData = [NSData dataWithBytes:dataStart length:header->caplen];
	[delegate->document addPacket:packetData
						   header:header
					   identifier:msgid
					  application:[NSString stringWithUTF8String:nameStart]
						 metadata:nil];
}

CFDataRef PacketCallback(CFMessagePortRef local, SInt32 msgid, CFDataRef data, void *info) {
	IP2MIDICapture *delegate = (IP2MIDICapture *)info;
	CFDataRef dataCopy = CFDataCreateCopy(NULL, data);
	
	dispatch_async(dispatch_get_global_queue(0, 0), ^(void) {
		DissectPacket(delegate, msgid, (NSData *)dataCopy);
		CFRelease(dataCopy);
	});
	
	return NULL;
}

- (id)initWithDocument:(IP2MIDIDocument *)theDocument {
	if (self = [super init]) {
		document = [theDocument retain];
	}
	
	return self;
}

- (NSString *)captureToolPath {
	return [[NSBundle mainBundle] pathForAuxiliaryExecutable:@"ip2midi-cli"];
}

- (NSString *)makePortName {
	CFUUIDRef uuid = CFUUIDCreate(NULL);
	CFStringRef uuidString = CFUUIDCreateString(NULL, uuid);
	NSString *result = [NSString stringWithFormat:@"com.alacatia.IP2MIDI.%@", uuidString];
	
	CFRelease(uuidString);
	CFRelease(uuid);
	return result;
}

- (BOOL)beginCapture {
	NSString *portName = [self makePortName];
	
	CFMessagePortContext context;
	context.version = 0;
	context.info = self;
	context.retain = CFRetain;
	context.release = CFRelease;
	context.copyDescription = CFCopyDescription;
	
	messagePort = CFMessagePortCreateLocal(NULL, (CFStringRef)portName, PacketCallback, &context, NULL);
	CFRunLoopSourceRef source = CFMessagePortCreateRunLoopSource(NULL, messagePort, 0);
	CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopDefaultMode);
	CFRelease(source);
	
	NSString *IP2MIDIPathString = [self captureToolPath];

	captureToolTask = [NSTask launchedTaskWithLaunchPath:IP2MIDIPathString arguments:[[NSArray alloc] initWithObjects:portName, nil]];
	
	return captureToolTask != nil;
}

- (void)stopCapture {
	CFMessagePortInvalidate(messagePort);
	CFRelease(messagePort);
	if (captureToolTask != nil) {
		//[captureToolTask terminate];
		//captureToolTask = nil;
	}
	messagePort = NULL;
}

@end
