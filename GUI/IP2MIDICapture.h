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

#import <Cocoa/Cocoa.h>
@class IP2MIDIDocument;

@interface IP2MIDICapture : NSObject {
	IP2MIDIDocument *document;
	CFMessagePortRef messagePort;
	NSTask *captureToolTask;
}

- (id)initWithDocument:(IP2MIDIDocument *)document;

- (NSString *)captureToolPath;
- (BOOL)beginCapture;
- (void)stopCapture;

@end
