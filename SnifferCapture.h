// Copyright 2011 Joe Ranieri.
//
// Sniffer is free software: you can redistribute it and/or modify it under the
// terms of the GNU General Public License as published by the Free Software
// Foundation, either version 2 of the License, or (at your option) any later
// version.
//
// Sniffer is distributed in the hope that it will be useful, but WITHOUT ANY
// WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
// FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
// details.
//
// You should have received a copy of the GNU General Public License along with
// Sniffer. If not, see <http://www.gnu.org/licenses/>.

#import <Cocoa/Cocoa.h>
#import <Security/Security.h>
@class SnifferDocument;

@interface SnifferCapture : NSObject {
	SnifferDocument *document;
	CFMessagePortRef messagePort;
	NSTask *captureToolTask;
}

- (id)initWithDocument:(SnifferDocument *)document;

- (NSString *)captureToolPath;
- (BOOL)beginCaptureWithAuthorization:(AuthorizationRef)authorizationRef;
- (void)stopCapture;

@end
