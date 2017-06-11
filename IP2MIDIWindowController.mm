// Copyright 2011 Joe Ranieri & Zach Fisher.
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

#import "IP2MIDIWindowController.h"
#import "IP2MIDIDocument.h"
#import "DatabaseLocker.h"
#import "IP2MIDICapture.h"
#import "PrettyCell.h"

@interface IP2MIDIWindowController ()
- (void)setupDatabase;
- (void)launchCaptureTool;
@end


@implementation IP2MIDIWindowController
@synthesize menu;

- (void)awakeFromNib {
	statusItem = [[[NSStatusBar systemStatusBar] statusItemWithLength:NSVariableStatusItemLength] retain];

	NSImage *menuIcon       = [NSImage imageNamed:@"Menu Icon"];
	NSImage *highlightIcon  = [NSImage imageNamed:@"Menu Icon"];
	[highlightIcon setTemplate:YES];

	[statusItem setImage:menuIcon];
	[statusItem setAlternateImage:highlightIcon];
	[statusItem setHighlightMode:YES];
	[statusItem setMenu:[self menu]];

	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
}

- (void)windowDidLoad {
	[self setupDatabase];
	[packetsView setDelegate:self];
	[packetsView setDataSource:self];
	[[self window] setDelegate:self];

	if ([[self document] isNewDocument]) {
		[self launchCaptureTool];
	}
}

- (IBAction)menuAction:(id)sender {
	[NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];
}

-(NSSize)windowWillResize:(NSWindow *)sender toSize:(NSSize)frameSize {
	frameSize.width = sender.frame.size.width;
	return frameSize;
}

- (BOOL)windowShouldClose:(id)sender {
	[NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
	return NO;
}

- (void)windowWillClose:(NSNotification *)notification {
	[capture stopCapture];
	[capture release];
	capture = nil;

	[statusItem release];
	statusItem = nil;

	sqlite3_finalize(rowCountStmt);
	rowCountStmt = NULL;

	sqlite3_finalize(packetSelectStmt);
	packetSelectStmt = NULL;

	sqlite3_finalize(appSelectStmt);
	appSelectStmt = NULL;
}

- (void)setupDatabase {
	DatabaseLocker lock([self document]);
	sqlite3_prepare_v2(lock.Database(), "SELECT COUNT(*) FROM packets", -1, &rowCountStmt, NULL);
	sqlite3_prepare_v2(lock.Database(), "SELECT * FROM packets ORDER BY rowid LIMIT 1 OFFSET ?", -1, &packetSelectStmt, NULL);
	sqlite3_prepare_v2(lock.Database(), "SELECT path FROM applications WHERE rowid = ?", -1, &appSelectStmt, NULL);
}

- (void)launchCaptureTool {
	capture = [[IP2MIDICapture alloc] initWithDocument:[self document]];
	[capture beginCapture];
}

#pragma mark -

- (void)dataChanged {
	[packetsView reloadData];
	[[self document] updateChangeCount:NSChangeDone];
	[packetsView scrollRowToVisible:[packetsView numberOfRows] - 1];
}

- (NSInteger)numberOfRowsInTableView:(NSTableView *)tableView {
	DatabaseLocker lock([self document]);

	sqlite3_reset(rowCountStmt);
	sqlite3_step(rowCountStmt);

	return sqlite3_column_int(rowCountStmt, 0);
}

- (id)tableView:(NSTableView *)tableView objectValueForTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row {
	DatabaseLocker lock([self document]);
	int appRowID;
	NSString *result;

	sqlite3_bind_int64(packetSelectStmt, 1, row);
	sqlite3_step(packetSelectStmt);
	appRowID = sqlite3_column_int64(packetSelectStmt, 0);
	sqlite3_reset(packetSelectStmt);

	sqlite3_bind_int64(appSelectStmt, 1, appRowID);
	sqlite3_step(appSelectStmt);
	result = [NSString stringWithUTF8String:(const char *)sqlite3_column_text(appSelectStmt, 0)];
	sqlite3_reset(appSelectStmt);

	return result;
}

- (void)tableViewSelectionDidChange:(NSNotification *)notification {
	NSInteger row = [[notification object] selectedRow];
	NSData *data = [[self document] packetData:row];
}

- (void)tableView:(NSTableView *)tableView willDisplayCell:(id)cell forTableColumn:(NSTableColumn *)tableColumn row:(NSInteger)row;
{
	NSString *appPath = [cell stringValue];

	//strip off the XXX.app/Contents/MacOS/XXX part of the appPath. FIXME?
	appPath = [appPath stringByDeletingLastPathComponent];
	appPath = [appPath stringByDeletingLastPathComponent];
	appPath = [appPath stringByDeletingLastPathComponent];
	if (![appPath length]) return;

	NSImage *appIcon = [[NSWorkspace sharedWorkspace] iconForFile:appPath];
	NSImage *smallIcon = [[[NSImage alloc] initWithSize:NSMakeSize(16.0f, 16.0f)] autorelease];
	[smallIcon addRepresentation:[appIcon bestRepresentationForRect:NSMakeRect(0, 0, 16.0f, 16.0f) context:nil hints:nil]];

	PrettyCell *prettyCell = (PrettyCell *)cell;
	[prettyCell setImage: smallIcon];
}


@end
