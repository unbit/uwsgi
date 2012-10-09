#include "../../uwsgi.h"
#import "Foundation/NSString.h"
#import "AppKit/NSSpeechSynthesizer.h"

@interface uWSGIAlarmSpeaker : NSObject {
        NSSpeechSynthesizer *synth;
}

-(void)speak: (NSString *)phrase;

@end


@implementation uWSGIAlarmSpeaker

- (uWSGIAlarmSpeaker *) init {
        self = [super init];
        synth = [[NSSpeechSynthesizer alloc] initWithVoice:nil];
        return self;
}

- (void)speak:(NSString *)phrase {
        [synth startSpeakingString:phrase];
}

@end

// generate a uwsgi signal on alarm
void uwsgi_alarm_speech_init(struct uwsgi_alarm_instance *uai) {
        uai->data_ptr = [[uWSGIAlarmSpeaker alloc] init];
}

void uwsgi_alarm_speech_func(struct uwsgi_alarm_instance *uai, char *msg, size_t len) {
	uWSGIAlarmSpeaker *say = (uWSGIAlarmSpeaker *) uai->data_ptr;
	NSString *phrase = [[NSString alloc]  initWithBytes:msg
                                                    length:len
                                                  encoding:NSUTF8StringEncoding];

	[say speak:phrase];
	[phrase release];

}

static void uwsgi_alarm_speech_load(void) {
        uwsgi_register_alarm("speech", uwsgi_alarm_speech_init, uwsgi_alarm_speech_func);
}

struct uwsgi_plugin alarm_speech_plugin = {
        .name = "alarm_speech",
        .on_load = uwsgi_alarm_speech_load,
};

