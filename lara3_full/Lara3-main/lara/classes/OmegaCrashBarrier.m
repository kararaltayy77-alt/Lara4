//
//  OmegaCrashBarrier.m
//  lara
//
//  Implementation of the ObjC @try/@catch crash barrier.
//

#import "OmegaCrashBarrier.h"

BOOL OmegaRunWithBarrier(void (^block)(void),
                         void (^onException)(NSException *exc)) {
    @try {
        block();
        return YES;
    }
    @catch (NSException *exc) {
        if (onException) onException(exc);
        return NO;
    }
}
