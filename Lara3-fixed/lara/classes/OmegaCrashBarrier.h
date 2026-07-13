//
//  OmegaCrashBarrier.h
//  lara
//
//  Objective-C @try/@catch trampoline for Swift.
//  Swift cannot enter ObjC @try blocks, so this thin ObjC wrapper
//  catches any NSException thrown during a block and passes it to a handler.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

/// Run `block` inside an ObjC @try. If an NSException is thrown,
/// invoke `onException` with it and return NO. Returns YES on clean exit.
FOUNDATION_EXPORT BOOL OmegaRunWithBarrier(
    void (^ _Nonnull block)(void),
    void (^ _Nullable onException)(NSException * _Nonnull exc)
);

NS_ASSUME_NONNULL_END
