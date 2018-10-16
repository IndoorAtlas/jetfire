/////////////////////////////////////////////////////////////////////////////
//
//  JFRWebSocket.m
//
//  Created by Austin and Dalton Cherry on 5/13/14.
//  Copyright (c) 2014 Vluxe. All rights reserved.
//
/////////////////////////////////////////////////////////////////////////////

#import "JFRWebSocket.h"
#import <UIKit/UIKit.h>
#import <pthread.h>
#import <objc/runtime.h>

//get the opCode from the packet
typedef NS_ENUM(NSUInteger, JFROpCode) {
    JFROpCodeContinueFrame = 0x0,
    JFROpCodeTextFrame = 0x1,
    JFROpCodeBinaryFrame = 0x2,
    //3-7 are reserved.
    JFROpCodeConnectionClose = 0x8,
    JFROpCodePing = 0x9,
    JFROpCodePong = 0xA,
    //B-F reserved.
};

typedef NS_ENUM(NSUInteger, JFRCloseCode) {
    JFRCloseCodeNormal                 = 1000,
    JFRCloseCodeGoingAway              = 1001,
    JFRCloseCodeProtocolError          = 1002,
    JFRCloseCodeProtocolUnhandledType  = 1003,
    // 1004 reserved.
    JFRCloseCodeNoStatusReceived       = 1005,
    //1006 reserved.
    JFRCloseCodeEncoding               = 1007,
    JFRCloseCodePolicyViolated         = 1008,
    JFRCloseCodeMessageTooBig          = 1009
};

typedef NS_ENUM(NSUInteger, JFRInternalErrorCode) {
    // 0-999 WebSocket status codes not used
    JFROutputStreamWriteError  = 1,
    JFRProxyError = 2,
};

#define kJFRInternalHTTPStatusWebSocket 101

//holds the responses in our read stack to properly process messages
@interface JFRResponse : NSObject

@property(nonatomic, assign)BOOL isFin;
@property(nonatomic, assign)JFROpCode code;
@property(nonatomic, assign)NSInteger bytesLeft;
@property(nonatomic, assign)NSInteger frameCount;
@property(nonatomic, strong)NSMutableData *buffer;

@end

@class JFRWebSocketProxyHandler;
@interface JFRWebSucket () <NSStreamDelegate>
- (void)connect;
- (void)disconnect;
- (void)writeData:(NSData*)data;
- (void)writeString:(NSString*)string;
- (void)writePing:(NSData*)data;
- (void)addHeader:(NSString*)value forKey:(NSString*)key;

@property(atomic, assign)BOOL isConnected;
@property(atomic, assign)BOOL voipEnabled;
@property(atomic, assign)BOOL selfSignedSSL;
@property(atomic, strong)NSString *securityLevel;
@property(atomic, strong)JFRSecurity *security;
@property(atomic, strong)NSString *proxyUsername;
@property(atomic, strong)NSString *proxyPassword;
@property(atomic, strong)dispatch_queue_t queue;
@property(atomic, strong)void (^onConnect)(void);
@property(atomic, strong)void (^onDisconnect)(NSError*);
@property(atomic, strong)void (^onData)(NSData*);
@property(atomic, strong)void (^onText)(NSString*);
@property(atomic, strong)NSURL *url;

@property(nonatomic, strong)NSInputStream *inputStream;
@property(nonatomic, strong)NSOutputStream *outputStream;
@property(nonatomic, strong)NSMutableArray *readStack;
@property(nonatomic, strong)NSMutableArray *inputQueue;
@property(nonatomic, strong)NSData *fragBuffer;
@property(nonatomic, strong)NSMutableDictionary *headers;
@property(nonatomic, strong)NSArray *optProtocols;
@property(nonatomic, assign)BOOL isCreated;
@property(nonatomic, assign)BOOL didDisconnect;
@property(nonatomic, assign)BOOL certValidated;
@property(nonatomic, strong)JFRWebSocketProxyHandler *proxyHandler;
@end

//Constant Header Values.
static NSString *const headerWSUpgradeName     = @"Upgrade";
static NSString *const headerWSUpgradeValue    = @"websocket";
static NSString *const headerWSHostName        = @"Host";
static NSString *const headerWSConnectionName  = @"Connection";
static NSString *const headerWSConnectionValue = @"Upgrade";
static NSString *const headerWSProtocolName    = @"Sec-WebSocket-Protocol";
static NSString *const headerWSVersionName     = @"Sec-Websocket-Version";
static NSString *const headerWSVersionValue    = @"13";
static NSString *const headerWSKeyName         = @"Sec-WebSocket-Key";
static NSString *const headerOriginName        = @"Origin";
static NSString *const headerWSAcceptName      = @"Sec-WebSocket-Accept";

//Class Constants
static char CRLFBytes[] = {'\r', '\n', '\r', '\n'};
#define BUFFER_MAX 4096

// This get the correct bits out by masking the bytes of the buffer.
static const uint8_t JFRFinMask             = 0x80;
static const uint8_t JFROpCodeMask          = 0x0F;
static const uint8_t JFRRSVMask             = 0x70;
static const uint8_t JFRMaskMask            = 0x80;
static const uint8_t JFRPayloadLenMask      = 0x7F;
static const size_t  JFRMaxFrameSize        = 32;

@interface JFRWebSocketProxyHandler : NSObject <NSStreamDelegate>
@property(nonatomic, strong)NSString *proxyUsername;
@property(nonatomic, strong)NSString *proxyPassword;
@property(nonatomic, strong)NSURL *url;
@property(nonatomic, strong)NSURL *proxy;
@property(nonatomic, strong)NSInputStream *inputStream;
@property(nonatomic, strong)NSOutputStream *outputStream;
@property(nonatomic, strong)NSTimer *timeout;
@property(nonatomic, strong)NSMutableData *response;
@property(nonatomic, copy)void (^completion)(bool success, NSInputStream *inputStream, NSOutputStream *outputStream, NSString *sni);
@property(nonatomic, assign)bool connecting;
@property(nonatomic, assign)NSUInteger authTries;
@end

@implementation JFRWebSocketProxyHandler

- (NSURL*)wsToHTTP:(NSURL*)url
{
    NSURLComponents *components = [NSURLComponents componentsWithURL:url resolvingAgainstBaseURL:YES];
    
    if([components.scheme isEqualToString:@"wss"]) {
        components.scheme = @"https";
    } else if([components.scheme isEqualToString:@"ws"]) {
        components.scheme = @"http";
    }
    
    return components.URL;
}

- (void)complete:(bool)success sni:(NSString*)sni
{
    if (!self.completion)
        return;
    
    self.response = nil;
    self.inputStream.delegate = nil;
    self.outputStream.delegate = nil;
    self.completion(success, self.inputStream, self.outputStream, sni);
    self.completion = nil;
    [self.timeout invalidate];
    self.timeout = nil;
}

- (void)sendProxyConnectWithAuthorization:(NSString*)auth
{
    NSArray *headers = @[
                         [NSString stringWithFormat:@"CONNECT %@ HTTP/1.1", [NSString stringWithFormat:@"%@:%@", self.url.host, self.url.port]],
                         [NSString stringWithFormat:@"Host: %@", self.url.host],
                         @"Proxy-Connection: keep-alive",
                         @"Connection: keep-alive",
                         @"Cache-Control: no-cache, no-store, must-revalidate",
                         @"Pragma: no-cache",
                         @"Expires: 0",
                         ];
    
    if(auth)
        headers = [headers arrayByAddingObject:[NSString stringWithFormat:@"Proxy-Authorization: %@", auth]];
    
    NSData *message = [[[headers componentsJoinedByString:@"\r\n"] stringByAppendingString:@"\r\n\r\n"] dataUsingEncoding:NSASCIIStringEncoding];
    
    NSInteger len = [self.outputStream write:[message bytes] maxLength:[message length]];
    if(len <= 0) {
        [self complete:false sni:nil];
        return;
    }
}

- (void)readProxyResponse
{
    UInt8 buf[BUFFER_MAX];
    NSInteger len = [self.inputStream read:buf maxLength:sizeof(buf)];
    
    if(len < 0) {
        [self complete:false sni:nil];
        return;
    }
    
    // 10MiB max limit
    const size_t max_len = 10 * 1024 * 1024;
    
    if(self.response.length + len > max_len) {
        NSLog(@"Proxy response over 10MiB, discarding response...");
        self.response = nil;
    }
    
    if(len > max_len)
        return;

    if(!self.response)
        self.response = [NSMutableData data];
    
    [self.response appendBytes:buf length:len];
    
    CFHTTPMessageRef receivedProxyHTTPHeaders = CFHTTPMessageCreateEmpty(NULL, NO);
    CFHTTPMessageAppendBytes(receivedProxyHTTPHeaders, self.response.bytes, self.response.length);
    
    if(!CFHTTPMessageIsHeaderComplete(receivedProxyHTTPHeaders)) {
        CFRelease(receivedProxyHTTPHeaders);
        return;
    }
    
    NSDictionary *proxyHeaders = (__bridge id)CFHTTPMessageCopyAllHeaderFields(receivedProxyHTTPHeaders);

    NSInteger responseCode = CFHTTPMessageGetResponseStatusCode(receivedProxyHTTPHeaders);
    CFRelease(receivedProxyHTTPHeaders);
    
    if(self.response.length < [proxyHeaders[@"Content-Length"] longLongValue])
        return;
    
    self.response = nil;
    
    if(responseCode == 407) {
        if (self.authTries >= 3) {
            [self complete:false sni:nil];
            return;
        }
        
        self.authTries++;
        
        NSString *authHeader = proxyHeaders[@"Proxy-Authenticate"];
        NSString *auth = nil;
        NSString *authType = nil;
        if([authHeader.lowercaseString rangeOfString:@"digest"].location != NSNotFound) {
            authType = @"Digest";
        } else {
            authType = @"Basic";
            if (self.proxyUsername && self.proxyPassword) {
                auth = [[[NSString stringWithFormat:@"%@:%@", self.proxyUsername, self.proxyPassword] dataUsingEncoding:NSASCIIStringEncoding] base64EncodedStringWithOptions:0];
            }
        }
        
        if(auth) {
            [self sendProxyConnectWithAuthorization:[NSString stringWithFormat:@"%@ %@", authType, auth]];
            return;
        }
    }
    
    if(responseCode >= 400) {
        [self complete:false sni:nil];
    } else {
        [self complete:true sni:self.url.host];
    }
}

- (void)connectToProxy
{
    if(self.connecting)
        return;
    
    self.connecting = true;
    
    if(!self.proxy) {
        [self complete:true sni:nil];
        return;
    }

    [self sendProxyConnectWithAuthorization:nil];
}

- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode
{
    switch (eventCode) {
        case NSStreamEventOpenCompleted:
            break;
            
        case NSStreamEventHasBytesAvailable:
            if(aStream == self.inputStream)
                [self readProxyResponse];
            break;
            
        case NSStreamEventEndEncountered:
        case NSStreamEventErrorOccurred:
            [self complete:false sni:nil];
            break;
            
        case NSStreamEventHasSpaceAvailable:
            if(aStream == self.outputStream)
                [self connectToProxy];
            break;
            
        case NSStreamEventNone:
        default:
            break;
    }
}

- (void)didTimeout
{
    [self complete:false sni:nil];
}

- (void)resetTimeout
{
    [self.timeout invalidate];
    self.timeout = [NSTimer scheduledTimerWithTimeInterval:60.0 target:self selector:@selector(didTimeout) userInfo:nil repeats:NO];
}

- (void)connect:(NSURL*)url completion:(void(^)(bool, NSInputStream*, NSOutputStream*, NSString*))completion
{
    assert(completion);
    
    if(self.completion) {
        completion(false, nil, nil, nil);
        return;
    }
    
    self.url = url;
    self.completion = completion;
    
    NSDictionary *settings  = nil;
    NSDictionary *proxySettings = (__bridge id)CFNetworkCopySystemProxySettings();
    NSURL *URL = [self wsToHTTP:url];
    NSArray *proxies = (__bridge id)CFNetworkCopyProxiesForURL((__bridge CFURLRef)URL, (__bridge CFDictionaryRef)proxySettings);
    
    if(proxies.count > 0) {
        settings = proxies.firstObject;
        
        NSURL *pacURL;
        if((pacURL = [settings objectForKey:(__bridge id)kCFProxyAutoConfigurationURLKey])) {
            NSError *error = nil;
            NSString *script = [NSString stringWithContentsOfURL:pacURL usedEncoding:nil error:&error];
            
            if(!error) {
                CFErrorRef eref = nil;
                proxies = (__bridge id)CFNetworkCopyProxiesForAutoConfigurationScript((__bridge CFStringRef)script, (__bridge CFURLRef)URL, &eref);
                
                if(!eref && proxies.count > 0) {
                    settings = proxies.firstObject;
                }
            }
        }
    }
    
    NSURLComponents *components = [NSURLComponents new];
    components.host = [settings objectForKey:(__bridge id)kCFProxyHostNameKey];
    components.port = [settings objectForKey:(__bridge id)kCFProxyPortNumberKey];
    self.proxy = components.URL;
    
    if(!self.proxy.host.length || !self.proxy.port)
        self.proxy = nil;
    
    if (!self.proxyUsername) {
        self.proxyUsername = [settings objectForKey:(__bridge id)kCFProxyUsernameKey];
        
        if(!self.proxyUsername)
            self.proxyUsername = [proxySettings objectForKey:@"HTTPProxyUsername"];
        
    }

    if (!self.proxyPassword) {
        self.proxyPassword = [settings objectForKey:(__bridge id)kCFProxyPasswordKey];
        
        
        if(!self.proxyPassword)
            self.proxyPassword = [proxySettings objectForKey:@"HTTPProxyPassword"];
    }
    
    CFReadStreamRef readStream = NULL;
    CFWriteStreamRef writeStream = NULL;
    
    if(self.proxy) {
        CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)self.proxy.host, [self.proxy.port intValue], &readStream, &writeStream);
    } else {
        CFStreamCreatePairWithSocketToHost(NULL, (__bridge CFStringRef)url.host, [url.port intValue], &readStream, &writeStream);
    }
    
    self.response = nil;
    self.connecting = false;
    self.authTries = 0;
    [self resetTimeout];
    self.inputStream = (__bridge_transfer NSInputStream *)readStream;
    self.outputStream = (__bridge_transfer NSOutputStream *)writeStream;
    self.inputStream.delegate = self;
    self.outputStream.delegate = self;
    [self.inputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.outputStream scheduleInRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.inputStream open];
    [self.outputStream open];
}

@end

@implementation JFRWebSucket

/////////////////////////////////////////////////////////////////////////////
//Default initializer
- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray*)protocols
{
    if(self = [super init]) {
        self.certValidated = NO;
        self.voipEnabled = NO;
        self.selfSignedSSL = NO;
        self.queue = dispatch_get_main_queue();
        self.url = url;
        self.readStack = [NSMutableArray new];
        self.inputQueue = [NSMutableArray new];
        self.optProtocols = protocols;
    }
    
    return self;
}
/////////////////////////////////////////////////////////////////////////////
//Exposed method for connecting to URL provided in init method.
- (void)connect {
    if(self.isCreated) {
        return;
    }
    
    self.didDisconnect = NO;
    self.isCreated = YES;
    [self createHTTPRequest];
}
- (void)dealloc {
    [self disconnect];
}
/////////////////////////////////////////////////////////////////////////////
- (void)disconnect {
    if (self.didDisconnect)
        return;
    
    self.didDisconnect = YES;
    [self writeError:JFRCloseCodeNormal];
}
/////////////////////////////////////////////////////////////////////////////
- (void)writeString:(NSString*)string {
    if(string) {
        [self dequeueWrite:[string dataUsingEncoding:NSUTF8StringEncoding]
                  withCode:JFROpCodeTextFrame];
    }
}
/////////////////////////////////////////////////////////////////////////////
- (void)writePing:(NSData*)data {
    [self dequeueWrite:data withCode:JFROpCodePing];
}
/////////////////////////////////////////////////////////////////////////////
- (void)writeData:(NSData*)data {
    [self dequeueWrite:data withCode:JFROpCodeBinaryFrame];
}
/////////////////////////////////////////////////////////////////////////////
- (void)addHeader:(NSString*)value forKey:(NSString*)key {
    if(!self.headers) {
        self.headers = [[NSMutableDictionary alloc] init];
    }
    [self.headers setObject:value forKey:key];
}
/////////////////////////////////////////////////////////////////////////////

#pragma mark - connect's internal supporting methods

/////////////////////////////////////////////////////////////////////////////

- (NSString *)origin;
{
    NSString *scheme = [_url.scheme lowercaseString];
    
    if ([scheme isEqualToString:@"wss"]) {
        scheme = @"https";
    } else if ([scheme isEqualToString:@"ws"]) {
        scheme = @"http";
    }
    
    if (_url.port) {
        return [NSString stringWithFormat:@"%@://%@:%@/", scheme, _url.host, _url.port];
    } else {
        return [NSString stringWithFormat:@"%@://%@/", scheme, _url.host];
    }
}


//Uses CoreFoundation to build a HTTP request to send over TCP stream.
- (void)createHTTPRequest {
    CFURLRef url = CFURLCreateWithString(kCFAllocatorDefault, (CFStringRef)self.url.absoluteString, NULL);
    CFStringRef requestMethod = CFSTR("GET");
    CFHTTPMessageRef urlRequest = CFHTTPMessageCreateRequest(kCFAllocatorDefault,
                                                             requestMethod,
                                                             url,
                                                             kCFHTTPVersion1_1);
    CFRelease(url);
    
    if (!self.url.port) {
        NSURLComponents *components = [NSURLComponents componentsWithURL:self.url resolvingAgainstBaseURL:YES];
        if([components.scheme isEqualToString:@"wss"] || [components.scheme isEqualToString:@"https"]){
            components.port = @(443);
        } else {
            components.port = @(80);
        }
        self.url = components.URL;
    }
    
    NSString *protocols = nil;
    if([self.optProtocols count] > 0) {
        protocols = [self.optProtocols componentsJoinedByString:@","];
    }
    CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                     (__bridge CFStringRef)headerWSHostName,
                                     (__bridge CFStringRef)[NSString stringWithFormat:@"%@:%@",self.url.host,self.url.port]);
    CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                     (__bridge CFStringRef)headerWSVersionName,
                                     (__bridge CFStringRef)headerWSVersionValue);
    CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                     (__bridge CFStringRef)headerWSKeyName,
                                     (__bridge CFStringRef)[self generateWebSocketKey]);
    CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                     (__bridge CFStringRef)headerWSUpgradeName,
                                     (__bridge CFStringRef)headerWSUpgradeValue);
    CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                     (__bridge CFStringRef)headerWSConnectionName,
                                     (__bridge CFStringRef)headerWSConnectionValue);
    if (protocols.length > 0) {
        CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                         (__bridge CFStringRef)headerWSProtocolName,
                                         (__bridge CFStringRef)protocols);
    }
   
    CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                     (__bridge CFStringRef)headerOriginName,
                                     (__bridge CFStringRef)[self origin]);
    
    for(NSString *key in self.headers) {
        CFHTTPMessageSetHeaderFieldValue(urlRequest,
                                         (__bridge CFStringRef)key,
                                         (__bridge CFStringRef)self.headers[key]);
    }
    
#if defined(DEBUG)
    NSLog(@"urlRequest = \"%@\"", urlRequest);
#endif
    NSData *serializedRequest = (__bridge_transfer NSData *)(CFHTTPMessageCopySerializedMessage(urlRequest));
    CFRelease(urlRequest);
    
    self.proxyHandler = [JFRWebSocketProxyHandler new];
    self.proxyHandler.proxyUsername = self.proxyUsername;
    self.proxyHandler.proxyPassword = self.proxyPassword;
    
    __weak typeof(self) weakSelf = self;
    [self.proxyHandler connect:self.url completion:^(bool success, NSInputStream *inputStream, NSOutputStream *outputStream, NSString *sni){
        weakSelf.inputStream = inputStream;
        weakSelf.outputStream = outputStream;
        
        if(success) {
            [weakSelf initStreamsWithData:serializedRequest withSNI:sni];
        } else {
            [weakSelf doDisconnect:[weakSelf errorWithDetail:@"proxy authentication failed" code:JFRProxyError]];
        }
    }];
}
/////////////////////////////////////////////////////////////////////////////
//Random String of 16 lowercase chars, SHA1 and base64 encoded.
- (NSString*)generateWebSocketKey {
    NSInteger seed = 16;
    NSMutableString *string = [NSMutableString stringWithCapacity:seed];
    for (int i = 0; i < seed; i++) {
        [string appendFormat:@"%C", (unichar)('a' + arc4random_uniform(25))];
    }
    return [[string dataUsingEncoding:NSUTF8StringEncoding] base64EncodedStringWithOptions:0];
}
/////////////////////////////////////////////////////////////////////////////
//Setups SSL connection for the sockets
- (void)setupSecureConnection:(BOOL)selfSigned peerName:(NSString*)peerName {
    NSMutableDictionary *sslSettings = [NSMutableDictionary dictionary];
    NSString *chainKey = (__bridge_transfer NSString *)kCFStreamSSLValidatesCertificateChain;
    NSString *peerNameKey = (__bridge_transfer NSString *)kCFStreamSSLPeerName;
    
    if(peerName) {
        [sslSettings setObject:peerName forKey:peerNameKey];
    }
    
    if(selfSigned) {
        [sslSettings setObject:@(NO) forKey:chainKey];
        [sslSettings setObject:[NSNull null] forKey:peerNameKey];
    } else {
        [sslSettings setObject:@(YES) forKey:chainKey];
    }
    
    NSString *levelKey = (__bridge_transfer NSString *)kCFStreamPropertySocketSecurityLevel;
    NSString *level = (__bridge_transfer NSString *)kCFStreamSocketSecurityLevelNegotiatedSSL;
    
    if(self.securityLevel) {
        level = self.securityLevel;
    }
    
    [sslSettings setObject:level forKey:levelKey];
    
    NSString *settingsKey = (__bridge_transfer NSString *)kCFStreamPropertySSLSettings;
    [self.inputStream setProperty:sslSettings forKey:settingsKey];
    [self.outputStream setProperty:sslSettings forKey:settingsKey];
}
/////////////////////////////////////////////////////////////////////////////
//Sets up our reader/writer for the TCP stream.
- (void)initStreamsWithData:(NSData*)data withSNI:(NSString*)sni {
    self.inputStream.delegate = self;
    self.outputStream.delegate = self;
    
    if(self.voipEnabled) {
        [self.inputStream setProperty:NSStreamNetworkServiceTypeVoIP forKey:NSStreamNetworkServiceType];
        [self.outputStream setProperty:NSStreamNetworkServiceTypeVoIP forKey:NSStreamNetworkServiceType];
    }
    
    if([self.url.scheme isEqualToString:@"wss"] || [self.url.scheme isEqualToString:@"https"]) {
        [self setupSecureConnection:self.selfSignedSSL peerName:sni];
    } else {
        self.certValidated = YES; // not a https session, so no need to check SSL pinning
    }
    
    [self.outputStream write:[data bytes] maxLength:[data length]];
}
/////////////////////////////////////////////////////////////////////////////

#pragma mark - NSStreamDelegate

/////////////////////////////////////////////////////////////////////////////
- (void)stream:(NSStream *)aStream handleEvent:(NSStreamEvent)eventCode {
    if(self.security && !self.certValidated && (eventCode == NSStreamEventHasBytesAvailable || eventCode == NSStreamEventHasSpaceAvailable)) {
        SecTrustRef trust = (__bridge SecTrustRef)([aStream propertyForKey:(__bridge_transfer NSString *)kCFStreamPropertySSLPeerTrust]);
        NSString *domain = [aStream propertyForKey:(__bridge_transfer NSString *)kCFStreamSSLPeerName];
        if([self.security isValid:trust domain:domain]) {
            self.certValidated = YES;
        } else {
            [self disconnectStream:[self errorWithDetail:@"Invalid SSL certificate" code:1]];
            return;
        }
    }
    switch (eventCode) {
        case NSStreamEventNone:
            break;
            
        case NSStreamEventOpenCompleted:
            break;
            
        case NSStreamEventHasBytesAvailable:
            if(aStream == self.inputStream) {
                [self processInputStream];
            }
            break;
            
        case NSStreamEventHasSpaceAvailable:
            break;
            
        case NSStreamEventErrorOccurred:
            [self disconnectStream:[aStream streamError]];
            break;
            
        case NSStreamEventEndEncountered:
            [self disconnectStream:nil];
            break;
            
        default:
            break;
    }
}
/////////////////////////////////////////////////////////////////////////////
- (void)disconnectStream:(NSError*)error {
    [self.inputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.outputStream removeFromRunLoop:[NSRunLoop currentRunLoop] forMode:NSDefaultRunLoopMode];
    [self.outputStream close];
    [self.inputStream close];
    self.outputStream = nil;
    self.inputStream = nil;
    _isConnected = NO;
    self.certValidated = NO;
    [self doDisconnect:error];
}
/////////////////////////////////////////////////////////////////////////////

#pragma mark - Stream Processing Methods

/////////////////////////////////////////////////////////////////////////////
- (void)processInputStream {
    @autoreleasepool {
        uint8_t buffer[BUFFER_MAX];
        NSInteger length = [self.inputStream read:buffer maxLength:BUFFER_MAX];
        if(length > 0) {
            if(!self.isConnected) {
                CFIndex responseStatusCode;
                BOOL status = [self processHTTP:buffer length:length responseStatusCode:&responseStatusCode];
#if defined(DEBUG)
                if (length < BUFFER_MAX) {
                    buffer[length] = 0x00;
                } else {
                    buffer[BUFFER_MAX - 1] = 0x00;
                }
                NSLog(@"response (%ld) = \"%s\"", responseStatusCode, buffer);
#endif
                if(status == NO) {
                    [self doDisconnect:[self errorWithDetail:@"Invalid HTTP upgrade" code:1 userInfo:@{@"HTTPResponseStatusCode" : @(responseStatusCode)}]];
                }
            } else {
                BOOL process = NO;
                if(self.inputQueue.count == 0) {
                    process = YES;
                }
                [self.inputQueue addObject:[NSData dataWithBytes:buffer length:length]];
                if(process) {
                    [self dequeueInput];
                }
            }
        }
    }
}
/////////////////////////////////////////////////////////////////////////////
- (void)dequeueInput {
    if(self.inputQueue.count > 0) {
        NSData *data = [self.inputQueue objectAtIndex:0];
        NSData *work = data;
        if(self.fragBuffer) {
            NSMutableData *combine = [NSMutableData dataWithData:self.fragBuffer];
            [combine appendData:data];
            work = combine;
            self.fragBuffer = nil;
        }
        [self processRawMessage:(uint8_t*)work.bytes length:work.length];
        [self.inputQueue removeObject:data];
        [self dequeueInput];
    }
}
/////////////////////////////////////////////////////////////////////////////
//Finds the HTTP Packet in the TCP stream, by looking for the CRLF.
- (BOOL)processHTTP:(uint8_t*)buffer length:(NSInteger)bufferLen responseStatusCode:(CFIndex*)responseStatusCode {
    int k = 0;
    NSInteger totalSize = 0;
    for(int i = 0; i < bufferLen; i++) {
        if(buffer[i] == CRLFBytes[k]) {
            k++;
            if(k == 3) {
                totalSize = i + 1;
                break;
            }
        } else {
            k = 0;
        }
    }
    if(totalSize > 0) {
        BOOL status = [self validateResponse:buffer length:totalSize responseStatusCode:responseStatusCode];
        if (status == YES) {
            _isConnected = YES;
            __weak typeof(self) weakSelf = self;
            dispatch_async(self.queue,^{
                if([weakSelf.delegate respondsToSelector:@selector(websocketDidConnect:)]) {
                    [weakSelf.delegate websocketDidConnect:weakSelf.master];
                }
                if(weakSelf.onConnect) {
                    weakSelf.onConnect();
                }
            });
            totalSize += 1; //skip the last \n
            NSInteger  restSize = bufferLen-totalSize;
            if(restSize > 0) {
                [self processRawMessage:(buffer+totalSize) length:restSize];
            }
        }
        return status;
    }
    return NO;
}
/////////////////////////////////////////////////////////////////////////////
//Validate the HTTP is a 101, as per the RFC spec.
- (BOOL)validateResponse:(uint8_t *)buffer length:(NSInteger)bufferLen responseStatusCode:(CFIndex*)responseStatusCode {
    CFHTTPMessageRef response = CFHTTPMessageCreateEmpty(kCFAllocatorDefault, NO);
    CFHTTPMessageAppendBytes(response, buffer, bufferLen);
    *responseStatusCode = CFHTTPMessageGetResponseStatusCode(response);
    BOOL status = ((*responseStatusCode) == kJFRInternalHTTPStatusWebSocket)?(YES):(NO);
    if(status == NO) {
        CFRelease(response);
        return NO;
    }
    NSDictionary *headers = (__bridge_transfer NSDictionary *)(CFHTTPMessageCopyAllHeaderFields(response));
    NSString *acceptKey = headers[headerWSAcceptName];
    CFRelease(response);
    if(acceptKey.length > 0) {
        return YES;
    }
    return NO;
}
/////////////////////////////////////////////////////////////////////////////
-(void)processRawMessage:(uint8_t*)buffer length:(NSInteger)bufferLen {
    JFRResponse *response = [self.readStack lastObject];
    if(response && bufferLen < 2) {
        self.fragBuffer = [NSData dataWithBytes:buffer length:bufferLen];
        return;
    }
    if(response.bytesLeft > 0) {
        NSInteger len = response.bytesLeft;
        NSInteger extra =  bufferLen - response.bytesLeft;
        if(response.bytesLeft > bufferLen) {
            len = bufferLen;
            extra = 0;
        }
        response.bytesLeft -= len;
        [response.buffer appendData:[NSData dataWithBytes:buffer length:len]];
        [self processResponse:response];
        NSInteger offset = bufferLen - extra;
        if(extra > 0) {
            [self processExtra:(buffer+offset) length:extra];
        }
        return;
    } else {
        if(bufferLen < 2) { // we need at least 2 bytes for the header
            self.fragBuffer = [NSData dataWithBytes:buffer length:bufferLen];
            return;
        }
        BOOL isFin = (JFRFinMask & buffer[0]);
        uint8_t receivedOpcode = (JFROpCodeMask & buffer[0]);
        BOOL isMasked = (JFRMaskMask & buffer[1]);
        uint8_t payloadLen = (JFRPayloadLenMask & buffer[1]);
        NSInteger offset = 2; //how many bytes do we need to skip for the header
        if((isMasked  || (JFRRSVMask & buffer[0])) && receivedOpcode != JFROpCodePong) {
            [self doDisconnect:[self errorWithDetail:@"masked and rsv data is not currently supported" code:JFRCloseCodeProtocolError]];
            [self writeError:JFRCloseCodeProtocolError];
            return;
        }
        BOOL isControlFrame = (receivedOpcode == JFROpCodeConnectionClose || receivedOpcode == JFROpCodePing);
        if(!isControlFrame && (receivedOpcode != JFROpCodeBinaryFrame && receivedOpcode != JFROpCodeContinueFrame && receivedOpcode != JFROpCodeTextFrame && receivedOpcode != JFROpCodePong)) {
            [self doDisconnect:[self errorWithDetail:[NSString stringWithFormat:@"unknown opcode: 0x%x",receivedOpcode] code:JFRCloseCodeProtocolError]];
            [self writeError:JFRCloseCodeProtocolError];
            return;
        }
        if(isControlFrame && !isFin) {
            [self doDisconnect:[self errorWithDetail:@"control frames can't be fragmented" code:JFRCloseCodeProtocolError]];
            [self writeError:JFRCloseCodeProtocolError];
            return;
        }
        if(receivedOpcode == JFROpCodeConnectionClose) {
            //the server disconnected us
            uint16_t code = JFRCloseCodeNormal;
            if(payloadLen == 1) {
                code = JFRCloseCodeProtocolError;
            }
            else if(payloadLen > 1) {
                code = CFSwapInt16BigToHost(*(uint16_t *)(buffer+offset) );
                if(code < 1000 || (code > 1003 && code < 1007) || (code > 1011 && code < 3000)) {
                    code = JFRCloseCodeProtocolError;
                }
                offset += 2;
            }
            
            if(payloadLen > 2) {
                NSInteger len = payloadLen-2;
                if(len > 0) {
                    NSData *data = [NSData dataWithBytes:(buffer+offset) length:len];
                    NSString *str = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
                    if(!str) {
                        code = JFRCloseCodeProtocolError;
                    }
                }
            }
            [self writeError:code];
            [self doDisconnect:[self errorWithDetail:@"continue frame before a binary or text frame" code:code]];
            return;
        }
        if(isControlFrame && payloadLen > 125) {
            [self writeError:JFRCloseCodeProtocolError];
            return;
        }
        NSInteger dataLength = payloadLen;
        if(payloadLen == 127) {
            dataLength = (NSInteger)CFSwapInt64BigToHost(*(uint64_t *)(buffer+offset));
            offset += sizeof(uint64_t);
        } else if(payloadLen == 126) {
            dataLength = CFSwapInt16BigToHost(*(uint16_t *)(buffer+offset) );
            offset += sizeof(uint16_t);
        }
        if(bufferLen < offset) { // we cannot process this yet, nead more header data
            self.fragBuffer = [NSData dataWithBytes:buffer length:bufferLen];
            return;
        }
        NSInteger len = dataLength;
        if(dataLength > (bufferLen-offset) || (bufferLen - offset) < dataLength) {
            len = bufferLen-offset;
        }
        NSData *data = nil;
        if(len < 0) {
            len = 0;
            data = [NSData data];
        } else {
            data = [NSData dataWithBytes:(buffer+offset) length:len];
        }
        if(receivedOpcode == JFROpCodePong) {
            NSInteger step = (offset+len);
            NSInteger extra = bufferLen-step;
            if(extra > 0) {
                [self processRawMessage:(buffer+step) length:extra];
            }
            __weak typeof(self) weakSelf = self;
            dispatch_async(self.queue,^{
                if([weakSelf.delegate respondsToSelector:@selector(websocket:didReceivePong:)]) {
                    [weakSelf.delegate websocket:weakSelf.master didReceivePong:data];
                }
            });
            return;
        }
        JFRResponse *response = [self.readStack lastObject];
        if(isControlFrame) {
            response = nil; //don't append pings
        }
        if(!isFin && receivedOpcode == JFROpCodeContinueFrame && !response) {
            [self doDisconnect:[self errorWithDetail:@"continue frame before a binary or text frame" code:JFRCloseCodeProtocolError]];
            [self writeError:JFRCloseCodeProtocolError];
            return;
        }
        BOOL isNew = NO;
        if(!response) {
            if(receivedOpcode == JFROpCodeContinueFrame) {
                [self doDisconnect:[self errorWithDetail:@"first frame can't be a continue frame" code:JFRCloseCodeProtocolError]];
                [self writeError:JFRCloseCodeProtocolError];
                return;
            }
            isNew = YES;
            response = [JFRResponse new];
            response.code = receivedOpcode;
            response.bytesLeft = dataLength;
            response.buffer = [NSMutableData dataWithData:data];
        } else {
            if(receivedOpcode == JFROpCodeContinueFrame) {
                response.bytesLeft = dataLength;
            } else {
                [self doDisconnect:[self errorWithDetail:@"second and beyond of fragment message must be a continue frame" code:JFRCloseCodeProtocolError]];
                [self writeError:JFRCloseCodeProtocolError];
                return;
            }
            [response.buffer appendData:data];
        }
        response.bytesLeft -= len;
        response.frameCount++;
        response.isFin = isFin;
        if(isNew) {
            [self.readStack addObject:response];
        }
        [self processResponse:response];
        
        NSInteger step = (offset+len);
        NSInteger extra = bufferLen-step;
        if(extra > 0) {
            [self processExtra:(buffer+step) length:extra];
        }
    }
    
}
/////////////////////////////////////////////////////////////////////////////
- (void)processExtra:(uint8_t*)buffer length:(NSInteger)bufferLen {
    if(bufferLen < 2) {
        self.fragBuffer = [NSData dataWithBytes:buffer length:bufferLen];
    } else {
        [self processRawMessage:buffer length:bufferLen];
    }
}
/////////////////////////////////////////////////////////////////////////////
- (BOOL)processResponse:(JFRResponse*)response {
    if(response.isFin && response.bytesLeft <= 0) {
        NSData *data = response.buffer;
        if(response.code == JFROpCodePing) {
            [self dequeueWrite:response.buffer withCode:JFROpCodePong];
        } else if(response.code == JFROpCodeTextFrame) {
            NSString *str = [[NSString alloc] initWithData:response.buffer encoding:NSUTF8StringEncoding];
            if(!str) {
                [self writeError:JFRCloseCodeEncoding];
                return NO;
            }
            __weak typeof(self) weakSelf = self;
            dispatch_async(self.queue,^{
                if([weakSelf.delegate respondsToSelector:@selector(websocket:didReceiveMessage:)]) {
                    [weakSelf.delegate websocket:weakSelf.master didReceiveMessage:str];
                }
                if(weakSelf.onText) {
                    weakSelf.onText(str);
                }
            });
        } else if(response.code == JFROpCodeBinaryFrame) {
            __weak typeof(self) weakSelf = self;
            dispatch_async(self.queue,^{
                if([weakSelf.delegate respondsToSelector:@selector(websocket:didReceiveData:)]) {
                    [weakSelf.delegate websocket:weakSelf.master didReceiveData:data];
                }
                if(weakSelf.onData) {
                    weakSelf.onData(data);
                }
            });
        }
        [self.readStack removeLastObject];
        return YES;
    }
    return NO;
}
/////////////////////////////////////////////////////////////////////////////
-(void)dequeueWrite:(NSData*)data withCode:(JFROpCode)code {
    if(!self.isConnected) {
        return;
    }

    uint64_t offset = 2; //how many bytes do we need to skip for the header
    uint8_t *bytes = (uint8_t*)[data bytes];
    uint64_t dataLength = data.length;
    NSMutableData *frame = [[NSMutableData alloc] initWithLength:(NSInteger)(dataLength + JFRMaxFrameSize)];
    uint8_t *buffer = (uint8_t*)[frame mutableBytes];
    buffer[0] = JFRFinMask | code;
    if(dataLength < 126) {
        buffer[1] |= dataLength;
    } else if(dataLength <= UINT16_MAX) {
        buffer[1] |= 126;
        *((uint16_t *)(buffer + offset)) = CFSwapInt16BigToHost((uint16_t)dataLength);
        offset += sizeof(uint16_t);
    } else {
        buffer[1] |= 127;
        *((uint64_t *)(buffer + offset)) = CFSwapInt64BigToHost((uint64_t)dataLength);
        offset += sizeof(uint64_t);
    }
    BOOL isMask = YES;
    if(isMask) {
        buffer[1] |= JFRMaskMask;
        uint8_t *mask_key = (buffer + offset);
        if (SecRandomCopyBytes(kSecRandomDefault, sizeof(uint32_t), (uint8_t *)mask_key) != errSecSuccess) {
            NSError *error = [self errorWithDetail:@"SecRandomCopyBytes failed" code:JFROutputStreamWriteError];
            [self doDisconnect:error];
            return;
        }
        
        offset += sizeof(uint32_t);
        
        for (size_t i = 0; i < dataLength; i++) {
            buffer[offset] = bytes[i] ^ mask_key[i % sizeof(uint32_t)];
            offset += 1;
        }
    } else {
        for(size_t i = 0; i < dataLength; i++) {
            buffer[offset] = bytes[i];
            offset += 1;
        }
    }
    uint64_t total = 0;
    while (true) {
        if(!self.isConnected || !self.outputStream) {
            break;
        }
        NSInteger len = [self.outputStream write:([frame bytes]+total) maxLength:(NSInteger)(offset-total)];
        if(len < 0 || len == NSNotFound) {
            NSError *error = self.outputStream.streamError;
            if(!error) {
                error = [self errorWithDetail:@"output stream error during write" code:JFROutputStreamWriteError];
            }
            [self doDisconnect:error];
            break;
        } else {
            total += len;
        }
        if(total >= offset) {
            break;
        }
    }
}
/////////////////////////////////////////////////////////////////////////////
- (void)doDisconnect:(NSError*)error {
    if(!self.didDisconnect) {
        [self disconnect];
        __weak typeof(self) weakSelf = self;
        dispatch_async(self.queue, ^{   
            if([weakSelf.delegate respondsToSelector:@selector(websocketDidDisconnect:error:)]) {
                [weakSelf.delegate websocketDidDisconnect:weakSelf.master error:error];
            }
            if(weakSelf.onDisconnect) {
                weakSelf.onDisconnect(error);
            }
        });
    }
}
/////////////////////////////////////////////////////////////////////////////
- (NSError*)errorWithDetail:(NSString*)detail code:(NSInteger)code
{
    return [self errorWithDetail:detail code:code userInfo:nil];
}
- (NSError*)errorWithDetail:(NSString*)detail code:(NSInteger)code userInfo:(NSDictionary *)userInfo
{
    NSMutableDictionary* details = [NSMutableDictionary dictionary];
    details[detail] = NSLocalizedDescriptionKey;
    if (userInfo) {
        [details addEntriesFromDictionary:userInfo];
    }
    return [[NSError alloc] initWithDomain:@"JFRWebSocket" code:code userInfo:details];
}
/////////////////////////////////////////////////////////////////////////////
- (void)writeError:(uint16_t)code {
    uint16_t buffer[1];
    buffer[0] = CFSwapInt16BigToHost(code);
    [self dequeueWrite:[NSData dataWithBytes:buffer length:sizeof(uint16_t)] withCode:JFROpCodeConnectionClose];
}
@end

/////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////////////////////////////////////////
@implementation JFRResponse

@end
/////////////////////////////////////////////////////////////////////////////

@interface JFRThread : NSObject
@property (nonatomic, strong) NSThread *thread;
@property (nonatomic, strong) NSCondition *startCondition;
@property (nonatomic, strong) NSCondition *exitCondition;
@end

@implementation JFRThread
- (id)init
{
    if (!(self = [super init]))
        return nil;
    
    self.startCondition = [NSCondition new];
    self.exitCondition = [NSCondition new];
    self.thread = [[NSThread alloc] initWithTarget:self selector:@selector(mainOnThread) object:nil];
    return self;
}

- (void)startWithName:(NSString*)name
{
    self.thread.name = name;
    [self.startCondition lock];
    [self.thread start];
    [self.startCondition wait];
    [self.startCondition unlock];
}

- (void)stop
{
    [self.exitCondition lock];
    [self performSelector:@selector(stopOnThread) onThread:self.thread withObject:nil waitUntilDone:NO];
    [self.exitCondition wait];
    [self.exitCondition unlock];
}

- (void)stopOnThread
{
    CFRunLoopStop(CFRunLoopGetCurrent());
}

static void noop(void *info) {}

- (void)mainOnThread
{
    @autoreleasepool {
        pthread_setname_np([[[NSThread currentThread] name] UTF8String]);
        CFRunLoopSourceContext context = {0};
        context.perform = noop;
        CFRunLoopSourceRef source = CFRunLoopSourceCreate(NULL, 0, &context);
        CFRunLoopAddSource(CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes);
        [self.startCondition lock];
        [self.startCondition signal];
        [self.startCondition unlock];
        CFRunLoopRun();
        CFRunLoopRemoveSource(CFRunLoopGetCurrent(), source, kCFRunLoopCommonModes);
        CFRelease(source);
        [self.exitCondition lock];
        [self.exitCondition signal];
        [self.exitCondition unlock];
    }
}
@end

@interface JFRWebSocket () <NSStreamDelegate>
{
    objc_property_t *properties;
    u_int property_count;
}
@property (nonatomic, strong) JFRWebSucket *sucket;
@property (nonatomic, strong) JFRThread *thread;
@end

@implementation JFRWebSocket
- (instancetype)initWithURL:(NSURL *)url protocols:(NSArray*)protocols
{
    if (!(self = [super init]))
        return nil;
    
    self.sucket = [[JFRWebSucket alloc] initWithURL:url protocols:protocols];
    self.sucket.master = self;
    properties = class_copyPropertyList([self.sucket class], &property_count);
    self.thread = [JFRThread new];
    [self.thread startWithName:@"JFRWebSucket"];
    return self;
}

- (void)dealloc
{
    [self.thread stop];
    free(properties);
}

- (BOOL)respondsToSelector:(SEL)selector
{
    return [super respondsToSelector:selector] || [self.sucket respondsToSelector:selector];
}

- (NSMethodSignature *)methodSignatureForSelector:(SEL)selector
{
    NSMethodSignature *sig;
    if ((sig = [super methodSignatureForSelector:selector]))
        return sig;
    return [self.sucket methodSignatureForSelector:selector];
}

- (bool)isProperty:(SEL)selector
{
    for (int i = 0; i < property_count; ++i) {
        char setter[255] = {0};
        const char *propertyName = property_getName(properties[i]);
        snprintf(setter, sizeof(setter), "set%s:", propertyName);
        setter[3] = toupper(setter[3]);
        if (!strcmp(sel_getName(selector), propertyName) || !strcmp(sel_getName(selector), setter))
            return true;
    }
    return false;
}

- (void)forwardInvocation:(NSInvocation *)invocation
{
    if ([self.sucket respondsToSelector:invocation.selector]) {
        if ([self isProperty:invocation.selector]) {
            [invocation invokeWithTarget:self.sucket];
        } else {
            [invocation retainArguments];
            [invocation performSelector:@selector(invokeWithTarget:) onThread:self.thread.thread withObject:self.sucket waitUntilDone:NO];
        }
    } else {
        [self doesNotRecognizeSelector:invocation.selector];
    }
}

@end
