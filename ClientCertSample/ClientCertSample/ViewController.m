#import "ViewController.h"

@interface ViewController (Private)

@end

@implementation ViewController

@synthesize connection;
@synthesize returnedData;

@synthesize txtUrl;
@synthesize txtResult;

- (void)viewDidLoad
{
    [super viewDidLoad];
	// Do any additional setup after loading the view, typically from a nib.
}

- (void)viewDidUnload
{
    [self setTxtUrl:nil];
    [self setTxtResult:nil];
    [super viewDidUnload];
    // Release any retained subviews of the main view.
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation
{
    return (interfaceOrientation != UIInterfaceOrientationPortraitUpsideDown);
}

- (IBAction)btnGoTapped:(id)sender 
{
    NSURL *url = [[NSURL alloc] initWithString:txtUrl.text];
    NSURLRequest *request = [NSURLRequest requestWithURL:url];
    
    returnedData = [[NSMutableData alloc] init];    
    self.connection = [[NSURLConnection alloc] initWithRequest:request 
                                                      delegate:self startImmediately:NO];
    [self.connection start];
}

#pragma mark - NSURLConnectionDelegate Handler -> Authentication

- (void)connection:(NSURLConnection *)connection willSendRequestForAuthenticationChallenge:(NSURLAuthenticationChallenge *)challenge
{
    // load certificate when server require
    
    NSString *path = [[NSBundle mainBundle] pathForResource:@"Certificates" ofType:@"p12"];
    NSData *p12data = [NSData dataWithContentsOfFile:path];
    CFDataRef inP12data = (__bridge CFDataRef)p12data;
    
    SecIdentityRef myIdentity;
    SecTrustRef myTrust;
    
    extractIdentityAndTrust(inP12data, &myIdentity, &myTrust);
    
    SecCertificateRef myCertificate;
    SecIdentityCopyCertificate(myIdentity, &myCertificate);
    const void *certs[] = { myCertificate };
    CFArrayRef certsArray = CFArrayCreate(NULL, certs, 1, NULL);
    
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:myIdentity 
                                                             certificates:(__bridge NSArray*)certsArray 
                                                              persistence:NSURLCredentialPersistencePermanent];
    
    [[challenge sender] useCredential:credential forAuthenticationChallenge:challenge];
}

OSStatus extractIdentityAndTrust(CFDataRef inP12data, SecIdentityRef *identity, SecTrustRef *trust)
{
    OSStatus securityError = errSecSuccess;
    
    CFStringRef password = CFSTR("pass@word1");
    const void *keys[] = { kSecImportExportPassphrase };
    const void *values[] = { password };
    
    CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
    
    CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
    securityError = SecPKCS12Import(inP12data, options, &items);
    
    if (securityError == 0) {
        CFDictionaryRef myIdentityAndTrust = CFArrayGetValueAtIndex(items, 0);
        const void *tempIdentity = NULL;
        tempIdentity = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemIdentity);
        *identity = (SecIdentityRef)tempIdentity;
        const void *tempTrust = NULL;
        tempTrust = CFDictionaryGetValue(myIdentityAndTrust, kSecImportItemTrust);
        *trust = (SecTrustRef)tempTrust;
    }
    
    if (options) {
        CFRelease(options);
    }
    
    return securityError;
}

#pragma mark - NSURLConnectionDelegate Handler -> Server Response

- (void)connection:(NSURLConnection *)connection didReceiveData:(NSData *)data
{
    // append returned data from server
    [returnedData appendData:data];
    
}

- (void)connectionDidFinishLoading:(NSURLConnection *)connection
{
    if (returnedData) {
        txtResult.text = [NSString stringWithUTF8String:[returnedData bytes]];
    }
}

- (void)connection:(NSURLConnection *)connection didFailWithError:(NSError *)error
{
    txtResult.text = [error localizedDescription];
}

@end
