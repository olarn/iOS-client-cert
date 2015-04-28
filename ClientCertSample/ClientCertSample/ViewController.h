#import <UIKit/UIKit.h>
#import <Security/Security.h>

@interface ViewController : UIViewController<NSURLConnectionDelegate>

@property (strong, nonatomic) NSURLConnection *connection;
@property (strong, atomic)  NSMutableData *returnedData;

@property (weak, nonatomic) IBOutlet UITextField *txtUrl;
@property (weak, nonatomic) IBOutlet UITextView *txtResult;

- (IBAction)btnGoTapped:(id)sender;
OSStatus extractIdentityAndTrust(CFDataRef inP12data, SecIdentityRef *identity, SecTrustRef *trust);

@end
